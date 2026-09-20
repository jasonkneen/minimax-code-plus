import { execFile as execFileCallback, spawn, type ExecFileException } from 'node:child_process';
import { resolve } from 'node:path';
import { promisify } from 'node:util';

import { sanitizeBashSubprocessEnv } from '@mavis/agent-core/bash-subprocess-env';

import { WorkspaceGitCommandError } from '../contracts.js';

const execFile = promisify(execFileCallback);
const GIT_MAX_BUFFER = 16 * 1024 * 1024;

export interface GitRunResult {
  code: number;
  stdout: string;
  stderr: string;
}

export interface GitRunOptions {
  signal?: AbortSignal;
}

export interface GitStreamOptions {
  signal?: AbortSignal;
  onStdout: (chunk: string) => void;
  maxStderrBytes?: number;
}

export async function git(
  args: string[],
  workspace: string,
  options: GitRunOptions = {},
): Promise<GitRunResult> {
  if (options.signal?.aborted) throw abortError();
  try {
    const result = await execFile(
      'git',
      ['-c', 'core.quotePath=false', '--no-optional-locks', ...args],
      {
        cwd: resolve(workspace),
        encoding: 'utf-8',
        env: gitEnv(),
        maxBuffer: GIT_MAX_BUFFER,
        ...(options.signal ? { signal: options.signal } : {}),
      },
    );
    return { code: 0, stdout: String(result.stdout ?? ''), stderr: String(result.stderr ?? '') };
  } catch (error) {
    if (isAbortFailure(error, options.signal)) {
      throw abortError();
    }
    const err = error as ExecFileException & { stdout?: string | Buffer; stderr?: string | Buffer };
    return {
      code: typeof err.code === 'number' ? err.code : 1,
      stdout: bufferToString(err.stdout),
      stderr: bufferToString(err.stderr) || err.message,
    };
  }
}

/**
 * Runs Git without buffering stdout. Review search and untracked enumeration
 * use this path so repository-sized output never crosses execFile.maxBuffer.
 */
export async function gitStream(
  args: string[],
  workspace: string,
  options: GitStreamOptions,
): Promise<Omit<GitRunResult, 'stdout'>> {
  if (options.signal?.aborted) throw abortError();
  return new Promise((resolvePromise, reject) => {
    const child = spawn('git', ['-c', 'core.quotePath=false', '--no-optional-locks', ...args], {
      cwd: resolve(workspace),
      env: gitEnv(),
      stdio: ['ignore', 'pipe', 'pipe'],
      windowsHide: true,
    });
    const stdoutDecoder = new TextDecoder();
    const stderrDecoder = new TextDecoder();
    const stderrLimit = options.maxStderrBytes ?? 64 * 1024;
    let stderr = '';
    let settled = false;

    const cleanup = () => options.signal?.removeEventListener('abort', onAbort);
    const finishError = (error: unknown) => {
      if (settled) return;
      settled = true;
      cleanup();
      reject(error);
    };
    const onAbort = () => {
      child.kill();
      finishError(abortError());
    };
    options.signal?.addEventListener('abort', onAbort, { once: true });

    child.stdout.on('data', (chunk: Buffer) => {
      if (settled) return;
      const text = stdoutDecoder.decode(chunk, { stream: true });
      if (text) options.onStdout(text);
    });
    child.stderr.on('data', (chunk: Buffer) => {
      if (stderr.length >= stderrLimit) return;
      stderr += stderrDecoder.decode(chunk, { stream: true });
      if (stderr.length > stderrLimit) stderr = stderr.slice(0, stderrLimit);
    });
    child.on('error', finishError);
    child.on('close', (code) => {
      if (settled) return;
      settled = true;
      cleanup();
      const tail = stdoutDecoder.decode();
      if (tail) options.onStdout(tail);
      stderr += stderrDecoder.decode();
      resolvePromise({ code: code ?? 1, stderr });
    });
  });
}

export function requireGitSuccess(
  result: GitRunResult,
  operation: 'diff' | 'ls-files',
): GitRunResult {
  if (result.code !== 0) {
    throw new WorkspaceGitCommandError(
      operation,
      result.code,
      (result.stderr || result.stdout).trim(),
    );
  }
  return result;
}

function gitEnv(): NodeJS.ProcessEnv {
  // Workspace git operations are bash-adjacent subprocesses — passing
  // `process.env` through would leak `MAVIS_ACCESS_TOKEN` / `MATRIX_TOKEN` /
  // `*_API_KEY` into the child git process. Route through the shared
  // sanitizer (scrub mode) and additionally strip the GIT_* namespace so the
  // spawned git does not pick up a parent's repository/worktree context.
  const { env } = sanitizeBashSubprocessEnv(process.env, { mode: 'scrub' });
  for (const key of Object.keys(env)) {
    if (key.startsWith('GIT_')) delete env[key];
  }
  return env;
}

function abortError(): Error {
  const error = new Error('Git operation aborted');
  error.name = 'AbortError';
  return error;
}

function isAbortFailure(error: unknown, signal: AbortSignal | undefined): boolean {
  return signal?.aborted === true || (error instanceof Error && error.name === 'AbortError');
}

function bufferToString(value: string | Buffer | undefined): string {
  return Buffer.isBuffer(value) ? value.toString('utf-8') : String(value ?? '');
}
