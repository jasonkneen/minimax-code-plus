/**
 * Regression test for the workspace git subprocess env scrubbing.
 *
 * `git` (execFile) and `gitStream` (spawn) previously called `gitEnv()` which
 * only stripped `GIT_*` vars from `process.env` — every desktop secret
 * (`MAVIS_ACCESS_TOKEN`, `MATRIX_TOKEN`, `*_API_KEY`) was inherited by the
 * spawned git. The fix routes both helpers through
 * `sanitizeBashSubprocessEnv({mode: 'scrub'})` so the env passed to git never
 * contains those tokens.
 */
import { EventEmitter } from 'node:events';
import { Readable, Writable } from 'node:stream';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const spawnMock = vi.fn();
const execFileMock = vi.fn();

vi.mock('node:child_process', async () => {
  const actual = await vi.importActual<typeof import('node:child_process')>('node:child_process');
  return {
    ...actual,
    spawn: (...args: unknown[]) => spawnMock(...args),
    execFile: (...args: unknown[]) => execFileMock(...args),
  };
});

import { git, gitStream } from './git-process.js';

class FakeChildProcess extends EventEmitter {
  stdin = new Writable({ write(_chunk, _enc, cb) { cb(); } });
  stdout = new Readable({ read() {} });
  stderr = new Readable({ read() {} });
}

function buildChild(): FakeChildProcess {
  const child = new FakeChildProcess();
  queueMicrotask(() => {
    child.stdout.emit('data', Buffer.from(''));
    child.emit('close', 0);
  });
  return child;
}

describe('workspace git subprocess env scrubbing', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    spawnMock.mockReset();
    execFileMock.mockReset();
    process.env = {
      ...originalEnv,
      MAVIS_ACCESS_TOKEN: 'leaked-mavis-token',
      MATRIX_TOKEN: 'leaked-matrix-token',
      ANTHROPIC_API_KEY: 'leaked-anthropic',
      OPENAI_API_KEY: 'leaked-openai',
      GIT_DIR: '/tmp/parent/.git',
      PATH: '/usr/bin',
    };
    execFileMock.mockImplementation((_cmd, _args, _opts, cb) => {
      // execFile has multiple signatures; the most common callback form.
      const callback = typeof _opts === 'function' ? _opts : cb;
      if (typeof callback === 'function') callback(null, '', '');
      return {} as never;
    });
    spawnMock.mockImplementation(() => buildChild());
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  it('strips MAVIS_ACCESS_TOKEN, MATRIX_TOKEN, and *_API_KEY from the execFile env', async () => {
    await git(['status'], '/tmp/workspace');

    expect(execFileMock).toHaveBeenCalledTimes(1);
    const opts = execFileMock.mock.calls[0][2] as { env?: NodeJS.ProcessEnv };
    expect(opts.env).toBeDefined();
    expect(opts.env?.MAVIS_ACCESS_TOKEN).toBeUndefined();
    expect(opts.env?.MATRIX_TOKEN).toBeUndefined();
    expect(opts.env?.ANTHROPIC_API_KEY).toBeUndefined();
    expect(opts.env?.OPENAI_API_KEY).toBeUndefined();
    // GIT_* vars should still be stripped by the post-sanitize cleanup.
    expect(opts.env?.GIT_DIR).toBeUndefined();
    expect(opts.env?.PATH).toBe('/usr/bin');
  });

  it('strips MAVIS_ACCESS_TOKEN, MATRIX_TOKEN, and *_API_KEY from the spawn env (gitStream)', async () => {
    await gitStream(['ls-files'], '/tmp/workspace', {
      onStdout: () => undefined,
    });

    expect(spawnMock).toHaveBeenCalledTimes(1);
    const opts = spawnMock.mock.calls[0][2] as { env?: NodeJS.ProcessEnv };
    expect(opts.env).toBeDefined();
    expect(opts.env?.MAVIS_ACCESS_TOKEN).toBeUndefined();
    expect(opts.env?.MATRIX_TOKEN).toBeUndefined();
    expect(opts.env?.ANTHROPIC_API_KEY).toBeUndefined();
    expect(opts.env?.OPENAI_API_KEY).toBeUndefined();
    expect(opts.env?.GIT_DIR).toBeUndefined();
  });
});