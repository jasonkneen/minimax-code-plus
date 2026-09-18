import { execFile as execFileCallback, spawn } from 'node:child_process';
import { promisify } from 'node:util';

import { sanitizeBashSubprocessEnv } from '@mavis/agent-core/bash-subprocess-env';

import type {
  LocalFileDiff,
  LocalTurnDiffRecord,
  LocalTurnDiffStore,
} from '../persistence/ports.js';
import type { LocalSessionRecord } from '../sessions/controller.js';
import { json } from '../api/host-helpers.js';
import { applyLocalTurnDiffSnapshotMutation } from './file-changes.js';

const execFile = promisify(execFileCallback);

export interface LocalDiffSession {
  readonly sessionId: string;
  readonly workspaceDir: string;
}

export interface LocalSessionDiffView {
  readonly diffs: LocalFileDiff[];
  readonly changeSetId?: string;
}

export interface LocalTurnDiffSelector {
  readonly assistantMessageId?: string;
  readonly turnId?: string;
  readonly changeSetId?: string;
}

export interface LocalTurnDiffView {
  readonly fileChanges: LocalFileDiff[];
  readonly sourceMessageId?: string;
  readonly changeSetId?: string;
  readonly status?: string;
  readonly revertedAt?: number;
  readonly undoable?: boolean;
  readonly canUndo?: boolean;
  readonly canReapply?: boolean;
}

export type LocalTurnDiffMutationBody = {
  readonly success: boolean;
  readonly error?: string;
} & Partial<LocalTurnDiffView>;

export interface LocalTurnDiffMutationOutcome {
  readonly status: 200 | 404 | 409;
  readonly body: LocalTurnDiffMutationBody;
}

export async function readLocalSessionDiff(input: {
  diffStore: LocalTurnDiffStore;
  session: LocalDiffSession;
  messageId?: string;
}): Promise<LocalSessionDiffView> {
  const record = input.messageId
    ? await input.diffStore.getByAssistantMessage(input.session.sessionId, input.messageId)
    : await input.diffStore.latestForSession(input.session.sessionId);
  if (record) return { diffs: record.fileChanges, changeSetId: record.changeSetId };
  const live = await readWorkspaceDiff(input.session.workspaceDir);
  return { diffs: live.fileChanges };
}

export async function readLocalTurnDiff(input: {
  diffStore: LocalTurnDiffStore;
  sessionId: string;
  selector?: LocalTurnDiffSelector;
}): Promise<LocalTurnDiffView> {
  const record = await findTurnDiffRecord(input.diffStore, input.sessionId, input.selector ?? {});
  if (!record) return { fileChanges: [] };
  const latest = await input.diffStore.latestForSession(input.sessionId);
  return serializeTurnDiffRecord(record, latest?.changeSetId === record.changeSetId);
}

export async function mutateLocalTurnDiff(input: {
  diffStore: LocalTurnDiffStore;
  sessionId: string;
  selector?: LocalTurnDiffSelector;
  action: 'revert' | 'reapply';
  nowMs: () => number;
}): Promise<LocalTurnDiffMutationOutcome> {
  const record = await findTurnDiffRecord(input.diffStore, input.sessionId, input.selector ?? {});
  if (!record) {
    return { status: 404, body: { success: false, error: 'Turn diff not found' } };
  }
  if (input.action === 'revert' && record.status === 'reverted') {
    return { status: 200, body: { success: true, ...serializeTurnDiffRecord(record, true) } };
  }
  if (input.action === 'reapply' && record.status === 'active') {
    return { status: 200, body: { success: true, ...serializeTurnDiffRecord(record, true) } };
  }
  const latest = await input.diffStore.latestForSession(input.sessionId);
  if (latest?.changeSetId !== record.changeSetId) {
    return {
      status: 409,
      body: { success: false, error: 'Only the latest turn diff can be changed' },
    };
  }
  const result = await applyTurnDiffMutation(record, input.action);
  if (!result.ok) {
    return { status: 409, body: { success: false, error: result.error } };
  }
  const updated = await input.diffStore.updateStatus(
    input.sessionId,
    record.changeSetId,
    input.action === 'revert' ? 'reverted' : 'active',
    input.action === 'revert' ? input.nowMs() : undefined,
  );
  return {
    status: 200,
    body: { success: true, ...serializeTurnDiffRecord(updated ?? record, true) },
  };
}

export async function routeLocalSessionDiffApi(input: {
  diffStore: LocalTurnDiffStore;
  session: LocalSessionRecord;
  url: URL;
}): Promise<Response> {
  const messageId =
    input.url.searchParams.get('messageID') ??
    input.url.searchParams.get('messageId') ??
    input.url.searchParams.get('assistantMessageId');
  return json(
    await readLocalSessionDiff({
      diffStore: input.diffStore,
      session: input.session,
      ...(messageId ? { messageId } : {}),
    }),
  );
}

export async function routeLocalTurnDiffApi(input: {
  diffStore: LocalTurnDiffStore;
  session: LocalSessionRecord;
  url: URL;
}): Promise<Response> {
  const result = await readLocalTurnDiff({
    diffStore: input.diffStore,
    sessionId: input.session.sessionId,
    selector: readTurnDiffSelector(input.url.searchParams),
  });
  return json(toLegacyTurnDiffBody(result));
}

export async function routeLocalTurnDiffMutationApi(input: {
  diffStore: LocalTurnDiffStore;
  session: LocalSessionRecord;
  action: 'revert' | 'reapply';
  body: Record<string, unknown>;
  nowMs: () => number;
}): Promise<Response> {
  const result = await mutateLocalTurnDiff({
    diffStore: input.diffStore,
    sessionId: input.session.sessionId,
    selector: readTurnDiffSelector(input.body),
    action: input.action,
    nowMs: input.nowMs,
  });
  return json(toLegacyTurnDiffBody(result.body), { status: result.status });
}

async function applyTurnDiffMutation(
  record: LocalTurnDiffRecord,
  action: 'revert' | 'reapply',
): Promise<{ ok: true } | { ok: false; error: string }> {
  if (record.undoable && record.undo?.length) {
    const result = await applyLocalTurnDiffSnapshotMutation(record, action);
    return result.success
      ? { ok: true }
      : { ok: false, error: result.reason ?? 'Turn diff conflict' };
  }
  if (!record.rawDiff) return { ok: false, error: 'Turn diff is not undoable' };
  return applyGitPatch({
    cwd: record.workspaceDir,
    patch: record.rawDiff,
    reverse: action === 'revert',
  });
}

function serializeTurnDiffRecord(
  record: LocalTurnDiffRecord,
  isLatest: boolean,
): LocalTurnDiffView {
  const undoable = record.undoable === true || Boolean(record.rawDiff);
  return {
    fileChanges: record.fileChanges,
    sourceMessageId: record.assistantMessageId,
    changeSetId: record.changeSetId,
    status: record.status,
    revertedAt: record.revertedAt,
    undoable,
    canUndo: undoable && isLatest && record.status === 'active',
    canReapply: undoable && isLatest && record.status === 'reverted',
  };
}

async function findTurnDiffRecord(
  store: LocalTurnDiffStore,
  sessionId: string,
  selector: LocalTurnDiffSelector,
): Promise<LocalTurnDiffRecord | undefined> {
  if (selector.changeSetId) return store.getByChangeSetId(sessionId, selector.changeSetId);
  if (selector.assistantMessageId) {
    return store.getByAssistantMessage(sessionId, selector.assistantMessageId);
  }
  if (selector.turnId) return store.getByTurn(sessionId, selector.turnId);
  return store.latestForSession(sessionId);
}

function readTurnDiffSelector(
  source: URLSearchParams | Record<string, unknown>,
): LocalTurnDiffSelector {
  const read = (key: string): string | undefined => {
    if (source instanceof URLSearchParams) return source.get(key) ?? undefined;
    return typeof source[key] === 'string' ? source[key] : undefined;
  };
  const assistantMessageId = read('assistantMessageId') ?? read('messageId') ?? read('messageID');
  return {
    ...(read('changeSetId') ? { changeSetId: read('changeSetId') } : {}),
    ...(assistantMessageId ? { assistantMessageId } : {}),
    ...(read('turnId') ? { turnId: read('turnId') } : {}),
  };
}

function toLegacyTurnDiffBody(
  view: LocalTurnDiffView | LocalTurnDiffMutationBody,
): Record<string, unknown> {
  const { fileChanges, ...rest } = view;
  return {
    ...rest,
    ...(fileChanges ? { file_changes: fileChanges } : {}),
  };
}

async function readWorkspaceDiff(
  workspaceDir: string,
): Promise<{ fileChanges: LocalFileDiff[]; rawDiff?: string }> {
  try {
    const [nameStatus, numstat, rawDiff] = await Promise.all([
      execGit(['diff', 'HEAD', '--name-status', '--'], workspaceDir),
      execGit(['diff', 'HEAD', '--numstat', '--'], workspaceDir),
      execGit(['diff', 'HEAD', '--'], workspaceDir),
    ]);
    const untracked = await readUntrackedFiles(workspaceDir);
    const untrackedDiffs = await Promise.all(
      untracked.map((file) => readUntrackedFileDiff(workspaceDir, file)),
    );
    const raw = [rawDiff.stdout, ...untrackedDiffs.flatMap((item) => item.rawDiff ?? [])]
      .filter(Boolean)
      .join('\n');
    const fileChanges = [
      ...parseGitDiffSummary(nameStatus.stdout, numstat.stdout, rawDiff.stdout),
      ...untrackedDiffs.map((item) => item.fileChange),
    ];
    return { fileChanges, ...(raw ? { rawDiff: raw } : {}) };
  } catch {
    return { fileChanges: [] };
  }
}

async function execGit(args: string[], cwd: string): Promise<{ stdout: string; stderr: string }> {
  return execFile('git', args, {
    cwd,
    env: cleanGitEnv(),
    maxBuffer: 10 * 1024 * 1024,
  });
}

function parseGitDiffSummary(
  nameStatus: string,
  numstat: string,
  rawDiff: string,
): LocalFileDiff[] {
  const stats = new Map<string, { additions: number; deletions: number }>();
  for (const line of numstat.split('\n')) {
    if (!line.trim()) continue;
    const [additions, deletions, ...pathParts] = line.split('\t');
    const file = pathParts.join('\t');
    if (!file) continue;
    stats.set(file, {
      additions: numericDiffStat(additions),
      deletions: numericDiffStat(deletions),
    });
  }
  const patches = splitPatchByFile(rawDiff);
  const out: LocalFileDiff[] = [];
  for (const line of nameStatus.split('\n')) {
    if (!line.trim()) continue;
    const [statusToken, ...pathParts] = line.split('\t');
    const file = pathParts[pathParts.length - 1];
    if (!file) continue;
    const stat = stats.get(file) ?? { additions: 0, deletions: 0 };
    out.push({
      file,
      additions: stat.additions,
      deletions: stat.deletions,
      status: mapGitStatus(statusToken),
      ...(patches.get(file) ? { diff: patches.get(file) } : {}),
    });
  }
  return out;
}

async function readUntrackedFiles(workspaceDir: string): Promise<string[]> {
  try {
    const result = await execGit(['ls-files', '--others', '--exclude-standard'], workspaceDir);
    return result.stdout
      .split('\n')
      .map((line) => line.trim())
      .filter(Boolean);
  } catch {
    return [];
  }
}

async function readUntrackedFileDiff(
  workspaceDir: string,
  file: string,
): Promise<{ fileChange: LocalFileDiff; rawDiff?: string }> {
  try {
    const rawDiff = await execFile('git', ['diff', '--no-index', '--', '/dev/null', file], {
      cwd: workspaceDir,
      env: cleanGitEnv(),
      maxBuffer: 10 * 1024 * 1024,
    }).catch((err: unknown) => {
      const error = err as { stdout?: string; code?: number };
      if (error.code === 1 && typeof error.stdout === 'string') return { stdout: error.stdout };
      throw err;
    });
    const text = rawDiff.stdout;
    const additions = text
      .split('\n')
      .filter((line) => line.startsWith('+') && !line.startsWith('+++')).length;
    return {
      fileChange: {
        file,
        additions,
        deletions: 0,
        status: 'added',
        ...(text ? { diff: text } : {}),
      },
      ...(text ? { rawDiff: text } : {}),
    };
  } catch {
    return {
      fileChange: {
        file,
        additions: 0,
        deletions: 0,
        status: 'added',
      },
    };
  }
}

function splitPatchByFile(rawDiff: string): Map<string, string> {
  const patches = new Map<string, string>();
  const chunks = rawDiff.split(/^diff --git /m);
  for (const chunk of chunks) {
    if (!chunk.trim()) continue;
    const text = `diff --git ${chunk}`;
    const match = /^diff --git a\/(.+?) b\/(.+)$/m.exec(text);
    const file = match?.[2];
    if (file) patches.set(file, text);
  }
  return patches;
}

function mapGitStatus(status: string | undefined): string {
  const code = status?.[0];
  if (code === 'A') return 'added';
  if (code === 'D') return 'deleted';
  if (code === 'R') return 'renamed';
  if (code === 'C') return 'copied';
  return 'modified';
}

function numericDiffStat(value: string | undefined): number {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : 0;
}

function applyGitPatch(input: {
  cwd: string;
  patch: string;
  reverse: boolean;
}): Promise<{ ok: true } | { ok: false; error: string }> {
  return new Promise((resolve) => {
    const args = ['apply', '--whitespace=nowarn', ...(input.reverse ? ['--reverse'] : [])];
    const child = spawn('git', args, { cwd: input.cwd, env: cleanGitEnv() });
    let stderr = '';
    child.stderr.setEncoding('utf8');
    child.stderr.on('data', (chunk) => {
      stderr += chunk;
    });
    child.on('error', (err) => {
      resolve({ ok: false, error: err.message });
    });
    child.on('close', (code) => {
      if (code === 0) {
        resolve({ ok: true });
        return;
      }
      resolve({ ok: false, error: stderr.trim() || `git apply exited with ${String(code)}` });
    });
    child.stdin.end(input.patch);
  });
}

function cleanGitEnv(): NodeJS.ProcessEnv {
  // `git apply` is a bash-adjacent subprocess: passing `process.env` through
  // would leak `MAVIS_ACCESS_TOKEN` / `MATRIX_TOKEN` / `*_API_KEY` into the
  // child. Route through the shared sanitizer (scrub mode) so the env is
  // always stripped before reaching git, then layer the GIT_* reset on top
  // to avoid the worktree picking up the parent's repository context.
  const { env } = sanitizeBashSubprocessEnv(process.env, { mode: 'scrub' });
  delete env['GIT_DIR'];
  delete env['GIT_WORK_TREE'];
  delete env['GIT_INDEX_FILE'];
  delete env['GIT_PREFIX'];
  delete env['GIT_OBJECT_DIRECTORY'];
  delete env['GIT_ALTERNATE_OBJECT_DIRECTORIES'];
  return env;
}
