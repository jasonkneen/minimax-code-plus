/**
 * Regression test for the git-apply subprocess used by `mutateLocalTurnDiff`.
 *
 * `applyGitPatch` spawns `git apply` from inside `cleanGitEnv()`, which
 * previously copied `process.env` and only stripped 5 GIT_* vars. The fix
 * routes through `sanitizeBashSubprocessEnv({mode: 'scrub'})` so desktop
 * secrets (MAVIS_ACCESS_TOKEN, MATRIX_TOKEN, *_API_KEY) cannot leak into the
 * spawned git child.
 */
import { EventEmitter } from 'node:events';
import { Readable, Writable } from 'node:stream';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const spawnMock = vi.fn();

vi.mock('node:child_process', async () => {
  const actual = await vi.importActual<typeof import('node:child_process')>('node:child_process');
  return {
    ...actual,
    spawn: (...args: unknown[]) => spawnMock(...args),
  };
});

import { mutateLocalTurnDiff } from '../../src/turns/diff-api.js';
import type { LocalTurnDiffRecord, LocalTurnDiffStore } from '../../src/persistence/ports.js';

class FakeChildProcess extends EventEmitter {
  stdin = new Writable({ write(_chunk, _enc, cb) { cb(); } });
  stdout = new Readable({ read() {} });
  stderr = new Readable({ read() {} });
}

function buildStore(record: LocalTurnDiffRecord): LocalTurnDiffStore {
  return {
    upsert: vi.fn(async () => undefined),
    getByTurn: vi.fn(async () => record),
    getByMessage: vi.fn(async () => record),
    getByChangeSet: vi.fn(async () => record),
    latestForSession: vi.fn(async () => record),
    listBySession: vi.fn(async () => [record]),
    listByMessage: vi.fn(async () => [record]),
    updateStatus: vi.fn(async (id, cs, status) => ({ ...record, sessionId: id, changeSetId: cs, status })),
    recordSnapshot: vi.fn(async () => undefined),
    pendingTurns: vi.fn(async () => []),
    pendingBySession: vi.fn(async () => []),
    consumePending: vi.fn(async () => undefined),
  } as unknown as LocalTurnDiffStore;
}

describe('diff-api.ts git apply subprocess env scrubbing', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    spawnMock.mockReset();
    // Stage sensitive desktop env vars in the parent process so the test
    // can assert they are stripped before reaching the spawned git child.
    process.env = {
      ...originalEnv,
      MAVIS_ACCESS_TOKEN: 'leaked-mavis-token',
      MATRIX_TOKEN: 'leaked-matrix-token',
      ANTHROPIC_API_KEY: 'leaked-anthropic',
      OPENAI_API_KEY: 'leaked-openai',
      PATH: '/usr/bin',
    };
    spawnMock.mockImplementation(() => {
      const child = new FakeChildProcess();
      // Close immediately with code 0 so applyGitPatch resolves successfully.
      queueMicrotask(() => child.emit('close', 0));
      return child;
    });
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  it('strips MAVIS_ACCESS_TOKEN, MATRIX_TOKEN, and *_API_KEY from the spawn env', async () => {
    const record: LocalTurnDiffRecord = {
      changeSetId: 'cs-1',
      sessionId: 'sess-1',
      turnId: 'turn-1',
      workspaceDir: '/tmp/workspace',
      capturedAtMs: 0,
      status: 'active',
      fileChanges: [],
      // rawDiff present, undoable absent → applyGitPatch (spawn path).
      rawDiff: 'diff --git a/x b/x\n',
    };
    const store = buildStore(record);

    const result = await mutateLocalTurnDiff({
      diffStore: store,
      sessionId: 'sess-1',
      // 'revert' against an active record must invoke git apply via spawn.
      action: 'revert',
      nowMs: () => 1,
    });

    expect(result.status).toBe(200);
    expect(spawnMock).toHaveBeenCalledTimes(1);
    const [, , options] = spawnMock.mock.calls[0] as [string, string[], { env?: NodeJS.ProcessEnv }];
    expect(options.env).toBeDefined();
    expect(options.env?.MAVIS_ACCESS_TOKEN).toBeUndefined();
    expect(options.env?.MATRIX_TOKEN).toBeUndefined();
    expect(options.env?.ANTHROPIC_API_KEY).toBeUndefined();
    expect(options.env?.OPENAI_API_KEY).toBeUndefined();
    // Sanity: the child must still have PATH so git can resolve.
    expect(options.env?.PATH).toBe('/usr/bin');
    // The 5 GIT_* vars should still be stripped (post-sanitize cleanup).
    expect(options.env?.GIT_DIR).toBeUndefined();
    expect(options.env?.GIT_WORK_TREE).toBeUndefined();
    expect(options.env?.GIT_INDEX_FILE).toBeUndefined();
    expect(options.env?.GIT_PREFIX).toBeUndefined();
    expect(options.env?.GIT_OBJECT_DIRECTORY).toBeUndefined();
    expect(options.env?.GIT_ALTERNATE_OBJECT_DIRECTORIES).toBeUndefined();
  });
});