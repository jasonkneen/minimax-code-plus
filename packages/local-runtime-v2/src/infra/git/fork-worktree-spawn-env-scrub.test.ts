/**
 * Regression test for the fork-worktree git subprocess env scrubbing.
 *
 * `gitWithInput` and `streamGit` previously spawned git with no `env` option
 * (so `process.env` was inherited). The fix routes both through
 * `sanitizeBashSubprocessEnv({mode: 'scrub'})` so desktop secrets cannot
 * leak into the git child.
 */
import { EventEmitter } from 'node:events';
import { Readable, Writable } from 'node:stream';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

const spawnMock = vi.fn();
const realpathMock = vi.fn();
const lstatMock = vi.fn();

vi.mock('node:child_process', async () => {
  const actual = await vi.importActual<typeof import('node:child_process')>('node:child_process');
  return {
    ...actual,
    spawn: (...args: unknown[]) => spawnMock(...args),
  };
});

// Realpath / lstat are the first fs calls resolveRepositoryContext makes,
// before any git spawn. Mock them so the test can drive the path to the
// first spawn without provisioning real on-disk state.
vi.mock('node:fs/promises', async () => {
  const actual = await vi.importActual<typeof import('node:fs/promises')>('node:fs/promises');
  return {
    ...actual,
    realpath: (...args: unknown[]) => realpathMock(...args),
    lstat: (...args: unknown[]) => lstatMock(...args),
  };
});

// The fork-worktree-adapter pulls in heavy fs dependencies; isolate the
// test to spawn-only by intercepting the streamGit/gitWithInput helpers
// via re-export shims. The adapter's `prepare()` path goes through `git`
// → `streamGit` → spawn, so capturing the spawn options is enough to
// verify the env scrubbing applied at the call site.
import { createForkWorktreeAdapter } from './fork-worktree-adapter.js';

class FakeChildProcess extends EventEmitter {
  stdin = new Writable({ write(_chunk, _enc, cb) { cb(); } });
  stdout = new Readable({ read() {} });
  stderr = new Readable({ read() {} });
}

function buildChild(payload = ''): FakeChildProcess {
  const child = new FakeChildProcess();
  queueMicrotask(() => {
    if (payload) child.stdout.push(Buffer.from(payload));
    child.stdout.push(null); // EOF: end the readable so for-await unblocks.
    child.emit('close', 0);
  });
  return child;
}

describe('fork-worktree-adapter.ts git subprocess env scrubbing', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    spawnMock.mockReset();
    realpathMock.mockReset();
    lstatMock.mockReset();
    process.env = {
      ...originalEnv,
      MAVIS_ACCESS_TOKEN: 'leaked-mavis-token',
      MATRIX_TOKEN: 'leaked-matrix-token',
      ANTHROPIC_API_KEY: 'leaked-anthropic',
      OPENAI_API_KEY: 'leaked-openai',
      PATH: '/usr/bin',
    };
    spawnMock.mockImplementation(() => buildChild());
    // resolveRepositoryContext: realpath(workspaceDir) → /tmp/workspace,
    // lstat(/tmp/workspace) → directory.
    realpathMock.mockImplementation(async (input: string) => input);
    lstatMock.mockImplementation(async () => ({
      isDirectory: () => true,
      isSymbolicLink: () => false,
    }));
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  it('exercises spawn with a sanitized env when the worktree adapter spawns git', async () => {
    // The fixture below mirrors what the adapter expects to find on disk;
    // the spawn mock is wired to satisfy the streaming pipeline without
    // needing real git output. We assert only the env sanitization here —
    // adapter correctness is covered by dedicated adapter tests elsewhere.
    const adapter = createForkWorktreeAdapter({
      worktreeParent: '/tmp/worktree-parent',
      makeSuffix: () => 'suffix-1',
    });

    // Drive prepare() to the first git spawn. We deliberately pass an
    // unsupported shape so prepare() throws early — the throw happens
    // AFTER the first spawn (the resolveRepositoryContext call) so the
    // env is captured. The test asserts only the captured env.
    try {
      await adapter.prepare({
        operationId: 'op-1',
        source: {
          workspaceDir: '/tmp/workspace',
          appMode: 'coding',
        },
      });
    } catch {
      // Expected: the adapter requires filesystem state we do not provide.
    }

    // At minimum, the resolveRepositoryContext path must have called spawn
    // (for `git rev-parse --show-toplevel`). The sanitizer must have
    // stripped the desktop secrets from the env passed to that spawn.
    expect(spawnMock).toHaveBeenCalled();
    const seenEnvs = spawnMock.mock.calls.map((call) => {
      const opts = call[2] as { env?: NodeJS.ProcessEnv };
      return opts.env;
    });
    expect(seenEnvs.length).toBeGreaterThan(0);
    for (const env of seenEnvs) {
      expect(env).toBeDefined();
      expect(env?.MAVIS_ACCESS_TOKEN).toBeUndefined();
      expect(env?.MATRIX_TOKEN).toBeUndefined();
      expect(env?.ANTHROPIC_API_KEY).toBeUndefined();
      expect(env?.OPENAI_API_KEY).toBeUndefined();
    }
  });
});