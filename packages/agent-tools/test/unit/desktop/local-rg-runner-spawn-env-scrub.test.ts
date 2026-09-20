/**
 * Regression test for the desktop ripgrep subprocess env scrubbing.
 *
 * `runRg` previously spawned ripgrep with no `env` option, so
 * `process.env` (and all desktop secrets) were inherited by the rg child.
 * The fix routes through `sanitizeBashSubprocessEnv({mode: 'scrub'})` so
 * `MAVIS_ACCESS_TOKEN` / `MATRIX_TOKEN` / `*_API_KEY` cannot reach rg or
 * any helper git/script rg shells out to.
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

import { runRg } from '../../../src/desktop/local-rg-runner.js';

class FakeChildProcess extends EventEmitter {
  stdin = new Writable({ write(_chunk, _enc, cb) { cb(); } });
  stdout = new Readable({ read() {} });
  stderr = new Readable({ read() {} });
}

function buildChild(): FakeChildProcess {
  const child = new FakeChildProcess();
  queueMicrotask(() => {
    child.stdout.push(Buffer.from(''));
    child.stdout.push(null);
    child.emit('close', 0);
  });
  return child;
}

describe('local-rg-runner spawn env scrubbing', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    spawnMock.mockReset();
    process.env = {
      ...originalEnv,
      MAVIS_ACCESS_TOKEN: 'leaked-mavis-token',
      MATRIX_TOKEN: 'leaked-matrix-token',
      ANTHROPIC_API_KEY: 'leaked-anthropic',
      OPENAI_API_KEY: 'leaked-openai',
      PATH: '/usr/bin',
    };
    spawnMock.mockImplementation(() => buildChild());
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  it('strips MAVIS_ACCESS_TOKEN, MATRIX_TOKEN, and *_API_KEY from the rg spawn env', async () => {
    const result = await runRg(['--version'], '/tmp', { timeoutMs: 1000 });
    expect(result.exitCode).toBe(0);
    expect(spawnMock).toHaveBeenCalledTimes(1);
    const opts = spawnMock.mock.calls[0][2] as { env?: NodeJS.ProcessEnv };
    expect(opts.env).toBeDefined();
    expect(opts.env?.MAVIS_ACCESS_TOKEN).toBeUndefined();
    expect(opts.env?.MATRIX_TOKEN).toBeUndefined();
    expect(opts.env?.ANTHROPIC_API_KEY).toBeUndefined();
    expect(opts.env?.OPENAI_API_KEY).toBeUndefined();
    // Sanity: PATH must survive so rg can locate its bundled helper scripts.
    expect(opts.env?.PATH).toBe('/usr/bin');
  });
});