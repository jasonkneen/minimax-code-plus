/**
 * Regression test for the miniapp host-runner subprocess env scrubbing.
 *
 * `createMiniAppNodeRuntimeAdapter` previously defaulted `options.env` to
 * `process.env`, leaking `MAVIS_ACCESS_TOKEN` / `MATRIX_TOKEN` / `*_API_KEY`
 * into the spawned host-runner child. The fix routes the default through
 * `sanitizeBashSubprocessEnv({mode: 'scrub'})` so the desktop secrets never
 * reach the child. `runnerEnvironment` further narrows the env to a small
 * PATH/HOME/TMP allowlist before the spawn.
 *
 * The combined sanitize + narrow pipeline is exposed as `buildHostRunnerEnv`
 * (marked `@internal`) so this test can verify the env-scrubbing contract
 * without driving the full prepare flow (filesystem state, port reservation,
 * IPC handshake).
 */
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { buildHostRunnerEnv } from './node-runtime.js';

describe('miniapp node-runtime host-runner env scrubbing', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    process.env = {
      ...originalEnv,
      MAVIS_ACCESS_TOKEN: 'leaked-mavis-token',
      MATRIX_TOKEN: 'leaked-matrix-token',
      ANTHROPIC_API_KEY: 'leaked-anthropic',
      OPENAI_API_KEY: 'leaked-openai',
      PATH: '/usr/bin',
      HOME: '/home/test',
    };
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  it('strips MAVIS_ACCESS_TOKEN, MATRIX_TOKEN, and *_API_KEY from the host-runner env', () => {
    const env = buildHostRunnerEnv();
    expect(env.MAVIS_ACCESS_TOKEN).toBeUndefined();
    expect(env.MATRIX_TOKEN).toBeUndefined();
    expect(env.ANTHROPIC_API_KEY).toBeUndefined();
    expect(env.OPENAI_API_KEY).toBeUndefined();
    // PATH and HOME survive the runnerEnvironment narrowing.
    expect(env.PATH).toBe('/usr/bin');
    expect(env.HOME).toBe('/home/test');
    // ELECTRON_RUN_AS_NODE is set by runnerEnvironment so the child runs
    // under the Electron-as-Node binary.
    expect(env.ELECTRON_RUN_AS_NODE).toBe('1');
  });

  it('honors a caller-supplied env override and still scrubs it', () => {
    const env = buildHostRunnerEnv({
      MAVIS_ACCESS_TOKEN: 'should-not-leak',
      MATRIX_TOKEN: 'should-not-leak',
      ANTHROPIC_API_KEY: 'should-not-leak',
      OPENAI_API_KEY: 'should-not-leak',
      PATH: '/custom/bin',
    });
    expect(env.MAVIS_ACCESS_TOKEN).toBeUndefined();
    expect(env.MATRIX_TOKEN).toBeUndefined();
    expect(env.ANTHROPIC_API_KEY).toBeUndefined();
    expect(env.OPENAI_API_KEY).toBeUndefined();
    expect(env.PATH).toBe('/custom/bin');
  });
});