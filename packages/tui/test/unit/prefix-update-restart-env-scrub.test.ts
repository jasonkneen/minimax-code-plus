/**
 * Regression test for the TUI prefix-update restart env scrubbing.
 *
 * The activator IIFE's `restart()` helper previously spawned
 * `process.execPath` with `env: process.env`, leaking desktop secrets into
 * the new mcode child. The fix routes through
 * `sanitizeBashSubprocessEnv({mode: 'scrub'})` and additionally drops the
 * update-flow-local vars.
 *
 * The env-construction logic is exposed as `buildRestartEnv` (marked
 * `@internal`) so this test can verify the sanitizer path without driving
 * the full activator IIFE.
 */
import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { buildRestartEnv, MCODE_UPDATE_PARENT_PID_ENV } from '../../src/update/prefix-update.js';

describe('prefix-update restart env scrubbing', () => {
  const originalEnv = process.env;

  beforeEach(() => {
    process.env = {
      ...originalEnv,
      MAVIS_ACCESS_TOKEN: 'leaked-mavis-token',
      MATRIX_TOKEN: 'leaked-matrix-token',
      ANTHROPIC_API_KEY: 'leaked-anthropic',
      OPENAI_API_KEY: 'leaked-openai',
      [MCODE_UPDATE_PARENT_PID_ENV]: '12345',
      MCODE_UPDATE_ACTIVATOR_LEASE: 'sentinel-lease',
      MCODE_UPDATE_PENDING_FILE: '/tmp/pending.json',
      MCODE_UPDATE_ACTIVATION_STATUS: 'waiting-parent',
      PATH: '/usr/bin',
    };
  });

  afterEach(() => {
    process.env = originalEnv;
  });

  it('strips MAVIS_ACCESS_TOKEN, MATRIX_TOKEN, and *_API_KEY from the restart env', () => {
    const env = buildRestartEnv();
    expect(env.MAVIS_ACCESS_TOKEN).toBeUndefined();
    expect(env.MATRIX_TOKEN).toBeUndefined();
    expect(env.ANTHROPIC_API_KEY).toBeUndefined();
    expect(env.OPENAI_API_KEY).toBeUndefined();
    // PATH must survive so the new mcode child can resolve its tools.
    expect(env.PATH).toBe('/usr/bin');
  });

  it('also strips the update-flow local vars (parent pid, lease, pending file, status)', () => {
    const env = buildRestartEnv();
    expect(env[MCODE_UPDATE_PARENT_PID_ENV]).toBeUndefined();
    expect(env.MCODE_UPDATE_ACTIVATOR_LEASE).toBeUndefined();
    expect(env.MCODE_UPDATE_PENDING_FILE).toBeUndefined();
    expect(env.MCODE_UPDATE_ACTIVATION_STATUS).toBeUndefined();
  });
});