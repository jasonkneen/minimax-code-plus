import { describe, expect, it } from 'vitest';

import {
  BASH_SUBPROCESS_SCRUB,
  resolveBashEnvPolicy,
  sanitizeBashSubprocessEnv,
} from '../../src/bash-subprocess-env.js';

describe('resolveBashEnvPolicy', () => {
  it('defaults to scrub mode for desktop launches', () => {
    // No env switch, no CI markers: must not silently disable secret scrubbing.
    expect(resolveBashEnvPolicy({}, {})).toEqual({ mode: 'scrub' });
  });

  it('defaults to scrub even when GITHUB_ACTIONS or CI markers are unset', () => {
    // Regression: prior behavior returned 'off' outside CI markers, leaking
    // MAVIS_ACCESS_TOKEN / MATRIX_TOKEN / *_API_KEY into subprocesses.
    expect(resolveBashEnvPolicy({}, { PATH: '/usr/bin' })).toEqual({ mode: 'scrub' });
  });

  it('honors explicit override `mode` over the env switch', () => {
    expect(resolveBashEnvPolicy({ mode: 'strict' }, { MAVIS_BASH_ENV_SANITIZE: 'off' })).toEqual({
      mode: 'strict',
    });
  });

  it('honors explicit override `mode: "off"` for power users', () => {
    expect(resolveBashEnvPolicy({ mode: 'off' }, {})).toEqual({ mode: 'off' });
  });

  it('reads MAVIS_BASH_ENV_SANITIZE env switch when no override is given', () => {
    expect(resolveBashEnvPolicy({}, { MAVIS_BASH_ENV_SANITIZE: 'strict' })).toEqual({
      mode: 'strict',
    });
    expect(resolveBashEnvPolicy({}, { MAVIS_BASH_ENV_SANITIZE: 'off' })).toEqual({
      mode: 'off',
    });
  });

  it('ignores an invalid MAVIS_BASH_ENV_SANITIZE value and falls back to scrub', () => {
    expect(resolveBashEnvPolicy({}, { MAVIS_BASH_ENV_SANITIZE: 'bogus' })).toEqual({
      mode: 'scrub',
    });
  });

  it('passes through allowlist, prependPath, and spawnPreflight when provided', () => {
    const preflight = () => undefined;
    expect(
      resolveBashEnvPolicy(
        { allowlist: ['FOO'], prependPath: ['/shim'], spawnPreflight: preflight },
        {},
      ),
    ).toEqual({
      mode: 'scrub',
      allowlist: ['FOO'],
      prependPath: ['/shim'],
      spawnPreflight: preflight,
    });
  });
});

describe('sanitizeBashSubprocessEnv with scrub mode', () => {
  it('strips MAVIS_ACCESS_TOKEN, MATRIX_TOKEN, and *_API_KEY by default', () => {
    const env: NodeJS.ProcessEnv = {
      MAVIS_ACCESS_TOKEN: 'secret-mavis',
      MATRIX_TOKEN: 'secret-matrix',
      ANTHROPIC_API_KEY: 'secret-key',
      OPENAI_API_KEY: 'openai-key',
      PATH: '/usr/bin',
      HOME: '/home/test',
    };
    const { env: scrubbed, removed } = sanitizeBashSubprocessEnv(env, { mode: 'scrub' });
    expect(scrubbed.MAVIS_ACCESS_TOKEN).toBeUndefined();
    expect(scrubbed.MATRIX_TOKEN).toBeUndefined();
    expect(scrubbed.ANTHROPIC_API_KEY).toBeUndefined();
    expect(scrubbed.OPENAI_API_KEY).toBeUndefined();
    expect(scrubbed.PATH).toBe('/usr/bin');
    expect(scrubbed.HOME).toBe('/home/test');
    expect(removed).toContain('MAVIS_ACCESS_TOKEN');
    expect(removed).toContain('MATRIX_TOKEN');
    expect(removed).toContain('ANTHROPIC_API_KEY');
    expect(removed).toContain('OPENAI_API_KEY');
  });

  it('also strips the INPUT_<NAME> GitHub Actions duplicate', () => {
    const env: NodeJS.ProcessEnv = { INPUT_FIGMA_API_TOKEN: 'leaked', FIGMA_API_TOKEN: 'leaked' };
    const { env: scrubbed, removed } = sanitizeBashSubprocessEnv(env, { mode: 'scrub' });
    expect(scrubbed.INPUT_FIGMA_API_TOKEN).toBeUndefined();
    expect(scrubbed.FIGMA_API_TOKEN).toBeUndefined();
    expect(removed).toContain('FIGMA_API_TOKEN');
    expect(removed).toContain('INPUT_FIGMA_API_TOKEN');
  });

  it('does not strip GH_TOKEN/GITHUB_TOKEN alternatives beyond the explicit blocklist', () => {
    // GITHUB_TOKEN is NOT in the blocklist by design (CC parity: gh CLI uses
    // it legitimately). The Layer A strip and scrub list together must not
    // accidentally remove it.
    const env: NodeJS.ProcessEnv = { GITHUB_TOKEN: 'gh-cli' };
    const { env: scrubbed } = sanitizeBashSubprocessEnv(env, { mode: 'scrub' });
    expect(scrubbed.GITHUB_TOKEN).toBe('gh-cli');
  });

  it('strips every entry in BASH_SUBPROCESS_SCRUB', () => {
    const env: NodeJS.ProcessEnv = {};
    for (const key of BASH_SUBPROCESS_SCRUB) env[key] = 'value';
    const { env: scrubbed, removed } = sanitizeBashSubprocessEnv(env, { mode: 'scrub' });
    for (const key of BASH_SUBPROCESS_SCRUB) expect(scrubbed[key]).toBeUndefined();
    for (const key of BASH_SUBPROCESS_SCRUB) expect(removed).toContain(key);
  });

  it('never mutates the input env object', () => {
    const env: NodeJS.ProcessEnv = { MAVIS_ACCESS_TOKEN: 'secret' };
    const snapshot = { ...env };
    sanitizeBashSubprocessEnv(env, { mode: 'scrub' });
    expect(env).toEqual(snapshot);
  });

  it('honors Layer A boundary strip independently of mode', () => {
    // Layer A is always on regardless of mode. MAVIS_DATA_DIR / MAVIS_PROFILE
    // are runtime identity keys, so both layers strip them.
    // ANTHROPIC_API_KEY is a Layer-B-only key, so it survives `mode: 'off'`
    // and is stripped in `mode: 'scrub'`.
    const env: NodeJS.ProcessEnv = {
      MAVIS_DATA_DIR: '/var/lib',
      MAVIS_PROFILE: 'desktop',
      ANTHROPIC_API_KEY: 'should-stay-scrubbed',
    };
    const off = sanitizeBashSubprocessEnv(env, { mode: 'off' });
    expect(off.env.MAVIS_DATA_DIR).toBeUndefined();
    expect(off.env.MAVIS_PROFILE).toBeUndefined();
    // Layer B is off, so ANTHROPIC_API_KEY survives in `off` mode.
    expect(off.env.ANTHROPIC_API_KEY).toBe('should-stay-scrubbed');

    const scrub = sanitizeBashSubprocessEnv(env, { mode: 'scrub' });
    expect(scrub.env.MAVIS_DATA_DIR).toBeUndefined();
    expect(scrub.env.MAVIS_PROFILE).toBeUndefined();
    expect(scrub.env.ANTHROPIC_API_KEY).toBeUndefined();
  });
});