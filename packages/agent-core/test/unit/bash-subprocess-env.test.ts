import { describe, expect, it } from 'vitest';

import {
  BASH_SUBPROCESS_SCRUB,
  createBashEnvSpawnHook,
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

const providerEnv = {
  MCODE_PROVIDER_API_KEY: 'synthetic-provider-value',
  INPUT_MCODE_PROVIDER_API_KEY: 'synthetic-input-value',
  MCODE_PROVIDER_BASE_URL: 'https://provider.example.invalid',
  MCODE_PROVIDER_MODEL: 'synthetic-model',
  CUSTOM_PROVIDER_API_KEY: 'synthetic-custom-value',
  GH_TOKEN: 'synthetic-gh-value',
  GITHUB_TOKEN: 'synthetic-github-value',
  NPM_TOKEN: 'synthetic-npm-value',
};

describe('bash subprocess default provider credentials', () => {
  it.each([{ CI: 'true' }, { GITHUB_ACTIONS: 'true' }, { MAVIS_BASH_ENV_SANITIZE: 'scrub' }])(
    'scrubs both provider key names using policy %j',
    (markers) => {
      const original = { ...providerEnv, ...markers };
      const policy = resolveBashEnvPolicy(undefined, original);
      expect(policy.mode).toBe('scrub');
      const { env, removed } = sanitizeBashSubprocessEnv(original, policy);
      const { MCODE_PROVIDER_API_KEY, INPUT_MCODE_PROVIDER_API_KEY, ...preserved } = original;
      expect(env).toEqual(preserved);
      expect(removed).toEqual(['INPUT_MCODE_PROVIDER_API_KEY', 'MCODE_PROVIDER_API_KEY']);
      expect(original.MCODE_PROVIDER_API_KEY).toBe(MCODE_PROVIDER_API_KEY);
      expect(original.INPUT_MCODE_PROVIDER_API_KEY).toBe(INPUT_MCODE_PROVIDER_API_KEY);
    },
  );

  it('applies scrub to the actual spawn-hook environment without mutating its input', () => {
    const original = { command: 'echo synthetic', cwd: '.', env: { ...providerEnv } };
    const result = createBashEnvSpawnHook({ mode: 'scrub' })(original);
    expect(result.env).not.toHaveProperty('MCODE_PROVIDER_API_KEY');
    expect(result.env).not.toHaveProperty('INPUT_MCODE_PROVIDER_API_KEY');
    expect(result.command).toBe(original.command);
    expect(original.env).toEqual(providerEnv);
  });

  it('preserves credentials when off is explicitly selected, including in CI', () => {
    const policy = resolveBashEnvPolicy({ mode: 'off' }, { CI: 'true' });
    expect(sanitizeBashSubprocessEnv(providerEnv, policy)).toEqual({
      env: providerEnv,
      removed: [],
    });
  });

  it('continues to strip both provider names in strict mode', () => {
    const { env, removed } = sanitizeBashSubprocessEnv(providerEnv, { mode: 'strict' });
    expect(env).not.toHaveProperty('MCODE_PROVIDER_API_KEY');
    expect(env).not.toHaveProperty('INPUT_MCODE_PROVIDER_API_KEY');
    expect(removed).toContain('MCODE_PROVIDER_API_KEY');
    expect(removed).toContain('INPUT_MCODE_PROVIDER_API_KEY');
    expect(env.MCODE_PROVIDER_MODEL).toBe(providerEnv.MCODE_PROVIDER_MODEL);
    expect(env.MCODE_PROVIDER_BASE_URL).toBe(providerEnv.MCODE_PROVIDER_BASE_URL);
  });

  it('retains the explicit strict allowlist escape hatch', () => {
    const { env } = sanitizeBashSubprocessEnv(providerEnv, {
      mode: 'strict',
      allowlist: ['MCODE_PROVIDER_API_KEY', 'INPUT_MCODE_PROVIDER_API_KEY'],
    });
    expect(env.MCODE_PROVIDER_API_KEY).toBe(providerEnv.MCODE_PROVIDER_API_KEY);
    expect(env.INPUT_MCODE_PROVIDER_API_KEY).toBe(providerEnv.INPUT_MCODE_PROVIDER_API_KEY);
  });
});
