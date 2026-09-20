/**
 * getRuntimeBuildEnv hardening.
 *
 * `MAVIS_BUILD_ENV` used to be read directly from `process.env`, which let
 * any child process — including one launched by an attacker who can set
 * shell env — silently flip the runtime at the staging host. The fix
 * restricts the env-var read to callers that have explicitly opted in via
 * the `--env` CLI flag, mirroring how `packages/tui/src/cli/environment.ts`
 * gates the TUI's `--lane` startup flag.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';

import { getRuntimeBuildEnv } from '../../src/config.js';

const originalArgv = process.argv;

afterEach(() => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
  // `process.argv` is replaced wholesale by the test; restore the original
  // snapshot so subsequent tests do not inherit a polluted CLI.
  Object.defineProperty(process, 'argv', { value: originalArgv, writable: true, configurable: true });
});

function stubArgv(args: readonly string[]): void {
  Object.defineProperty(process, 'argv', { value: [...args], writable: true, configurable: true });
}

describe('getRuntimeBuildEnv CLI-flag gate', () => {
  it('ignores MAVIS_BUILD_ENV when the --env flag is absent', () => {
    stubArgv(['node', 'mavis']);
    vi.stubEnv('MAVIS_BUILD_ENV', 'staging');
    expect(getRuntimeBuildEnv()).toBe('dev');
  });

  it('honors MAVIS_BUILD_ENV when --env is passed as a separate argument', () => {
    stubArgv(['node', 'mavis', '--env', 'staging']);
    vi.stubEnv('MAVIS_BUILD_ENV', 'staging');
    expect(getRuntimeBuildEnv()).toBe('staging');
  });

  it('honors MAVIS_BUILD_ENV when --env is passed via the equals form', () => {
    stubArgv(['node', 'mavis', '--env=prod']);
    vi.stubEnv('MAVIS_BUILD_ENV', 'prod');
    expect(getRuntimeBuildEnv()).toBe('prod');
  });

  it('falls back to dev when --env is set but MAVIS_BUILD_ENV is not valid', () => {
    stubArgv(['node', 'mavis', '--env', 'staging']);
    vi.stubEnv('MAVIS_BUILD_ENV', 'definitely-not-an-env');
    expect(getRuntimeBuildEnv()).toBe('dev');
  });

  it('does not match a flag named --environment as the --env opt-in', () => {
    stubArgv(['node', 'mavis', '--environment', 'prod']);
    vi.stubEnv('MAVIS_BUILD_ENV', 'prod');
    expect(getRuntimeBuildEnv()).toBe('dev');
  });
});
