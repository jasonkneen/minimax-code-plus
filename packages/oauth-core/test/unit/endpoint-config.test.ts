/**
 * Endpoint-resolution guard for the Shared MCode OAuth client.
 *
 * Before the fix, `resolveMCodeOAuthEndpointConfig` silently fell through
 * to `https://account-*-test.example.invalid` whenever the build environment
 * was `dev` / `test`, with no warning. That made it easy to:
 *
 *   - forget to set `MAVIS_BUILD_ENV` and accidentally mint tokens against a
 *     `*.example.invalid` host that never resolves,
 *   - flip a single env var in a prod build to land on the staging
 *     account origin and ride the `X-User-Pre: 1` header into a real
 *     pre-release account.
 *
 * The new gate refuses to construct the client unless the build environment
 * is `prod` / `staging` or the caller has explicitly set `MAVIS_DEV_OAUTH_OK=1`.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';

import {
  resolveMCodeOAuthEndpointConfig,
  type MCodeOAuthEndpointContext,
  type MCodeOAuthEndpointEnvironment,
} from '../../src/endpoint-config.js';

afterEach(() => {
  vi.unstubAllEnvs();
});

const cnContext: MCodeOAuthEndpointContext = { region: 'cn', buildEnv: 'prod' };
const enContext: MCodeOAuthEndpointContext = { region: 'en', buildEnv: 'prod' };

describe('resolveMCodeOAuthEndpointConfig dev/test gate', () => {
  it('refuses a dev build unless MAVIS_DEV_OAUTH_OK is set', () => {
    expect(() =>
      resolveMCodeOAuthEndpointConfig(
        {} satisfies MCodeOAuthEndpointEnvironment,
        { region: 'cn', buildEnv: 'dev' },
      ),
    ).toThrow(/Refusing to construct the Shared MCode OAuth client/);
  });

  it('refuses a test build unless MAVIS_DEV_OAUTH_OK is set', () => {
    expect(() =>
      resolveMCodeOAuthEndpointConfig(
        {} satisfies MCodeOAuthEndpointEnvironment,
        { region: 'en', buildEnv: 'test' },
      ),
    ).toThrow(/Refusing to construct the Shared MCode OAuth client/);
  });

  it('accepts a dev build when MAVIS_DEV_OAUTH_OK=1 is set', () => {
    vi.stubEnv('MAVIS_DEV_OAUTH_OK', '1');
    const config = resolveMCodeOAuthEndpointConfig(
      {} satisfies MCodeOAuthEndpointEnvironment,
      { region: 'cn', buildEnv: 'dev' },
    );
    expect(config.deviceAuthorizationEndpoint).toBe(
      'https://account-test.example.invalid/oauth2/device/code',
    );
    expect(config.tokenEndpoint).toBe('https://account-test.example.invalid/oauth2/token');
    expect(config.revocationEndpoint).toBe('https://account-test.example.invalid/oauth2/revoke');
  });

  it('still refuses the dev/test fallback when the env-var opt-in is anything other than "1"', () => {
    vi.stubEnv('MAVIS_DEV_OAUTH_OK', 'true');
    expect(() =>
      resolveMCodeOAuthEndpointConfig(
        {} satisfies MCodeOAuthEndpointEnvironment,
        { region: 'cn', buildEnv: 'dev' },
      ),
    ).toThrow(/Refusing to construct the Shared MCode OAuth client/);
  });

  it('does not gate prod builds on the dev opt-in env var', () => {
    const config = resolveMCodeOAuthEndpointConfig(
      {} satisfies MCodeOAuthEndpointEnvironment,
      cnContext,
    );
    expect(config.tokenEndpoint).toBe('https://account.minimax.cn/oauth2/token');
  });

  it('does not gate staging builds on the dev opt-in env var', () => {
    const config = resolveMCodeOAuthEndpointConfig(
      {} satisfies MCodeOAuthEndpointEnvironment,
      { region: 'en', buildEnv: 'staging' },
    );
    expect(config.tokenEndpoint).toBe('https://account-overseas-pre.example.invalid/oauth2/token');
    expect(config.deviceAuthorizationHeaders).toEqual({ 'X-User-Pre': '1' });
  });

  it('applies the same gate when endpoints are explicitly configured', () => {
    // Even with explicit endpoints, the gate must reject unauthorised
    // build-env combinations so a caller cannot bypass it by overriding
    // MCODE_OAUTH_* env vars while keeping buildEnv=dev.
    expect(() =>
      resolveMCodeOAuthEndpointConfig(
        {
          MCODE_OAUTH_DEVICE_AUTHORIZATION_ENDPOINT:
            'https://attacker.example.test/oauth2/device/code',
          MCODE_OAUTH_TOKEN_ENDPOINT: 'https://attacker.example.test/oauth2/token',
          MCODE_OAUTH_REVOCATION_ENDPOINT:
            'https://attacker.example.test/oauth2/revoke',
        },
        { region: 'cn', buildEnv: 'dev' },
      ),
    ).toThrow(/Refusing to construct the Shared MCode OAuth client/);
  });

  it('allows explicit endpoints when buildEnv=prod', () => {
    const config = resolveMCodeOAuthEndpointConfig(
      {
        MCODE_OAUTH_DEVICE_AUTHORIZATION_ENDPOINT:
          'https://account.example.test/oauth2/device/code',
        MCODE_OAUTH_TOKEN_ENDPOINT: 'https://account.example.test/oauth2/token',
        MCODE_OAUTH_REVOCATION_ENDPOINT: 'https://account.example.test/oauth2/revoke',
      },
      enContext,
    );
    expect(config.tokenEndpoint).toBe('https://account.example.test/oauth2/token');
    expect(config.deviceAuthorizationHeaders).toBeUndefined();
  });
});
