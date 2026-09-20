import type { AuthBuildEnv, AuthRegion } from './contracts.js';

export type MCodeOAuthEndpointEnvironment = Partial<
  Record<
    | 'MCODE_OAUTH_DEVICE_AUTHORIZATION_ENDPOINT'
    | 'MCODE_OAUTH_TOKEN_ENDPOINT'
    | 'MCODE_OAUTH_REVOCATION_ENDPOINT',
    string
  >
>;

export interface MCodeOAuthEndpointConfig {
  deviceAuthorizationEndpoint: string;
  deviceAuthorizationHeaders?: Record<string, string>;
  tokenEndpoint: string;
  revocationEndpoint: string;
}

export interface MCodeOAuthEndpointContext {
  buildEnv: AuthBuildEnv;
  region: AuthRegion;
}

const ACCOUNT_ORIGINS: Record<AuthRegion, Record<AuthBuildEnv, string>> = {
  cn: {
    dev: 'https://account-test.example.invalid',
    test: 'https://account-test.example.invalid',
    staging: 'https://account-pre.example.invalid',
    prod: 'https://account.minimax.cn',
  },
  en: {
    dev: 'https://account-overseas-test.example.invalid',
    test: 'https://account-overseas-test.example.invalid',
    staging: 'https://account-overseas-pre.example.invalid',
    prod: 'https://account.minimax.io',
  },
};

export function resolveMCodeOAuthEndpointConfig(
  environment: MCodeOAuthEndpointEnvironment,
  context: MCodeOAuthEndpointContext,
): MCodeOAuthEndpointConfig {
  const configuredValues = [
    environment.MCODE_OAUTH_DEVICE_AUTHORIZATION_ENDPOINT,
    environment.MCODE_OAUTH_TOKEN_ENDPOINT,
    environment.MCODE_OAUTH_REVOCATION_ENDPOINT,
  ];
  if (configuredValues.every((value) => !value?.trim())) {
    assertBuildEnvAuthorised(context.buildEnv);
    const accountOrigin = ACCOUNT_ORIGINS[context.region][context.buildEnv];
    return {
      deviceAuthorizationEndpoint: `${accountOrigin}/oauth2/device/code`,
      ...deviceAuthorizationRequestConfig(context.buildEnv),
      tokenEndpoint: `${accountOrigin}/oauth2/token`,
      revocationEndpoint: `${accountOrigin}/oauth2/revoke`,
    };
  }

  const deviceAuthorizationEndpoint = readHttpsEndpoint(
    environment.MCODE_OAUTH_DEVICE_AUTHORIZATION_ENDPOINT,
  );
  const tokenEndpoint = readHttpsEndpoint(environment.MCODE_OAUTH_TOKEN_ENDPOINT);
  const revocationEndpoint = readHttpsEndpoint(environment.MCODE_OAUTH_REVOCATION_ENDPOINT);
  if (!deviceAuthorizationEndpoint || !tokenEndpoint || !revocationEndpoint) {
    throw new TypeError(
      'Shared MCode OAuth requires all three public OAuth endpoints to be configured.',
    );
  }
  // Even when endpoints are explicit, the staging build-env still demands the
  // pre-release header — refuse the request when the caller asked for an
  // unauthorised environment so an attacker cannot bypass the gate by
  // supplying custom endpoints while keeping `buildEnv=staging` semantics.
  assertBuildEnvAuthorised(context.buildEnv);
  return {
    deviceAuthorizationEndpoint,
    ...deviceAuthorizationRequestConfig(context.buildEnv),
    tokenEndpoint,
    revocationEndpoint,
  };
}

/**
 * Refuse dev/test builds unless the host has explicitly opted in via
 * `MAVIS_DEV_OAUTH_OK=1`. Without this gate, a developer who runs a build
 * with an unset `MAVIS_BUILD_ENV` (which falls through to `dev`) silently
 * gets OAuth endpoints that resolve to `*.example.invalid` and never warns;
 * the same fallback is what an attacker would piggy-back on to mint staging
 * credentials by setting `MAVIS_REGION=en` while leaving the rest of the
 * environment pointing at staging.
 */
function assertBuildEnvAuthorised(buildEnv: AuthBuildEnv): void {
  if (buildEnv === 'prod' || buildEnv === 'staging') return;
  if (process.env.MAVIS_DEV_OAUTH_OK === '1') return;
  throw new TypeError(
    `Refusing to construct the Shared MCode OAuth client for buildEnv='${buildEnv}'. ` +
      `Dev/test builds must set MAVIS_DEV_OAUTH_OK=1 to opt in.`,
  );
}

function deviceAuthorizationRequestConfig(
  buildEnv: AuthBuildEnv,
): Pick<MCodeOAuthEndpointConfig, 'deviceAuthorizationHeaders'> {
  return buildEnv === 'staging' ? { deviceAuthorizationHeaders: { 'X-User-Pre': '1' } } : {};
}

function readHttpsEndpoint(value: string | undefined): string | undefined {
  if (!value?.trim()) return undefined;
  try {
    const url = new URL(value);
    if (url.protocol !== 'https:' || url.username || url.password || url.hash) return undefined;
    return url.toString();
  } catch {
    return undefined;
  }
}
