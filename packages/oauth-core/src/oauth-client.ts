import { createHash, randomBytes, randomUUID } from 'node:crypto';

import { MCODE_OAUTH_AUDIENCE, MCODE_OAUTH_CLIENT_ID, MCODE_OAUTH_SCOPES } from './contracts.js';
import { JwtVerifier } from './jwt-verifier.js';

const DEVICE_GRANT_TYPE = 'urn:ietf:params:oauth:grant-type:device_code';
const DEVICE_FLOW_STATE_PARAMETER = 'state';

export interface DeviceAuthorization {
  deviceCode: string;
  codeVerifier: string;
  tokenPollingParameter?: 'user_code';
  userCode: string;
  verificationUri: string;
  verificationUriComplete?: string;
  expiresInSec: number;
  intervalSec: number;
  /**
   * Random nonce generated at device-authorize time and bound to the local
   * device-code session. Re-emitted in the token poll request so the issuer
   * can echo it back; otherwise the client treats it as a server-validated
   * opaque identifier and refuses any grant whose response diverges from it.
   */
  nonce?: string;
}

export interface OAuthTokenGrant {
  accessToken: string;
  refreshToken: string;
  tokenType: 'Bearer';
  scopes: string[];
  audience: string;
  expiresInSec: number;
  subject?: string;
  accountId?: string;
  /** Verified device-flow nonce; present whenever the OAuth client produced it. */
  nonce?: string;
}

export interface OAuthClient {
  startDeviceAuthorization(options?: OAuthRequestOptions): Promise<DeviceAuthorization>;
  pollDeviceToken(
    authorization: DeviceAuthorization,
    options?: OAuthRequestOptions,
  ): Promise<OAuthTokenGrant>;
  refreshToken(refreshToken: string): Promise<OAuthTokenGrant>;
  revokeToken(refreshToken: string): Promise<void>;
}

export interface OAuthRequestOptions {
  signal?: AbortSignal;
}

export interface HttpOAuthClientOptions {
  deviceAuthorizationEndpoint: string;
  deviceAuthorizationHeaders?: Record<string, string>;
  tokenEndpoint: string;
  revocationEndpoint: string;
  fetchImpl?: typeof fetch;
  sleep?: (durationMs: number) => Promise<void>;
  now?: () => number;
  /**
   * Override the JWT verifier (mainly for tests and callers that already
   * maintain their own JWKS cache). The defaults discover the issuer JWKS
   * through OIDC metadata using the configured token endpoint.
   */
  jwtVerifierOverride?: {
    jwksUri?: string;
    now?: () => number;
    sleep?: (durationMs: number) => Promise<void>;
  };
}

export class OAuthProtocolError extends Error {
  constructor(
    readonly code: string,
    message?: string,
    readonly httpStatus?: number,
  ) {
    super(
      message ??
        `The OAuth server rejected the request (${code}${httpStatus ? `, HTTP ${httpStatus}` : ''}).`,
    );
    this.name = 'OAuthProtocolError';
  }
}

export class HttpOAuthClient implements OAuthClient {
  private readonly fetchImpl: typeof fetch;
  private readonly sleep: (durationMs: number) => Promise<void>;
  private readonly now: () => number;
  private readonly jwtVerifier: JwtVerifier;

  constructor(private readonly options: HttpOAuthClientOptions) {
    this.fetchImpl = options.fetchImpl ?? fetch;
    this.sleep =
      options.sleep ?? ((durationMs) => new Promise((resolve) => setTimeout(resolve, durationMs)));
    this.now = options.now ?? Date.now;
    this.jwtVerifier = new JwtVerifier({
      fetchImpl: this.fetchImpl,
      ...(options.jwtVerifierOverride ?? {}),
    });
  }

  async startDeviceAuthorization(options: OAuthRequestOptions = {}): Promise<DeviceAuthorization> {
    const codeVerifier = randomBytes(32).toString('base64url');
    const codeChallenge = createHash('sha256').update(codeVerifier, 'ascii').digest('base64url');
    const nonce = randomUUID();
    const body = await this.postForm(
      this.options.deviceAuthorizationEndpoint,
      {
        client_id: MCODE_OAUTH_CLIENT_ID,
        scope: MCODE_OAUTH_SCOPES.join(' '),
        audience: MCODE_OAUTH_AUDIENCE,
        code_challenge: codeChallenge,
        code_challenge_method: 'S256',
        [DEVICE_FLOW_STATE_PARAMETER]: nonce,
      },
      {
        headers: this.options.deviceAuthorizationHeaders,
        signal: options.signal,
      },
    );
    const userCode = readString(body, 'user_code');
    const standardDeviceCode = readString(body, 'device_code');
    const accountExpiredAtMs = readPositiveNumber(body, 'expired_in');
    const usesAccountUserCodePolling =
      !standardDeviceCode && Boolean(userCode) && accountExpiredAtMs !== undefined;
    const deviceCode = standardDeviceCode ?? (usesAccountUserCodePolling ? userCode : undefined);
    const verificationUri =
      readString(body, 'verification_uri') ?? readString(body, 'verification_url');
    const expiresInSec =
      readPositiveNumber(body, 'expires_in') ??
      normalizeAccountExpirySeconds(accountExpiredAtMs, this.now());
    const rawInterval = readPositiveNumber(body, 'interval');
    const intervalSec =
      usesAccountUserCodePolling && rawInterval !== undefined
        ? rawInterval / 1_000
        : (rawInterval ?? 5);
    if (!deviceCode || !userCode || !verificationUri || !expiresInSec) {
      throw new OAuthProtocolError('invalid_device_authorization_response');
    }
    return {
      deviceCode,
      codeVerifier,
      nonce,
      ...(usesAccountUserCodePolling ? { tokenPollingParameter: 'user_code' as const } : {}),
      userCode,
      verificationUri,
      ...(readString(body, 'verification_uri_complete') || usesAccountUserCodePolling
        ? {
            verificationUriComplete:
              readString(body, 'verification_uri_complete') ?? verificationUri,
          }
        : {}),
      expiresInSec,
      intervalSec,
    };
  }

  async pollDeviceToken(
    authorization: DeviceAuthorization,
    options: OAuthRequestOptions = {},
  ): Promise<OAuthTokenGrant> {
    const deadline = this.now() + authorization.expiresInSec * 1_000;
    let intervalMs = authorization.intervalSec * 1_000;
    while (this.now() < deadline) {
      options.signal?.throwIfAborted();
      const pollingCode: Record<string, string> =
        authorization.tokenPollingParameter === 'user_code'
          ? { user_code: authorization.userCode }
          : { device_code: authorization.deviceCode };
      const formValues: Record<string, string> = {
        grant_type: DEVICE_GRANT_TYPE,
        ...pollingCode,
        client_id: MCODE_OAUTH_CLIENT_ID,
        code_verifier: authorization.codeVerifier,
      };
      if (authorization.nonce) {
        formValues[DEVICE_FLOW_STATE_PARAMETER] = authorization.nonce;
      }
      const response = await this.postFormAllowOAuthError(
        this.options.tokenEndpoint,
        formValues,
        { signal: options.signal },
      );
      const pollingStatus = readString(response.body, 'status');
      if (response.ok && pollingStatus === 'pending') {
        await sleepWithSignal(this.sleep, intervalMs, options.signal);
        continue;
      }
      if (response.ok && pollingStatus === 'slow_down') {
        intervalMs += 5_000;
        await sleepWithSignal(this.sleep, intervalMs, options.signal);
        continue;
      }
      if (response.ok && (pollingStatus === 'denied' || pollingStatus === 'access_denied')) {
        throw new OAuthProtocolError('access_denied');
      }
      if (response.ok && (pollingStatus === 'expired' || pollingStatus === 'expired_token')) {
        throw new OAuthProtocolError('expired_token');
      }
      if (response.ok) return parseTokenGrant(response.body, undefined, this.jwtVerifier, {
        expectedNonce: authorization.nonce,
        tokenEndpoint: this.options.tokenEndpoint,
      });
      if (response.error === 'authorization_pending') {
        await sleepWithSignal(this.sleep, intervalMs, options.signal);
        continue;
      }
      if (response.error === 'slow_down') {
        intervalMs += 5_000;
        await sleepWithSignal(this.sleep, intervalMs, options.signal);
        continue;
      }
      throw new OAuthProtocolError(
        response.error ?? 'device_authorization_failed',
        undefined,
        response.status,
      );
    }
    throw new OAuthProtocolError('expired_token', 'The OAuth device authorization expired.');
  }

  async refreshToken(refreshToken: string): Promise<OAuthTokenGrant> {
    const body = await this.postForm(this.options.tokenEndpoint, {
      grant_type: 'refresh_token',
      refresh_token: refreshToken,
      client_id: MCODE_OAUTH_CLIENT_ID,
      scope: MCODE_OAUTH_SCOPES.join(' '),
      audience: MCODE_OAUTH_AUDIENCE,
    });
    return parseTokenGrant(body, refreshToken, this.jwtVerifier, {
      tokenEndpoint: this.options.tokenEndpoint,
    });
  }

  async revokeToken(refreshToken: string): Promise<void> {
    const response = await this.postFormAllowOAuthError(
      this.options.revocationEndpoint,
      {
        token: refreshToken,
        token_type_hint: 'refresh_token',
        client_id: MCODE_OAUTH_CLIENT_ID,
      },
      { allowEmptySuccess: true },
    );
    if (!response.ok)
      throw new OAuthProtocolError(
        response.error ?? 'oauth_request_failed',
        undefined,
        response.status,
      );
  }

  private async postForm(
    endpoint: string,
    values: Record<string, string>,
    options: OAuthHttpRequestOptions = {},
  ): Promise<Record<string, unknown>> {
    const response = await this.postFormAllowOAuthError(endpoint, values, options);
    if (!response.ok)
      throw new OAuthProtocolError(
        response.error ?? 'oauth_request_failed',
        undefined,
        response.status,
      );
    return response.body;
  }

  private async postFormAllowOAuthError(
    endpoint: string,
    values: Record<string, string>,
    options: OAuthHttpRequestOptions = {},
  ): Promise<{ ok: boolean; status: number; body: Record<string, unknown>; error?: string }> {
    const response = await this.fetchImpl(endpoint, {
      method: 'POST',
      headers: {
        Accept: 'application/json',
        'Content-Type': 'application/x-www-form-urlencoded',
        ...options.headers,
      },
      body: new URLSearchParams(values),
      signal: options.signal,
    });
    const body = asRecord(await response.json().catch(() => undefined));
    if (!body && response.ok && options.allowEmptySuccess)
      return { ok: true, status: response.status, body: {} };
    if (!body) throw new OAuthProtocolError('invalid_json_response', undefined, response.status);
    const error = readString(body, 'error');
    return {
      ok: response.ok && !error,
      status: response.status,
      body,
      ...(error ? { error } : {}),
    };
  }
}

interface OAuthHttpRequestOptions extends OAuthRequestOptions {
  headers?: Record<string, string>;
  allowEmptySuccess?: boolean;
}

async function sleepWithSignal(
  sleep: (durationMs: number) => Promise<void>,
  durationMs: number,
  signal: AbortSignal | undefined,
): Promise<void> {
  if (!signal) {
    await sleep(durationMs);
    return;
  }
  signal.throwIfAborted();
  let rejectAbort!: (reason?: unknown) => void;
  const onAbort = () => rejectAbort(signal.reason);
  const aborted = new Promise<never>((_resolve, reject) => {
    rejectAbort = reject;
  });
  signal.addEventListener('abort', onAbort, { once: true });
  try {
    await Promise.race([sleep(durationMs), aborted]);
  } finally {
    signal.removeEventListener('abort', onAbort);
  }
}

async function parseTokenGrant(
  body: Record<string, unknown>,
  previousRefreshToken: string | undefined,
  jwtVerifier: JwtVerifier,
  context: ParseTokenGrantContext,
): Promise<OAuthTokenGrant> {
  const accessToken = readString(body, 'access_token');
  const refreshToken = readString(body, 'refresh_token') ?? previousRefreshToken;
  const tokenType = readString(body, 'token_type');
  const expiresInSec = readPositiveNumber(body, 'expires_in');
  const responseState = readString(body, DEVICE_FLOW_STATE_PARAMETER);
  const claims = accessToken
    ? await jwtVerifier.verifyAndDecode(accessToken, context.tokenEndpoint)
    : undefined;
  const scopes = parseScopes(body.scope ?? claims?.scope ?? claims?.scp);
  if (
    !accessToken ||
    !refreshToken ||
    tokenType?.toLowerCase() !== 'bearer' ||
    !expiresInSec ||
    !scopes.includes(MCODE_OAUTH_SCOPES[0])
  ) {
    throw new OAuthProtocolError('invalid_token_response');
  }
  if (context.expectedNonce !== undefined) {
    if (responseState !== undefined && responseState !== context.expectedNonce) {
      throw new OAuthProtocolError(
        'state_mismatch',
        'The OAuth token response echoed a different device-flow nonce.',
      );
    }
  } else if (responseState !== undefined) {
    throw new OAuthProtocolError(
      'state_mismatch',
      'The OAuth token response included an unexpected device-flow nonce.',
    );
  }
  return {
    accessToken,
    refreshToken,
    tokenType: 'Bearer',
    scopes,
    audience: MCODE_OAUTH_AUDIENCE,
    expiresInSec,
    ...(context.expectedNonce !== undefined ? { nonce: context.expectedNonce } : {}),
    ...(readString(claims, 'sub') ? { subject: readString(claims, 'sub') } : {}),
    ...(readString(claims, 'account_id') ? { accountId: readString(claims, 'account_id') } : {}),
  };
}

interface ParseTokenGrantContext {
  expectedNonce?: string;
  tokenEndpoint: string;
}

function parseScopes(value: unknown): string[] {
  if (typeof value === 'string') return value.split(/\s+/u).filter(Boolean);
  if (Array.isArray(value) && value.every((scope) => typeof scope === 'string')) return value;
  return [];
}

function asRecord(value: unknown): Record<string, unknown> | undefined {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function readString(value: unknown, key: string): string | undefined {
  const record = asRecord(value);
  const candidate = record?.[key];
  return typeof candidate === 'string' && candidate.trim() ? candidate.trim() : undefined;
}

function readPositiveNumber(value: unknown, key: string): number | undefined {
  const record = asRecord(value);
  const candidate = record?.[key];
  return typeof candidate === 'number' && Number.isFinite(candidate) && candidate > 0
    ? candidate
    : undefined;
}

function normalizeAccountExpirySeconds(
  expiredIn: number | undefined,
  nowMs: number,
): number | undefined {
  if (expiredIn === undefined) return undefined;
  if (expiredIn < 1_000_000_000_000) return expiredIn;
  const remainingMs = expiredIn - nowMs;
  return remainingMs > 0 ? Math.ceil(remainingMs / 1_000) : undefined;
}
