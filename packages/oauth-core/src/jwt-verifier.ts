import { createPublicKey, verify } from 'node:crypto';

const DEFAULT_JWKS_TTL_MS = 10 * 60 * 1_000;
const DEFAULT_DISCOVERY_TTL_MS = 60 * 60 * 1_000;
const SUPPORTED_JWS_ALGORITHMS = new Set([
  'RS256',
  'RS384',
  'RS512',
  'PS256',
  'PS384',
  'PS512',
  'ES256',
  'ES384',
  'ES512',
  'EdDSA',
]);

export interface JwtVerifierOptions {
  fetchImpl: typeof fetch;
  signal?: AbortSignal;
  /** Pre-configured JWKS URI; skips OIDC discovery when set. */
  jwksUri?: string;
  /** TTL for the JWKS document cache in ms. */
  jwksTtlMs?: number;
  /** TTL for the OIDC discovery document cache in ms. */
  discoveryTtlMs?: number;
  now?: () => number;
  /** Sleep helper for tests; defaults to setTimeout. */
  sleep?: (durationMs: number) => Promise<void>;
}

interface Jwk {
  kid?: string;
  kty: string;
  alg?: string;
  [parameter: string]: unknown;
}

interface JwksDocument {
  keys: Jwk[];
}

interface CachedDocument<T> {
  value: T;
  fetchedAt: number;
}

/**
 * Verify the signature of JWT-shaped access tokens issued by the configured
 * OAuth provider by fetching the issuer JWKS (via OIDC discovery when needed).
 *
 * If the verifier cannot reach the JWKS endpoint, `verify` resolves with
 * `undefined` so the caller can treat the JWT claims as untrusted.
 */
export class JwtVerifier {
  private readonly fetchImpl: typeof fetch;
  private readonly signal: AbortSignal | undefined;
  private readonly jwksUri: string | undefined;
  private readonly jwksTtlMs: number;
  private readonly discoveryTtlMs: number;
  private readonly now: () => number;
  private readonly sleep: (durationMs: number) => Promise<void>;
  private readonly jwksByIssuer = new Map<string, CachedDocument<JwksDocument>>();
  private readonly discoveryByIssuer = new Map<string, CachedDocument<{ jwks_uri?: string }>>();
  private readonly inFlightJwks = new Map<string, Promise<JwksDocument | undefined>>();
  private readonly inFlightDiscovery = new Map<string, Promise<{ jwks_uri?: string } | undefined>>();

  constructor(options: JwtVerifierOptions) {
    this.fetchImpl = options.fetchImpl;
    this.signal = options.signal;
    this.jwksUri = options.jwksUri;
    this.jwksTtlMs = options.jwksTtlMs ?? DEFAULT_JWKS_TTL_MS;
    this.discoveryTtlMs = options.discoveryTtlMs ?? DEFAULT_DISCOVERY_TTL_MS;
    this.now = options.now ?? Date.now;
    this.sleep =
      options.sleep ?? ((durationMs) => new Promise((resolve) => setTimeout(resolve, durationMs)));
  }

  /**
   * Verify the JWT signature and return the decoded payload claims.
   *
   * Returns `undefined` when the token is not a JWT, the signature cannot be
   * verified, or no JWKS is available. The caller must treat the absence of
   * claims as a signal to drop identity fields derived from the JWT.
   */
  async verifyAndDecode(token: string, tokenEndpoint: string): Promise<JwtClaims | undefined> {
    const segments = token.split('.');
    if (segments.length !== 3) return undefined;
    const [headerSegment, payloadSegment, signatureSegment] = segments;
    if (!headerSegment || !payloadSegment || !signatureSegment) return undefined;

    let header: JwtHeader;
    try {
      header = JSON.parse(Buffer.from(headerSegment, 'base64url').toString('utf8')) as JwtHeader;
    } catch {
      return undefined;
    }
    if (!SUPPORTED_JWS_ALGORITHMS.has(header.alg)) return undefined;

    const issuer = extractIssuer(tokenEndpoint);
    if (!issuer) return undefined;
    const jwks = await this.resolveJwks(issuer);
    if (!jwks) return undefined;

    const matchingKey = selectKey(jwks.keys, header.kid, header.alg);
    if (!matchingKey) return undefined;

    let publicKey;
    try {
      publicKey = createPublicKey({ key: matchingKey as never, format: 'jwk' });
    } catch {
      return undefined;
    }

    const signature = Buffer.from(signatureSegment, 'base64url');
    const signedData = Buffer.from(`${headerSegment}.${payloadSegment}`, 'ascii');
    let verified = false;
    try {
      verified = verify(null, signedData, publicKey, signature);
    } catch {
      return undefined;
    }
    if (!verified) return undefined;

    try {
      const parsed = JSON.parse(Buffer.from(payloadSegment, 'base64url').toString('utf8')) as unknown;
      return isRecord(parsed) ? parsed : undefined;
    } catch {
      return undefined;
    }
  }

  private async resolveJwks(issuer: string): Promise<JwksDocument | undefined> {
    const cached = this.jwksByIssuer.get(issuer);
    if (cached && this.now() - cached.fetchedAt < this.jwksTtlMs) return cached.value;

    const jwksUri = await this.resolveJwksUri(issuer);
    if (!jwksUri) return undefined;

    const existing = this.inFlightJwks.get(jwksUri);
    if (existing) return existing;

    const load = this.fetchJwks(jwksUri)
      .then((document) => {
        if (document) this.jwksByIssuer.set(issuer, { value: document, fetchedAt: this.now() });
        return document;
      })
      .finally(() => {
        this.inFlightJwks.delete(jwksUri);
      });
    this.inFlightJwks.set(jwksUri, load);
    return load;
  }

  private async resolveJwksUri(issuer: string): Promise<string | undefined> {
    if (this.jwksUri) return this.jwksUri;

    const cached = this.discoveryByIssuer.get(issuer);
    if (cached && this.now() - cached.fetchedAt < this.discoveryTtlMs) {
      return cached.value.jwks_uri;
    }

    const existing = this.inFlightDiscovery.get(issuer);
    if (existing) {
      const result = await existing;
      return result?.jwks_uri;
    }

    const discoveryUrl = `${issuer}/.well-known/openid-configuration`;
    const load = this.fetchDiscovery(discoveryUrl)
      .then((document) => {
        if (document)
          this.discoveryByIssuer.set(issuer, { value: document, fetchedAt: this.now() });
        return document;
      })
      .finally(() => {
        this.inFlightDiscovery.delete(issuer);
      });
    this.inFlightDiscovery.set(issuer, load);
    const result = await load;
    return result?.jwks_uri;
  }

  private async fetchDiscovery(url: string): Promise<{ jwks_uri?: string } | undefined> {
    try {
      const response = await this.fetchImpl(url, {
        headers: { Accept: 'application/json' },
        signal: this.signal,
      });
      if (!response.ok) return undefined;
      const parsed = (await response.json().catch(() => undefined)) as unknown;
      if (!isRecord(parsed)) return undefined;
      const jwksUri = parsed['jwks_uri'];
      return typeof jwksUri === 'string' && jwksUri ? { jwks_uri: jwksUri } : undefined;
    } catch {
      return undefined;
    }
  }

  private async fetchJwks(url: string): Promise<JwksDocument | undefined> {
    try {
      const response = await this.fetchImpl(url, {
        headers: { Accept: 'application/json' },
        signal: this.signal,
      });
      if (!response.ok) return undefined;
      const parsed = (await response.json().catch(() => undefined)) as unknown;
      if (!isRecord(parsed) || !Array.isArray(parsed['keys'])) return undefined;
      const keys = parsed['keys'].filter(isJwk);
      return { keys };
    } catch {
      return undefined;
    }
  }
}

interface JwtHeader {
  alg: string;
  kid?: string;
  typ?: string;
}

export type JwtClaims = Record<string, unknown>;

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isJwk(value: unknown): value is Jwk {
  return isRecord(value) && typeof value['kty'] === 'string';
}

function selectKey(keys: Jwk[], kid: string | undefined, alg: string): Jwk | undefined {
  for (const key of keys) {
    if (kid && key.kid !== kid) continue;
    if (key.alg && key.alg !== alg) continue;
    if (!isAsymmetricSigningKey(key)) continue;
    return key;
  }
  return undefined;
}

function isAsymmetricSigningKey(key: Jwk): boolean {
  if (key.kty === 'RSA') {
    return typeof key['n'] === 'string' && typeof key['e'] === 'string';
  }
  if (key.kty === 'EC') {
    return (
      typeof key['crv'] === 'string' &&
      typeof key['x'] === 'string' &&
      typeof key['y'] === 'string'
    );
  }
  if (key.kty === 'OKP') {
    return typeof key['crv'] === 'string' && typeof key['x'] === 'string';
  }
  return false;
}

function extractIssuer(tokenEndpoint: string): string | undefined {
  try {
    const url = new URL(tokenEndpoint);
    if (url.protocol !== 'https:' && url.protocol !== 'http:') return undefined;
    return `${url.protocol}//${url.host}`;
  } catch {
    return undefined;
  }
}
