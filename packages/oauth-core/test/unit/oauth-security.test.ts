import { createPublicKey, createSign, generateKeyPairSync, randomUUID } from 'node:crypto';
import { mkdir } from 'node:fs/promises';
import { dirname } from 'node:path';

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import { HttpOAuthClient, OAuthProtocolError } from '../../src/oauth-client.js';

const DEVICE_ENDPOINT = 'https://account.example.test/oauth2/device/code';
const TOKEN_ENDPOINT = 'https://account.example.test/oauth2/token';
const REVOCATION_ENDPOINT = 'https://account.example.test/oauth2/revoke';
const DISCOVERY_URL = 'https://account.example.test/.well-known/openid-configuration';
const JWKS_URI = 'https://account.example.test/.well-known/jwks.json';

interface IssuedToken {
  token: string;
  kid: string;
}

function base64url(input: string | Buffer): string {
  return Buffer.from(input).toString('base64url');
}

function signRs256(payload: Record<string, unknown>, privateKey: string, kid: string): IssuedToken {
  const header = { alg: 'RS256', typ: 'JWT', kid };
  const headerSegment = base64url(JSON.stringify(header));
  const payloadSegment = base64url(JSON.stringify(payload));
  const signer = createSign('RSA-SHA256');
  signer.update(`${headerSegment}.${payloadSegment}`);
  signer.end();
  const signature = signer.sign(privateKey).toString('base64url');
  return { token: `${headerSegment}.${payloadSegment}.${signature}`, kid };
}

function buildJwks(publicKeyPem: string, kid: string): { keys: unknown[] } {
  const jwk = createPublicKey(publicKeyPem).export({ format: 'jwk' });
  return { keys: [{ ...jwk, kid, alg: 'RS256', use: 'sig' }] };
}

function createTokenEndpointResponse(token: IssuedToken, state?: string) {
  return {
    access_token: token.token,
    refresh_token: 'refresh-secret',
    token_type: 'Bearer',
    scope: 'agent.default',
    expires_in: 3_600,
    ...(state ? { state } : {}),
  };
}

function createFetchMock(options: {
  discovery?: () => Response;
  jwks?: () => Response;
  token?: (body: URLSearchParams) => Response;
  device?: (body: URLSearchParams) => Response;
  revoke?: () => Response;
}): typeof fetch {
  return vi.fn(async (input, init) => {
    const url = typeof input === 'string' ? input : (input as URL).toString();
    const method = init?.method ?? 'GET';
    if (url === DISCOVERY_URL && method === 'GET') return options.discovery!();
    if (url === JWKS_URI && method === 'GET') return options.jwks!();
    if (url === DEVICE_ENDPOINT) return options.device!(new URLSearchParams(init?.body as string));
    if (url === TOKEN_ENDPOINT) return options.token!(new URLSearchParams(init?.body as string));
    if (url === REVOCATION_ENDPOINT) return options.revoke!();
    throw new Error(`Unmocked fetch: ${method} ${url}`);
  }) as unknown as typeof fetch;
}

describe('HttpOAuthClient device-flow nonce binding', () => {
  let now: () => number;
  const sleep = vi.fn(async () => undefined);

  beforeEach(() => {
    sleep.mockClear();
    now = () => 1_800_000_000_000;
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it('generates a fresh nonce on startDeviceAuthorization and echoes it on the token poll', async () => {
    const fetchMock = createFetchMock({
      device: () =>
        Response.json({
          user_code: 'ABCD-EFGH',
          device_code: 'device-secret',
          verification_uri: 'https://account.example.test/activate',
          expires_in: 300,
          interval: 1,
        }),
      token: (body) => {
        expect(body.get('state')).toMatch(/^[0-9a-f-]{36}$/u);
        return Response.json({
          access_token: 'opaque-access-token',
          refresh_token: 'refresh-secret',
          token_type: 'Bearer',
          scope: 'agent.default',
          expires_in: 3_600,
        });
      },
      revoke: () => new Response(null, { status: 200 }),
    });
    const client = new HttpOAuthClient({
      deviceAuthorizationEndpoint: DEVICE_ENDPOINT,
      tokenEndpoint: TOKEN_ENDPOINT,
      revocationEndpoint: REVOCATION_ENDPOINT,
      fetchImpl: fetchMock,
      sleep,
      now,
    });

    const authorization = await client.startDeviceAuthorization();
    expect(authorization.nonce).toMatch(/^[0-9a-f-]{36}$/u);
    const grant = await client.pollDeviceToken(authorization);
    expect(grant.nonce).toBe(authorization.nonce);
    expect(grant.accessToken).toBe('opaque-access-token');
  });

  it('refuses a grant whose response echoes a different device-flow nonce', async () => {
    const fetchMock = createFetchMock({
      device: () =>
        Response.json({
          user_code: 'ABCD-EFGH',
          device_code: 'device-secret',
          verification_uri: 'https://account.example.test/activate',
          expires_in: 300,
          interval: 1,
        }),
      token: () =>
        Response.json({
          access_token: 'opaque-access-token',
          refresh_token: 'refresh-secret',
          token_type: 'Bearer',
          scope: 'agent.default',
          expires_in: 3_600,
          state: 'attacker-supplied-nonce',
        }),
      revoke: () => new Response(null, { status: 200 }),
    });
    const client = new HttpOAuthClient({
      deviceAuthorizationEndpoint: DEVICE_ENDPOINT,
      tokenEndpoint: TOKEN_ENDPOINT,
      revocationEndpoint: REVOCATION_ENDPOINT,
      fetchImpl: fetchMock,
      sleep,
      now,
    });

    const authorization = await client.startDeviceAuthorization();
    await expect(client.pollDeviceToken(authorization)).rejects.toMatchObject({
      name: 'OAuthProtocolError',
      code: 'state_mismatch',
    });
  });

  it('accepts a grant whose response does not echo any nonce (server does not validate state)', async () => {
    let seenStateOnPoll: string | null = null;
    const fetchMock = createFetchMock({
      device: (body) => {
        expect(body.get('state')).toMatch(/^[0-9a-f-]{36}$/u);
        return Response.json({
          user_code: 'ABCD-EFGH',
          device_code: 'device-secret',
          verification_uri: 'https://account.example.test/activate',
          expires_in: 300,
          interval: 1,
        });
      },
      token: (body) => {
        seenStateOnPoll = body.get('state');
        return Response.json({
          access_token: 'opaque-access-token',
          refresh_token: 'refresh-secret',
          token_type: 'Bearer',
          scope: 'agent.default',
          expires_in: 3_600,
        });
      },
      revoke: () => new Response(null, { status: 200 }),
    });
    const client = new HttpOAuthClient({
      deviceAuthorizationEndpoint: DEVICE_ENDPOINT,
      tokenEndpoint: TOKEN_ENDPOINT,
      revocationEndpoint: REVOCATION_ENDPOINT,
      fetchImpl: fetchMock,
      sleep,
      now,
    });

    const authorization = await client.startDeviceAuthorization();
    const grant = await client.pollDeviceToken(authorization);
    expect(seenStateOnPoll).toBe(authorization.nonce);
    expect(grant.nonce).toBe(authorization.nonce);
  });

  it('treats a refresh response that unexpectedly echoes a nonce as a state mismatch', async () => {
    const fetchMock = createFetchMock({
      token: () =>
        Response.json({
          access_token: 'opaque-access-token',
          refresh_token: 'refresh-secret',
          token_type: 'Bearer',
          scope: 'agent.default',
          expires_in: 3_600,
          state: randomUUID(),
        }),
      revoke: () => new Response(null, { status: 200 }),
    });
    const client = new HttpOAuthClient({
      deviceAuthorizationEndpoint: DEVICE_ENDPOINT,
      tokenEndpoint: TOKEN_ENDPOINT,
      revocationEndpoint: REVOCATION_ENDPOINT,
      fetchImpl: fetchMock,
      sleep,
      now,
    });

    await expect(client.refreshToken('refresh-secret')).rejects.toMatchObject({
      name: 'OAuthProtocolError',
      code: 'state_mismatch',
    });
  });
});

describe('HttpOAuthClient JWT verification', () => {
  let keyPair: ReturnType<typeof generateKeyPairSync>;
  let keyPair2: ReturnType<typeof generateKeyPairSync>;
  let kid: string;

  beforeEach(() => {
    keyPair = generateKeyPairSync('rsa', { modulusLength: 2048 });
    keyPair2 = generateKeyPairSync('rsa', { modulusLength: 2048 });
    kid = 'test-key-1';
  });

  function buildClient(jwks: () => Response, discovery: () => Response): HttpOAuthClient {
    return new HttpOAuthClient({
      deviceAuthorizationEndpoint: DEVICE_ENDPOINT,
      tokenEndpoint: TOKEN_ENDPOINT,
      revocationEndpoint: REVOCATION_ENDPOINT,
      fetchImpl: createFetchMock({
        discovery,
        jwks,
        device: () =>
          Response.json({
            user_code: 'ABCD-EFGH',
            device_code: 'device-secret',
            verification_uri: 'https://account.example.test/activate',
            expires_in: 300,
            interval: 1,
          }),
        token: (body) => {
          const claims = {
            sub: 'user-42',
            account_id: 'acct-42',
            scope: 'agent.default',
            exp: Math.floor(Date.now() / 1_000) + 600,
          };
          const issued = signRs256(
            claims,
            keyPair.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
            kid,
          );
          return Response.json({
            ...createTokenEndpointResponse(issued, body.get('state') ?? undefined),
          });
        },
        revoke: () => new Response(null, { status: 200 }),
      }),
      sleep: async () => undefined,
      now: () => 1_800_000_000_000,
    });
  }

  it('exposes sub and account_id claims only after JWKS signature verification succeeds', async () => {
    const jwks = buildJwks(
      keyPair.publicKey.export({ format: 'pem', type: 'spki' }).toString(),
      kid,
    );
    const client = buildClient(
      () => Response.json(jwks),
      () => Response.json({ jwks_uri: JWKS_URI }),
    );
    const authorization = await client.startDeviceAuthorization();
    const grant = await client.pollDeviceToken(authorization);
    expect(grant.subject).toBe('user-42');
    expect(grant.accountId).toBe('acct-42');
  });

  it('drops sub and account_id when the access token is signed with a different key', async () => {
    const foreignKid = 'foreign-key';
    const header = { alg: 'RS256', typ: 'JWT', kid: foreignKid };
    const payload = {
      sub: 'attacker',
      account_id: 'acct-attacker',
      scope: 'agent.default',
      exp: Math.floor(Date.now() / 1_000) + 600,
    };
    const headerSegment = base64url(JSON.stringify(header));
    const payloadSegment = base64url(JSON.stringify(payload));
    const signer = createSign('RSA-SHA256');
    signer.update(`${headerSegment}.${payloadSegment}`);
    signer.end();
    const signature = signer
      .sign(keyPair2.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString())
      .toString('base64url');
    const tamperedToken = `${headerSegment}.${payloadSegment}.${signature}`;

    const jwks = buildJwks(
      keyPair.publicKey.export({ format: 'pem', type: 'spki' }).toString(),
      kid,
    );
    const fetchMock = createFetchMock({
      discovery: () => Response.json({ jwks_uri: JWKS_URI }),
      jwks: () => Response.json(jwks),
      device: () =>
        Response.json({
          user_code: 'ABCD-EFGH',
          device_code: 'device-secret',
          verification_uri: 'https://account.example.test/activate',
          expires_in: 300,
          interval: 1,
        }),
      token: (body) =>
        Response.json({
          ...createTokenEndpointResponse(
            { token: tamperedToken, kid: foreignKid },
            body.get('state') ?? undefined,
          ),
        }),
      revoke: () => new Response(null, { status: 200 }),
    });
    const client = new HttpOAuthClient({
      deviceAuthorizationEndpoint: DEVICE_ENDPOINT,
      tokenEndpoint: TOKEN_ENDPOINT,
      revocationEndpoint: REVOCATION_ENDPOINT,
      fetchImpl: fetchMock,
      sleep: async () => undefined,
      now: () => 1_800_000_000_000,
    });

    const authorization = await client.startDeviceAuthorization();
    const grant = await client.pollDeviceToken(authorization);
    expect(grant.accessToken).toBe(tamperedToken);
    expect(grant.subject).toBeUndefined();
    expect(grant.accountId).toBeUndefined();
  });

  it('drops sub and account_id when the JWT signature is tampered after signing', async () => {
    const claims = {
      sub: 'user-42',
      account_id: 'acct-42',
      scope: 'agent.default',
      exp: Math.floor(Date.now() / 1_000) + 600,
    };
    const issued = signRs256(
      claims,
      keyPair.privateKey.export({ format: 'pem', type: 'pkcs8' }).toString(),
      kid,
    );
    // Mutate the payload after signing so the signature no longer matches.
    const tamperedPayload = base64url(
      JSON.stringify({ ...claims, sub: 'attacker', account_id: 'acct-attacker' }),
    );
    const tamperedToken = issued.token.replace(/\.[^.]+\.[^.]+$/u, `.${tamperedPayload}.${issued.token.split('.')[2]}`);

    const jwks = buildJwks(
      keyPair.publicKey.export({ format: 'pem', type: 'spki' }).toString(),
      kid,
    );
    const fetchMock = createFetchMock({
      discovery: () => Response.json({ jwks_uri: JWKS_URI }),
      jwks: () => Response.json(jwks),
      device: () =>
        Response.json({
          user_code: 'ABCD-EFGH',
          device_code: 'device-secret',
          verification_uri: 'https://account.example.test/activate',
          expires_in: 300,
          interval: 1,
        }),
      token: (body) =>
        Response.json({
          ...createTokenEndpointResponse(
            { token: tamperedToken, kid },
            body.get('state') ?? undefined,
          ),
        }),
      revoke: () => new Response(null, { status: 200 }),
    });
    const client = new HttpOAuthClient({
      deviceAuthorizationEndpoint: DEVICE_ENDPOINT,
      tokenEndpoint: TOKEN_ENDPOINT,
      revocationEndpoint: REVOCATION_ENDPOINT,
      fetchImpl: fetchMock,
      sleep: async () => undefined,
      now: () => 1_800_000_000_000,
    });

    const authorization = await client.startDeviceAuthorization();
    const grant = await client.pollDeviceToken(authorization);
    expect(grant.subject).toBeUndefined();
    expect(grant.accountId).toBeUndefined();
  });

  it('does not call any auth endpoint when the access token is opaque', async () => {
    const discovery = vi.fn();
    const jwks = vi.fn();
    const fetchMock = createFetchMock({
      discovery: () => {
        discovery();
        return Response.json({ jwks_uri: JWKS_URI });
      },
      jwks: () => {
        jwks();
        return Response.json({ keys: [] });
      },
      device: () =>
        Response.json({
          user_code: 'ABCD-EFGH',
          device_code: 'device-secret',
          verification_uri: 'https://account.example.test/activate',
          expires_in: 300,
          interval: 1,
        }),
      token: (body) =>
        Response.json({
          access_token: 'opaque-not-a-jwt',
          refresh_token: 'refresh-secret',
          token_type: 'Bearer',
          scope: 'agent.default',
          expires_in: 3_600,
          state: body.get('state') ?? undefined,
        }),
      revoke: () => new Response(null, { status: 200 }),
    });
    const client = new HttpOAuthClient({
      deviceAuthorizationEndpoint: DEVICE_ENDPOINT,
      tokenEndpoint: TOKEN_ENDPOINT,
      revocationEndpoint: REVOCATION_ENDPOINT,
      fetchImpl: fetchMock,
      sleep: async () => undefined,
      now: () => 1_800_000_000_000,
    });
    const authorization = await client.startDeviceAuthorization();
    const grant = await client.pollDeviceToken(authorization);
    expect(grant.accessToken).toBe('opaque-not-a-jwt');
    expect(grant.subject).toBeUndefined();
    expect(grant.accountId).toBeUndefined();
    expect(discovery).not.toHaveBeenCalled();
    expect(jwks).not.toHaveBeenCalled();
  });

  it('refuses grants whose response carries a state_mismatch error code', async () => {
    const fetchMock = createFetchMock({
      device: () =>
        Response.json({
          user_code: 'ABCD-EFGH',
          device_code: 'device-secret',
          verification_uri: 'https://account.example.test/activate',
          expires_in: 300,
          interval: 1,
        }),
      token: () => Response.json({ error: 'invalid_grant' }, { status: 400 }),
      revoke: () => new Response(null, { status: 200 }),
    });
    const client = new HttpOAuthClient({
      deviceAuthorizationEndpoint: DEVICE_ENDPOINT,
      tokenEndpoint: TOKEN_ENDPOINT,
      revocationEndpoint: REVOCATION_ENDPOINT,
      fetchImpl: fetchMock,
      sleep: async () => undefined,
      now: () => 1_800_000_000_000,
    });
    const authorization = await client.startDeviceAuthorization();
    await expect(client.pollDeviceToken(authorization)).rejects.toBeInstanceOf(OAuthProtocolError);
  });
});

interface CoreFixture {
  dataDir: string;
  cleanup: () => Promise<void>;
  buildClient: (
    responses: {
      device?: () => Response;
      token?: (body: URLSearchParams) => Response;
      revoke?: () => Response;
    },
    overrides?: { sleep?: () => Promise<void>; now?: () => number },
  ) => { client: HttpOAuthClient; nonceOnPoll: string | null };
  nonceFromAuthorizationResponse: () => string | undefined;
}

async function buildCoreFixture(options: {
  fetchImpl?: typeof fetch;
  sleep?: () => Promise<void>;
  now?: () => number;
} = {}): Promise<CoreFixture> {
  const { mkdtemp, rm } = await import('node:fs/promises');
  const { tmpdir } = await import('node:os');
  const { join } = await import('node:path');
  const dataDir = await mkdtemp(join(tmpdir(), 'mcode-oauth-security-'));
  let nonceFromAuthorizationResponse: string | undefined;

  const buildClient: CoreFixture['buildClient'] = (responses, overrides = {}) => {
    let nonceOnPoll: string | null = null;
    const fetchImpl: typeof fetch = options.fetchImpl ?? (createFetchMock({
      device: (body) => {
        nonceFromAuthorizationResponse = body.get('state') ?? undefined;
        return (
          responses.device?.() ??
          Response.json({
            user_code: 'ABCD-EFGH',
            device_code: 'device-secret',
            verification_uri: 'https://account.example.test/activate',
            expires_in: 300,
            interval: 1,
          })
        );
      },
      token: (body) => {
        nonceOnPoll = body.get('state');
        return (
          responses.token?.(body) ??
          Response.json({
            access_token: 'opaque-access-token',
            refresh_token: 'refresh-secret',
            token_type: 'Bearer',
            scope: 'agent.default',
            expires_in: 3_600,
          })
        );
      },
      revoke: () => responses.revoke?.() ?? new Response(null, { status: 200 }),
    }) as typeof fetch);
    const client = new HttpOAuthClient({
      deviceAuthorizationEndpoint: DEVICE_ENDPOINT,
      tokenEndpoint: TOKEN_ENDPOINT,
      revocationEndpoint: REVOCATION_ENDPOINT,
      fetchImpl,
      sleep: overrides.sleep ?? options.sleep ?? (async () => undefined),
      now: overrides.now ?? options.now ?? (() => 1_800_000_000_000),
    });
    return { client, nonceOnPoll };
  };
  return {
    dataDir,
    cleanup: () => rm(dataDir, { recursive: true, force: true }),
    buildClient,
    nonceFromAuthorizationResponse: () => nonceFromAuthorizationResponse,
  };
}

describe('HttpOAuthClient nonce lifecycle integration', () => {
  it('round-trips the nonce end-to-end and exposes it on the grant', async () => {
    const fixture = await buildCoreFixture();
    try {
      const { client } = fixture.buildClient({});
      const authorization = await client.startDeviceAuthorization();
      expect(authorization.nonce).toMatch(/^[0-9a-f-]{36}$/u);
      expect(fixture.nonceFromAuthorizationResponse()).toBe(authorization.nonce);
      const grant = await client.pollDeviceToken(authorization);
      expect(grant.nonce).toBe(authorization.nonce);
      expect(grant.accessToken).toBe('opaque-access-token');
    } finally {
      await fixture.cleanup();
    }
  });
});

describe('MCodeOAuthCore nonce verification against the persisted lease', () => {
  it('rejects the login when the grant nonce diverges from the persisted lease nonce', async () => {
    const { writeFile } = await import('node:fs/promises');
    const { MCodeOAuthCore } = await import('../../src/auth-core.js');
    const { FileStore } = await import('../../src/credential-store/file-store.js');
    const { createAuthNamespace } = await import('../../src/namespace.js');
    const fixture = await buildCoreFixture();
    try {
      const namespace = createAuthNamespace({
        dataDir: fixture.dataDir,
        buildEnv: 'test',
        region: 'cn',
      });
      await mkdir(dirname(namespace.statePath), { recursive: true });
      await writeFile(
        namespace.statePath,
        JSON.stringify(
          {
            schemaVersion: 2,
            status: 'authorizing',
            storeKind: 'file',
            clientId: 'mcode-public',
            scopes: ['agent.default'],
            audience: 'agent-backend',
            buildEnv: 'test',
            region: 'cn',
            generation: 0,
            authorization: {
              leaseId: 'legacy-lease',
              leaseExpiresAtMs: Date.now() + 60_000,
              nonce: 'persisted-nonce',
            },
          },
          null,
          2,
        ),
      );
      const { client } = fixture.buildClient({});
      const staleAuthorization = {
        deviceCode: 'legacy-device',
        codeVerifier: 'legacy-verifier',
        userCode: 'ABCD-EFGH',
        verificationUri: 'https://account.example.test/activate',
        expiresInSec: 300,
        intervalSec: 1,
        nonce: 'grant-nonce',
      };
      const grant = await client.pollDeviceToken(staleAuthorization);
      const core = new MCodeOAuthCore({
        namespace,
        credentialStore: new FileStore({ authHome: namespace.namespaceHome }),
        oauthClient: client,
      });
      const commitLogin = (
        core as unknown as {
          commitLogin: (
            leaseId: string,
            grant: typeof grant,
            signal: AbortSignal,
          ) => Promise<unknown>;
        }
      ).commitLogin.bind(core);
      await expect(
        commitLogin('legacy-lease', grant, new AbortController().signal),
      ).rejects.toMatchObject({ code: 'state_mismatch' });
    } finally {
      await fixture.cleanup();
    }
  });

  it('accepts the login when the persisted lease carries no nonce (legacy migration)', async () => {
    const { writeFile, readFile } = await import('node:fs/promises');
    const { MCodeOAuthCore } = await import('../../src/auth-core.js');
    const { FileStore } = await import('../../src/credential-store/file-store.js');
    const { createAuthNamespace } = await import('../../src/namespace.js');
    const fixture = await buildCoreFixture();
    try {
      const namespace = createAuthNamespace({
        dataDir: fixture.dataDir,
        buildEnv: 'test',
        region: 'cn',
      });
      await mkdir(dirname(namespace.statePath), { recursive: true });
      await writeFile(
        namespace.statePath,
        JSON.stringify(
          {
            schemaVersion: 2,
            status: 'authorizing',
            storeKind: 'file',
            clientId: 'mcode-public',
            scopes: ['agent.default'],
            audience: 'agent-backend',
            buildEnv: 'test',
            region: 'cn',
            generation: 0,
            authorization: {
              leaseId: 'legacy-lease',
              leaseExpiresAtMs: Date.now() + 60_000,
              // No nonce — represents an in-flight login from before the upgrade.
            },
          },
          null,
          2,
        ),
      );
      const { client } = fixture.buildClient({});
      const core = new MCodeOAuthCore({
        namespace,
        credentialStore: new FileStore({ authHome: namespace.namespaceHome }),
        oauthClient: client,
      });
      const staleAuthorization = {
        deviceCode: 'legacy-device',
        codeVerifier: 'legacy-verifier',
        userCode: 'ABCD-EFGH',
        verificationUri: 'https://account.example.test/activate',
        expiresInSec: 300,
        intervalSec: 1,
        nonce: 'grant-nonce',
      };
      const grant = await client.pollDeviceToken(staleAuthorization);
      const commitLogin = (
        core as unknown as {
          commitLogin: (
            leaseId: string,
            grant: typeof grant,
            signal: AbortSignal,
          ) => Promise<{ status: string; generation: number }>;
        }
      ).commitLogin.bind(core);
      await expect(
        commitLogin('legacy-lease', grant, new AbortController().signal),
      ).resolves.toMatchObject({ status: 'authenticated' });
      const persistedState = JSON.parse(await readFile(namespace.statePath, 'utf8'));
      expect(persistedState.status).toBe('authenticated');
      expect(persistedState.expiresAtMs).toBeGreaterThan(Date.now());
    } finally {
      await fixture.cleanup();
    }
  });
});
