/**
 * Bearer-fallback hardening for the content-safety HTTP boundary.
 *
 * The v1 / v2 safety clients used to read `MAVIS_ACCESS_TOKEN` from the
 * environment whenever the caller's auth context had no token, which turned
 * any env-setting caller into an authenticated managed client. The fix:
 *
 *   - v2 drops the env-var fallback entirely; the access token must come
 *     from `authContext`.
 *   - v1 keeps the env-var fallback for managed desktop sessions but
 *     requires `__MAVIS_RUNTIME_MANAGED=1` AND a managed-host allowlist
 *     (`agent.minimax.cn` / `agent.minimax.io`) so a staging / test
 *     resolve never receives a Bearer header from the env.
 *
 * The `reviewBlocks` predicate still owns the fail-policy classification,
 * so the assertions here only check the outbound HTTP headers.
 */
import { afterEach, describe, expect, it, vi } from 'vitest';

import { callLocalSafetyCheckV2 } from '../../src/content-safety/api-v2.js';
import {
  callSafetyApi,
  createContentSafetyChecker,
  SAFETY_SCENE,
} from '../../src/content-safety/api.js';

const cnTestRegion = () => 'cn' as const;
const testBuildEnv = () => 'test' as const;

afterEach(() => {
  vi.unstubAllEnvs();
  vi.restoreAllMocks();
});

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function captureHeaders(fetchImpl: ReturnType<typeof vi.fn<typeof fetch>>): Headers {
  const init = fetchImpl.mock.calls[0]?.[1] as RequestInit;
  return new Headers(init.headers);
}

describe('v1 callSafetyApi Bearer-fallback hardening', () => {
  it('omits the Authorization header when no token and no managed marker is set', async () => {
    vi.stubEnv('MAVIS_ACCESS_TOKEN', 'env-only-token');
    vi.stubEnv('__MAVIS_RUNTIME_MANAGED', '');
    const fetchImpl = vi.fn(async () => jsonResponse({ pass: true }));

    await callSafetyApi({
      content: 'hello',
      scene: SAFETY_SCENE.UserInput,
      fetchImpl,
      region: cnTestRegion,
      buildEnv: testBuildEnv,
    });

    expect(captureHeaders(fetchImpl).has('Authorization')).toBe(false);
  });

  it('omits the Authorization header when the managed marker is set but the origin is a stage/test host', async () => {
    vi.stubEnv('MAVIS_ACCESS_TOKEN', 'env-only-token');
    vi.stubEnv('__MAVIS_RUNTIME_MANAGED', '1');
    const fetchImpl = vi.fn(async () => jsonResponse({ pass: true }));

    // `test` buildEnv + cn region resolves to https://matrix-test.example.invalid,
    // which is intentionally NOT on the managed allowlist.
    await callSafetyApi({
      content: 'hello',
      scene: SAFETY_SCENE.UserInput,
      fetchImpl,
      region: cnTestRegion,
      buildEnv: testBuildEnv,
    });

    expect(captureHeaders(fetchImpl).has('Authorization')).toBe(false);
  });

  it('sends the env-var token only when the managed marker is set AND the origin is a managed host', async () => {
    vi.stubEnv('MAVIS_ACCESS_TOKEN', 'env-managed-token');
    vi.stubEnv('__MAVIS_RUNTIME_MANAGED', '1');
    const fetchImpl = vi.fn(async () => jsonResponse({ pass: true }));

    await callSafetyApi({
      content: 'hello',
      scene: SAFETY_SCENE.UserInput,
      fetchImpl,
      region: cnTestRegion,
      buildEnv: () => 'prod',
    });

    expect(captureHeaders(fetchImpl).get('Authorization')).toBe('Bearer env-managed-token');
  });

  it('prefers the authContext token over the env-var token in a managed runtime', async () => {
    vi.stubEnv('MAVIS_ACCESS_TOKEN', 'env-managed-token');
    vi.stubEnv('__MAVIS_RUNTIME_MANAGED', '1');
    const fetchImpl = vi.fn(async () => jsonResponse({ pass: true }));

    await callSafetyApi({
      content: 'hello',
      scene: SAFETY_SCENE.UserInput,
      authContext: { accessToken: 'oauth-token' },
      fetchImpl,
      region: cnTestRegion,
      buildEnv: () => 'prod',
    });

    expect(captureHeaders(fetchImpl).get('Authorization')).toBe('Bearer oauth-token');
  });

  it('never sends the env-var token to a staging host even with the managed marker', async () => {
    vi.stubEnv('MAVIS_ACCESS_TOKEN', 'env-managed-token');
    vi.stubEnv('__MAVIS_RUNTIME_MANAGED', '1');
    const fetchImpl = vi.fn(async () => jsonResponse({ pass: true }));

    await callSafetyApi({
      content: 'hello',
      scene: SAFETY_SCENE.UserInput,
      fetchImpl,
      region: cnTestRegion,
      buildEnv: () => 'staging',
    });

    // The staging host is *not* on the managed allowlist, so a managed
    // desktop must not be able to send an env-var token to it.
    expect(captureHeaders(fetchImpl).has('Authorization')).toBe(false);
  });

  it('lets the auth-invalidator mirror the same managed-only fallback', async () => {
    vi.stubEnv('MAVIS_ACCESS_TOKEN', 'env-managed-token');
    vi.stubEnv('__MAVIS_RUNTIME_MANAGED', '1');
    let accessToken: string | undefined;
    const fetchImpl = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(new Response('{}', { status: 401 }))
      .mockResolvedValueOnce(jsonResponse({ pass: true }));
    const authContextInvalidator = vi.fn(async () => {
      accessToken = 'fresh-oauth-token';
    });
    const check = createContentSafetyChecker({
      authContextGetter: () => (accessToken ? { accessToken } : undefined),
      authContextInvalidator,
      fetchImpl,
      region: cnTestRegion,
      buildEnv: () => 'prod',
    });

    expect(await check('hello', SAFETY_SCENE.UserInput)).toMatchObject({ pass: true });
    // The rejected token sent to the gateway on the first attempt is the
    // env-managed-token (managed + prod origin). The invalidator sees that
    // exact value, and the second attempt ships the fresh oauth token.
    expect(authContextInvalidator).toHaveBeenCalledWith('env-managed-token');
    const retryHeaders = new Headers(fetchImpl.mock.calls[1]?.[1]?.headers);
    expect(retryHeaders.get('Authorization')).toBe('Bearer fresh-oauth-token');
  });
});

describe('v2 callLocalSafetyCheckV2 Bearer-fallback hardening', () => {
  it('never reads MAVIS_ACCESS_TOKEN from the environment', async () => {
    vi.stubEnv('MAVIS_ACCESS_TOKEN', 'env-only-token');
    const fetchImpl = vi.fn(async () => jsonResponse({ action: 1 }));

    await callLocalSafetyCheckV2({
      request: { content_text: 'hello', scene: 100 },
      fetchImpl,
      region: cnTestRegion,
      buildEnv: () => 'prod',
    });

    // v2 must require an explicit authContext credential; the env-var
    // fallback is removed entirely so a v2 caller cannot become an
    // authenticated managed client by setting a process env.
    expect(captureHeaders(fetchImpl).has('Authorization')).toBe(false);
  });

  it('still sends the authContext token to the v2 endpoint', async () => {
    const fetchImpl = vi.fn(async () => jsonResponse({ action: 1 }));

    await callLocalSafetyCheckV2({
      request: { content_text: 'hello', scene: 100 },
      authContext: { accessToken: ' oauth-token ' },
      fetchImpl,
      region: cnTestRegion,
      buildEnv: () => 'prod',
    });

    expect(captureHeaders(fetchImpl).get('Authorization')).toBe('Bearer oauth-token');
  });

  it('ignores MAVIS_ACCESS_TOKEN even when the managed marker is set', async () => {
    vi.stubEnv('MAVIS_ACCESS_TOKEN', 'env-managed-token');
    vi.stubEnv('__MAVIS_RUNTIME_MANAGED', '1');
    const fetchImpl = vi.fn(async () => jsonResponse({ action: 1 }));

    await callLocalSafetyCheckV2({
      request: { content_text: 'hello', scene: 100 },
      fetchImpl,
      region: cnTestRegion,
      buildEnv: () => 'prod',
    });

    expect(captureHeaders(fetchImpl).has('Authorization')).toBe(false);
  });
});
