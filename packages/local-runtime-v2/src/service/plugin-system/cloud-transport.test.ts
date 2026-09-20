import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it, vi } from 'vitest';

import { PluginSystemCloudTransport, PluginSystemCloudTransportError } from './cloud-transport.js';
import { writeFileChunkFully } from './file-chunk-writer.js';

// The transport is shared by the Plugin registry and Connector app clients.
const roots: string[] = [];

afterEach(async () => {
  for (const root of roots.splice(0)) await rm(root, { recursive: true, force: true });
});

describe('writeFileChunkFully', () => {
  it('retries short file writes until the complete download chunk is persisted', async () => {
    const persisted: number[] = [];
    const writer = {
      write: vi.fn(async (buffer: Uint8Array, offset: number, length: number, _position: null) => {
        const bytesWritten = Math.min(2, length);
        persisted.push(...buffer.subarray(offset, offset + bytesWritten));
        return { bytesWritten };
      }),
    };

    await writeFileChunkFully(writer, new TextEncoder().encode('plugin'), downloadWriteError);

    expect(new TextDecoder().decode(Uint8Array.from(persisted))).toBe('plugin');
    expect(writer.write.mock.calls.map((call) => [call[1], call[2]])).toEqual([
      [0, 6],
      [2, 4],
      [4, 2],
    ]);
  });

  it('fails closed when a file write makes no progress', async () => {
    const writer = {
      write: vi.fn(async () => ({ bytesWritten: 0 })),
    };

    await expect(
      writeFileChunkFully(writer, new Uint8Array([1]), downloadWriteError),
    ).rejects.toMatchObject({ code: 'DOWNLOAD_WRITE_FAILED' });
  });
});

function downloadWriteError(): PluginSystemCloudTransportError {
  return new PluginSystemCloudTransportError(
    'DOWNLOAD_WRITE_FAILED',
    'Plugin package download could not be written completely',
  );
}

describe('PluginSystemCloudTransport admission credential', () => {
  it('uses an explicit admission credential without re-reading the live identity', async () => {
    const fetchImpl = vi.fn<typeof fetch>(async () =>
      Response.json({ base_resp: { status_code: 0 } }),
    );
    const transport = new PluginSystemCloudTransport({
      baseUrl: 'https://agent.example',
      fetchImpl,
      authContextGetter: () => ({ accessToken: 'token-b', realUserID: 'bob' }),
      nowMs: () => 1_700_000_000_123,
    });

    await transport.request({
      method: 'POST',
      path: '/minimax-cloud/api/v1/connectors/tools/call',
      auth: 'required',
      authContext: { accessToken: 'token-a', realUserID: 'alice' },
      body: { provider: 'drive' },
    });

    const firstCall = fetchImpl.mock.calls[0];
    if (!firstCall) throw new Error('Cloud transport did not dispatch');
    const [url, init] = firstCall;
    expect(String(url)).toContain('user_id=alice');
    expect(String(url)).not.toContain('user_id=bob');
    expect(new Headers(init?.headers).get('authorization')).toBe('Bearer token-a');
    expect(new Headers(init?.headers).has('token')).toBe(false);
    expect(init?.body).toBe('{"provider":"drive","common_param":{"user_id":"alice"}}');
  });
});

describe('PluginSystemCloudTransport dispatch boundary', () => {
  it('does not mark dispatch when authentication preflight rejects before fetch', async () => {
    const fetchImpl = vi.fn<typeof fetch>();
    const onDispatch = vi.fn();
    const transport = new PluginSystemCloudTransport({
      baseUrl: 'https://agent.example',
      fetchImpl,
      authContextGetter: () => undefined,
    });

    await expect(
      transport.request({
        method: 'POST',
        path: '/minimax-cloud/api/v1/connectors/tools/call',
        auth: 'required',
        onDispatch,
      }),
    ).rejects.toMatchObject({ code: 'AUTH_REQUIRED' });
    expect(fetchImpl).not.toHaveBeenCalled();
    expect(onDispatch).not.toHaveBeenCalled();
  });

  it('does not mark dispatch when fetch throws synchronously', async () => {
    const fetchImpl = vi.fn<typeof fetch>(() => {
      throw new Error('sync fetch setup failed');
    });
    const onDispatch = vi.fn();
    const transport = new PluginSystemCloudTransport({
      baseUrl: 'https://agent.example',
      fetchImpl,
      authContextGetter: () => undefined,
    });

    await expect(
      transport.request({
        method: 'POST',
        path: '/minimax-cloud/api/v1/connectors/tools/call',
        auth: 'none',
        onDispatch,
      }),
    ).rejects.toMatchObject({ code: 'NETWORK_ERROR' });
    expect(fetchImpl).toHaveBeenCalledOnce();
    expect(onDispatch).not.toHaveBeenCalled();
  });

  it('marks dispatch once after fetch returns its response promise', async () => {
    const events: string[] = [];
    const fetchImpl = vi.fn<typeof fetch>(() => {
      events.push('fetch');
      return Promise.resolve(Response.json({ base_resp: { status_code: 0 } }));
    });
    const onDispatch = vi.fn(() => events.push('dispatch'));
    const transport = new PluginSystemCloudTransport({
      baseUrl: 'https://agent.example',
      fetchImpl,
      authContextGetter: () => undefined,
    });

    await transport.request({
      method: 'POST',
      path: '/minimax-cloud/api/v1/connectors/tools/call',
      auth: 'none',
      onDispatch,
    });

    expect(events).toEqual(['fetch', 'dispatch']);
    expect(onDispatch).toHaveBeenCalledOnce();
  });
});

describe('PluginSystemCloudTransport', () => {
  it('signs anonymous and authenticated requests from the live trusted identity', async () => {
    let identity: { accessToken?: string; realUserID?: string } | undefined;
    const fetchImpl = vi.fn<typeof fetch>(async () =>
      Response.json({ base_resp: { status_code: 0 } }),
    );
    const transport = new PluginSystemCloudTransport({
      baseUrl: 'https://agent.example',
      fetchImpl,
      authContextGetter: () => identity,
      appVersion: '2.3.4',
      previewSecret: 'preview',
      lane: 'blue',
      nowMs: () => 1_700_000_000_123,
    });

    await transport.request({
      method: 'GET',
      path: '/minimax-cloud/api/v1/marketplace/plugins',
      query: { keyword: 'notes' },
      auth: 'optional',
    });
    const anonymous = fetchImpl.mock.calls[0];
    expect(String(anonymous?.[0])).toContain('keyword=notes');
    expect(String(anonymous?.[0])).not.toContain('user_id=');
    expect(new Headers(anonymous?.[1]?.headers).has('token')).toBe(false);
    expect(new Headers(anonymous?.[1]?.headers).has('authorization')).toBe(false);

    identity = { accessToken: 'token-new', realUserID: '42' };
    await transport.request({
      method: 'GET',
      path: '/minimax-cloud/api/v1/marketplace/plugins',
      auth: 'none',
    });
    const forcedAnonymous = fetchImpl.mock.calls[1];
    expect(String(forcedAnonymous?.[0])).not.toContain('user_id=');
    expect(new Headers(forcedAnonymous?.[1]?.headers).has('token')).toBe(false);
    expect(new Headers(forcedAnonymous?.[1]?.headers).has('authorization')).toBe(false);

    await transport.request({
      method: 'GET',
      path: '/minimax-cloud/api/v1/marketplace/plugins',
      auth: 'optional',
    });
    const optionallyAuthenticated = fetchImpl.mock.calls[2];
    expect(String(optionallyAuthenticated?.[0])).toContain('user_id=42');
    expect(new Headers(optionallyAuthenticated?.[1]?.headers).get('authorization')).toBe(
      'Bearer token-new',
    );
    expect(new Headers(optionallyAuthenticated?.[1]?.headers).has('token')).toBe(false);

    await transport.request({
      method: 'POST',
      path: '/minimax-cloud/api/v1/plugins/notes/enable',
      body: { action: 'enable', common_param: { user_id: 'forged' } },
      auth: 'required',
    });
    const authenticated = fetchImpl.mock.calls[3];
    const headers = new Headers(authenticated?.[1]?.headers);
    expect(String(authenticated?.[0])).toContain('user_id=42');
    expect(authenticated?.[1]?.body).toBe('{"action":"enable","common_param":{"user_id":"42"}}');
    expect(headers.get('authorization')).toBe('Bearer token-new');
    expect(headers.has('token')).toBe(false);
    expect(headers.get('yy')).toMatch(/^[0-9a-f]{64}$/u);
    expect(headers.get('x-signature')).toMatch(/^[0-9a-f]{64}$/u);
    expect(headers.get('X-Minimax-Agent-Preview-Secret')).toBe('preview');
    expect(headers.get('bedrock-lane')).toBe('blue');
  });

  it('fails closed for missing auth and response errors without exposing response text', async () => {
    const transport = new PluginSystemCloudTransport({
      baseUrl: 'https://agent.example',
      fetchImpl: vi.fn<typeof fetch>(async () => Response.json({ base_resp: { status_code: 7 } })),
      authContextGetter: () => undefined,
    });

    await expect(
      transport.request({ method: 'GET', path: '/private', auth: 'required' }),
    ).rejects.toMatchObject({ code: 'AUTH_REQUIRED' });
    await expect(
      transport.request({ method: 'GET', path: '/public', auth: 'optional' }),
    ).rejects.toMatchObject({ code: 'BUSINESS_ERROR' });

    const broken = new PluginSystemCloudTransport({
      baseUrl: 'https://agent.example',
      fetchImpl: vi.fn<typeof fetch>(async () => new Response('secret', { status: 503 })),
      authContextGetter: () => undefined,
    });
    await expect(
      broken.request({ method: 'GET', path: '/public', auth: 'optional' }),
    ).rejects.toMatchObject({ code: 'HTTP_ERROR', status: 503 });
  });

  it('normalizes network, payload, path, and download failures to stable errors', async () => {
    const network = new PluginSystemCloudTransport({
      baseUrl: 'https://agent.example/',
      fetchImpl: vi.fn<typeof fetch>(async () => {
        throw new Error('private network detail');
      }),
      authContextGetter: () => ({ accessToken: 'partial' }),
      timeoutMs: 1,
    });
    await expect(
      network.request({ method: 'GET', path: '/public', auth: 'optional' }),
    ).rejects.toMatchObject({ code: 'NETWORK_ERROR' });
    await expect(network.downloadToFile('not-a-url', '/tmp/unused')).rejects.toMatchObject({
      code: 'DOWNLOAD_URL_INVALID',
    });
    await expect(
      network.downloadToFile('https://oss.example/package.zip', '/tmp/unused'),
    ).rejects.toMatchObject({ code: 'NETWORK_ERROR' });

    const responses = [
      new Response('not-json'),
      Response.json([]),
      Response.json({ baseResp: {} }),
    ];
    const malformed = new PluginSystemCloudTransport({
      baseUrl: 'https://agent.example',
      fetchImpl: vi.fn<typeof fetch>(async () => responses.shift() ?? Response.json({})),
      authContextGetter: () => undefined,
    });
    await expect(
      malformed.request({ method: 'GET', path: '/invalid-json', auth: 'optional' }),
    ).rejects.toMatchObject({ code: 'RESPONSE_INVALID' });
    await expect(
      malformed.request({ method: 'GET', path: '/invalid-record', auth: 'optional' }),
    ).rejects.toMatchObject({ code: 'RESPONSE_INVALID' });
    await expect(
      malformed.request({ method: 'POST', path: '/no-status', auth: 'optional' }),
    ).resolves.toEqual({ baseResp: {} });
    await expect(
      malformed.request({ method: 'GET', path: 'relative', auth: 'optional' }),
    ).rejects.toMatchObject({ code: 'PATH_INVALID' });
    await expect(
      malformed.request({ method: 'GET', path: '/https://invalid', auth: 'optional' }),
    ).rejects.toMatchObject({ code: 'PATH_INVALID' });
  });

  it('distinguishes caller cancellation from the bounded request timeout', async () => {
    const waitingFetch = vi.fn<typeof fetch>(async (_url, init) => {
      init?.signal?.throwIfAborted();
      await new Promise<void>((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => reject(init.signal?.reason), { once: true });
      });
      throw new Error('unreachable');
    });
    const transport = new PluginSystemCloudTransport({
      baseUrl: 'https://agent.example',
      fetchImpl: waitingFetch,
      authContextGetter: () => undefined,
      timeoutMs: 5,
    });

    await expect(
      transport.request({ method: 'GET', path: '/slow', auth: 'optional' }),
    ).rejects.toMatchObject({ code: 'REQUEST_TIMEOUT' });

    const controller = new AbortController();
    controller.abort();
    await expect(
      transport.request({
        method: 'GET',
        path: '/cancelled',
        auth: 'optional',
        signal: controller.signal,
      }),
    ).rejects.toMatchObject({ code: 'REQUEST_ABORTED' });
  });

  it('streams a bounded HTTPS package to an exclusive regular file', async () => {
    const root = await mkdtemp(join(tmpdir(), 'plugin-cloud-transport-'));
    roots.push(root);
    const transport = new PluginSystemCloudTransport({
      baseUrl: 'https://agent.example',
      fetchImpl: vi.fn<typeof fetch>(async () => new Response(Buffer.from('plugin-bytes'))),
      authContextGetter: () => undefined,
    });
    const target = join(root, 'package.zip');

    await transport.downloadToFile('https://oss.example/package.zip', target);
    await expect(readFile(target, 'utf8')).resolves.toBe('plugin-bytes');
    await transport.downloadToFile('http://localhost/package.zip', join(root, 'local.zip'));
    await expect(
      transport.downloadToFile('http://oss.example/package.zip', join(root, 'bad.zip')),
    ).rejects.toMatchObject({ code: 'DOWNLOAD_URL_INVALID' });

    const tooLarge = new PluginSystemCloudTransport({
      baseUrl: 'https://agent.example',
      fetchImpl: vi.fn<typeof fetch>(
        async () =>
          new Response(Buffer.from('x'), {
            headers: { 'content-length': String(1024 * 1024 * 1024) },
          }),
      ),
      authContextGetter: () => undefined,
    });
    await expect(
      tooLarge.downloadToFile('https://oss.example/large.zip', join(root, 'large.zip')),
    ).rejects.toMatchObject({ code: 'DOWNLOAD_TOO_LARGE' });
  });

  it('rejects invalid base URLs at construction', () => {
    expect(
      () =>
        new PluginSystemCloudTransport({
          baseUrl: '/relative',
          fetchImpl: vi.fn<typeof fetch>(),
          authContextGetter: () => undefined,
        }),
    ).toThrow(PluginSystemCloudTransportError);
  });
});

describe('PluginSystemCloudTransport HMAC-SHA256 signature', () => {
  const fetchImpl = vi.fn<typeof fetch>(async () =>
    Response.json({ base_resp: { status_code: 0 } }),
  );

  it('emits deterministic 64-char hex SHA256 signatures for the same inputs', async () => {
    const transport = new PluginSystemCloudTransport({
      baseUrl: 'https://agent.example',
      fetchImpl,
      authContextGetter: () => undefined,
      nowMs: () => 1_700_000_000_000,
    });

    await transport.request({ method: 'GET', path: '/p', auth: 'none' });
    const first = fetchImpl.mock.calls[0]?.[1]?.headers as Record<string, string> | undefined;
    const firstYy = first?.['yy'];
    const firstSig = first?.['x-signature'];

    await transport.request({ method: 'GET', path: '/p', auth: 'none' });
    const second = fetchImpl.mock.calls[1]?.[1]?.headers as Record<string, string> | undefined;

    expect(firstYy).toMatch(/^[0-9a-f]{64}$/u);
    expect(firstSig).toMatch(/^[0-9a-f]{64}$/u);
    expect(second?.['yy']).toBe(firstYy);
    expect(second?.['x-signature']).toBe(firstSig);
  });

  it('produces SHA256 output that differs from the prior MD5 signing of the same payload', async () => {
    const { createHash, createHmac } = await import('node:crypto');
    // The signing string for `x-signature` is `${second}${bodyText}`. We compare
    // the live HMAC-SHA256 output against the historical MD5 of that exact
    // payload (regardless of which salt produced it) — they MUST differ, which
    // proves the wire protocol has actually moved off MD5.
    const payload = '1700000000';
    const legacyMd5 = createHash('md5').update(payload).digest('hex');
    const freshHmac = createHmac('sha256', 'any-salt').update(payload).digest('hex');

    expect(legacyMd5).toHaveLength(32);
    expect(freshHmac).toHaveLength(64);
    expect(freshHmac).not.toBe(legacyMd5);

    const transport = new PluginSystemCloudTransport({
      baseUrl: 'https://agent.example',
      fetchImpl,
      authContextGetter: () => undefined,
      nowMs: () => 1_700_000_000_000,
    });
    await transport.request({ method: 'GET', path: '/p', auth: 'none' });
    const headers = fetchImpl.mock.calls.at(-1)?.[1]?.headers as Record<string, string> | undefined;
    const liveSig = headers?.['x-signature'] ?? '';
    expect(liveSig).toMatch(/^[0-9a-f]{64}$/u);
    expect(liveSig).not.toBe(legacyMd5);
  });
});
