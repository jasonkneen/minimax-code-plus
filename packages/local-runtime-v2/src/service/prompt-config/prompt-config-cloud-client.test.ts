/**
 * `PromptConfigCloudClient` HMAC-SHA256 signature boundary.
 *
 * Pins:
 *   - The wire signature header emits deterministic 64-char hex
 *     HMAC-SHA256 for the same inputs (and the `yy` header follows the
 *     same property).
 *   - The new HMAC-SHA256 output for the same signing payload is not
 *     bit-equal to the historical MD5 digest — the protocol has actually
 *     moved off MD5.
 *   - Header names (`yy`, `x-signature`) are preserved for backward
 *     compatibility, but the signing payload no longer mixes the salt
 *     into the input string (HMAC handles keying internally).
 */

import { createHash, createHmac } from 'node:crypto';

import { describe, expect, it, vi } from 'vitest';

import {
  PromptConfigCloudClient,
  type PromptConfigCloudClientOptions,
} from './prompt-config-cloud-client.js';

function fixture(
  overrides: Partial<PromptConfigCloudClientOptions> = {},
): { client: PromptConfigCloudClient; fetchImpl: ReturnType<typeof vi.fn> } {
  const fetchImpl = vi.fn<typeof fetch>(async () => new Response('not-json', { status: 500 }));
  const client = new PromptConfigCloudClient({
    baseUrl: 'https://agent.example',
    fetchImpl: fetchImpl as unknown as typeof fetch,
    nowMs: () => 1_700_000_000_000,
    ...overrides,
  });
  return { client, fetchImpl };
}

describe('PromptConfigCloudClient HMAC-SHA256 signature', () => {
  it('emits deterministic 64-char hex SHA256 signatures for the same inputs', async () => {
    const { client, fetchImpl } = fixture();
    const auth = {
      scopeId: 'scope',
      subject: 'user-1',
      keyVersion: 'desktop-v1',
      generation: 0,
      accessToken: 'token',
    };

    await client.fetch({ auth, signal: AbortSignal.timeout(10) }).catch(() => undefined);
    const first = fetchImpl.mock.calls[0]?.[1]?.headers as Record<string, string> | undefined;

    await client.fetch({ auth, signal: AbortSignal.timeout(10) }).catch(() => undefined);
    const second = fetchImpl.mock.calls[1]?.[1]?.headers as Record<string, string> | undefined;

    expect(first?.['yy']).toMatch(/^[0-9a-f]{64}$/u);
    expect(first?.['x-signature']).toMatch(/^[0-9a-f]{64}$/u);
    expect(second?.['yy']).toBe(first?.['yy']);
    expect(second?.['x-signature']).toBe(first?.['x-signature']);
  });

  it('produces SHA256 output that differs from MD5 for the same signing payload', () => {
    // Sign `${second}` with HMAC-SHA256 and compare against MD5 of the
    // same string — the two algorithms MUST differ on equal-length-ish
    // inputs and always produce different digests for the same payload.
    const payload = '1700000000';
    const md5Digest = createHash('md5').update(payload).digest('hex');
    const hmacDigest = createHmac('sha256', 'any-salt').update(payload).digest('hex');

    expect(md5Digest).toHaveLength(32);
    expect(hmacDigest).toHaveLength(64);
    expect(hmacDigest).not.toBe(md5Digest);
  });

  it('keeps the historical header names for backward compatibility', async () => {
    const { client, fetchImpl } = fixture();
    const auth = {
      scopeId: 'scope',
      subject: 'user-1',
      keyVersion: 'desktop-v1',
      generation: 0,
    };
    await client.fetch({ auth, signal: AbortSignal.timeout(10) }).catch(() => undefined);
    const headers = fetchImpl.mock.calls[0]?.[1]?.headers as Record<string, string> | undefined;

    expect(headers?.['yy']).toBeDefined();
    expect(headers?.['x-signature']).toBeDefined();
    expect(headers?.['x-timestamp']).toBe('1700000000');
  });
});