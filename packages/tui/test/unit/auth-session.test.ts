import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { createAuthNamespace, type OAuthClient } from '@mavis/oauth-core';
import { afterEach, describe, expect, it, vi } from 'vitest';

import { createMcodeSharedAuthSession } from '../../src/runtime/auth-session.js';

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(roots.splice(0).map((root) => rm(root, { recursive: true, force: true })));
});

describe('createMcodeSharedAuthSession', () => {
  it('persists and reuses a plaintext credential without a passphrase provider', async () => {
    const dataDir = await mkdtemp(join(tmpdir(), 'mcode-tui-auth-session-'));
    roots.push(dataDir);
    const namespace = createAuthNamespace({ dataDir, buildEnv: 'test', region: 'en' });
    const unused = vi.fn(async () => {
      throw new Error('OAuth network should not be used for a valid stored credential');
    });
    const oauthClient: OAuthClient = {
      startDeviceAuthorization: vi.fn(async () => ({
        deviceCode: 'device-secret',
        codeVerifier: 'pkce-secret',
        userCode: 'ABCD-EFGH',
        verificationUri: 'https://account.example.test/device',
        expiresInSec: 300,
        intervalSec: 1,
      })),
      pollDeviceToken: vi.fn(async () => ({
        accessToken: 'shared-access-token',
        refreshToken: 'shared-refresh-token',
        tokenType: 'Bearer',
        scopes: ['agent.default'],
        audience: 'agent-backend',
        expiresInSec: 3_600,
      })),
      refreshToken: unused,
      revokeToken: unused,
    };
    const session = createMcodeSharedAuthSession({
      dataDir,
      region: 'en',
      buildEnv: 'test',
      oauthClient,
    });

    await expect(session.login()).resolves.toMatchObject({
      status: 'authenticated',
      generation: 1,
    });
    const raw = await readFile(namespace.credentialPath, 'utf8');
    // The credential file is envelope-encrypted at rest; neither the access
    // nor the refresh token must appear in plaintext on disk.
    const envelope = JSON.parse(raw);
    expect(envelope).toMatchObject({ v: 2, alg: 'AES-256-GCM' });
    expect(typeof envelope.iv).toBe('string');
    expect(typeof envelope.ct).toBe('string');
    expect(raw).not.toContain('shared-access-token');
    expect(raw).not.toContain('shared-refresh-token');

    const restored = createMcodeSharedAuthSession({
      dataDir,
      region: 'en',
      buildEnv: 'test',
      oauthClient: {
        startDeviceAuthorization: unused,
        pollDeviceToken: unused,
        refreshToken: unused,
        revokeToken: unused,
      },
    });
    await expect(
      restored.getAccessToken({ requiredScopes: ['agent.default'], minValidityMs: 30_000 }),
    ).resolves.toMatchObject({ accessToken: 'shared-access-token', generation: 1 });
    expect(unused).not.toHaveBeenCalled();
  });
});
