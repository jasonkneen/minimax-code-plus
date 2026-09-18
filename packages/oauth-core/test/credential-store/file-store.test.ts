import { chmod, mkdtemp, readFile, rm, stat, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, beforeEach, describe, expect, it } from 'vitest';

import { FileStore } from '../../src/credential-store/file-store.js';
import type { CredentialKey, StoredCredential } from '../../src/credential-store/types.js';
import {
  MCODE_OAUTH_AUDIENCE,
  MCODE_OAUTH_CLIENT_ID,
  MCODE_OAUTH_SCOPES,
} from '../../src/contracts.js';

const KEY: CredentialKey = {
  service: 'com.example.test.oauth',
  account: 'unit-test-account',
};

function buildCredential(overrides: Partial<StoredCredential> = {}): StoredCredential {
  return {
    schemaVersion: 1,
    accessToken: 'access-token-1234567890',
    refreshToken: 'refresh-token-1234567890',
    tokenType: 'Bearer',
    clientId: MCODE_OAUTH_CLIENT_ID,
    scopes: [...MCODE_OAUTH_SCOPES],
    audience: MCODE_OAUTH_AUDIENCE,
    expiresAtMs: Date.now() + 60 * 60 * 1_000,
    generation: 1,
    loginEpoch: 'unit-test-login-epoch',
    ...overrides,
  };
}

const directories: string[] = [];

async function temporaryDirectory(): Promise<string> {
  const dir = await mkdtemp(join(tmpdir(), 'mcode-oauth-filestore-'));
  directories.push(dir);
  return dir;
}

async function setPrivatePermissions(directory: string, file: string): Promise<void> {
  if (process.platform === 'win32') return;
  await chmod(directory, 0o700);
  await chmod(file, 0o600);
}

afterEach(async () => {
  while (directories.length > 0) {
    const dir = directories.pop();
    if (dir) await rm(dir, { recursive: true, force: true });
  }
});

describe('FileStore envelope encryption', () => {
  let authHome: string;
  let filePath: string;

  beforeEach(async () => {
    authHome = await temporaryDirectory();
    filePath = join(authHome, 'auth.json');
  });

  it('round-trips a stored credential through the encrypted envelope', async () => {
    const store = new FileStore({ authHome });
    const credential = buildCredential();
    await store.put(KEY, credential);

    const onDisk = JSON.parse(await readFile(filePath, 'utf8'));
    expect(onDisk).toMatchObject({ v: 2, alg: 'AES-256-GCM' });
    expect(typeof onDisk.iv).toBe('string');
    expect(typeof onDisk.ct).toBe('string');
    expect(onDisk).not.toHaveProperty('records');
    expect(JSON.stringify(onDisk)).not.toContain(credential.refreshToken);
    expect(JSON.stringify(onDisk)).not.toContain(credential.accessToken);

    const restored = await store.get(KEY);
    expect(restored).toEqual(credential);
  });

  it('uses a fresh IV and ciphertext on every write', async () => {
    const store = new FileStore({ authHome });
    await store.put(KEY, buildCredential());
    const first = JSON.parse(await readFile(filePath, 'utf8'));
    await store.put(KEY, buildCredential({ generation: 2 }));
    const second = JSON.parse(await readFile(filePath, 'utf8'));

    expect(first.iv).not.toEqual(second.iv);
    expect(first.ct).not.toEqual(second.ct);
  });

  it('rejects tampered ciphertext via the GCM authentication tag', async () => {
    const writer = new FileStore({ authHome });
    await writer.put(KEY, buildCredential());

    const envelope = JSON.parse(await readFile(filePath, 'utf8'));
    const ctBytes = Buffer.from(envelope.ct, 'base64');
    // Flip a single byte inside the ciphertext portion (not the trailing tag).
    ctBytes[0] = ctBytes[0] ^ 0x01;
    envelope.ct = ctBytes.toString('base64');
    await writeFile(filePath, JSON.stringify(envelope));
    // `writeFile` resets permissions; restore the private bits so the
    // permission assertion does not mask the tamper.
    await setPrivatePermissions(authHome, filePath);

    // A fresh FileStore has no cached payload, so the on-disk tampered
    // envelope must fail GCM verification and yield no credential.
    const reader = new FileStore({ authHome });
    expect(await reader.get(KEY)).toBeNull();
  });

  it('loads a legacy plaintext file and re-saves it encrypted on the next write', async () => {
    const legacy: StoredCredential = buildCredential({ generation: 7 });
    const legacyDocument = {
      schemaVersion: 1,
      records: { [`${KEY.service}\0${KEY.account}`]: legacy },
    };
    await writeFile(filePath, `${JSON.stringify(legacyDocument)}\n`);
    await setPrivatePermissions(authHome, filePath);

    const store = new FileStore({ authHome });
    expect(await store.get(KEY)).toEqual(legacy);

    // The next save must rewrite the file in the encrypted envelope form.
    await store.put(KEY, legacy);
    const onDisk = JSON.parse(await readFile(filePath, 'utf8'));
    expect(onDisk).toMatchObject({ v: 2, alg: 'AES-256-GCM' });
    expect(onDisk).not.toHaveProperty('records');
    expect(JSON.stringify(onDisk)).not.toContain(legacy.refreshToken);
    expect(JSON.stringify(onDisk)).not.toContain(legacy.accessToken);
  });

  it('preserves private permission bits (0o700 dir / 0o600 file) across the migration', async () => {
    const legacy: StoredCredential = buildCredential({ generation: 3 });
    const legacyDocument = {
      schemaVersion: 1,
      records: { [`${KEY.service}\0${KEY.account}`]: legacy },
    };
    await writeFile(filePath, `${JSON.stringify(legacyDocument)}\n`);
    await setPrivatePermissions(authHome, filePath);

    const store = new FileStore({ authHome });
    await store.get(KEY);
    await store.put(KEY, legacy);

    if (process.platform !== 'win32') {
      const dirStat = await stat(authHome);
      const fileStat = await stat(filePath);
      expect(dirStat.mode & 0o777).toBe(0o700);
      expect(fileStat.mode & 0o777).toBe(0o600);
    }
  });

  it('survives a malformed file as a recoverable empty store', async () => {
    await writeFile(filePath, '{ this is not valid json');
    await setPrivatePermissions(authHome, filePath);

    const store = new FileStore({ authHome });
    expect(await store.get(KEY)).toBeNull();

    // A subsequent save must produce a valid envelope.
    await store.put(KEY, buildCredential({ generation: 9 }));
    expect(await store.get(KEY)).toMatchObject({ generation: 9 });
  });
});