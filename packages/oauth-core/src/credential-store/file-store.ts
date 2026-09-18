import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from 'node:crypto';
import { readFile, stat } from 'node:fs/promises';
import { join, resolve } from 'node:path';

import { atomicWritePrivateFile, ensurePrivateDirectory } from '../fs/atomic-write.js';
import {
  type CredentialKey,
  CredentialRecordCorruptError,
  type CredentialStore,
  CredentialStorePermissionError,
  parseStoredCredential,
  type StoredCredential,
} from './types.js';

const FILE_SCHEMA_VERSION = 1;
const ENVELOPE_VERSION = 2 as const;
const ENVELOPE_ALGORITHM = 'AES-256-GCM' as const;
const ENVELOPE_HKDF_SALT = 'mcode-oauth-core-credential-store';
const ENVELOPE_HKDF_INFO = 'mcode-oauth-core-credential-store-v2';
const IV_BYTES = 12;
const AUTH_TAG_BYTES = 16;

interface CredentialFilePayload {
  schemaVersion: 1;
  records: Record<string, StoredCredential>;
}

interface CredentialEnvelope {
  v: typeof ENVELOPE_VERSION;
  alg: typeof ENVELOPE_ALGORITHM;
  iv: string;
  ct: string;
}

export interface FileStoreOptions {
  authHome: string;
}

function recordKey(key: CredentialKey): string {
  return `${key.service}\0${key.account}`;
}

function parsePayload(value: unknown): CredentialFilePayload {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) {
    throw new CredentialRecordCorruptError();
  }
  const payload = value as Record<string, unknown>;
  if (
    payload.schemaVersion !== FILE_SCHEMA_VERSION ||
    typeof payload.records !== 'object' ||
    payload.records === null ||
    Array.isArray(payload.records)
  ) {
    throw new CredentialRecordCorruptError();
  }
  const records = Object.fromEntries(
    Object.entries(payload.records).map(([key, credential]) => [
      key,
      parseStoredCredential(credential),
    ]),
  );
  return { schemaVersion: FILE_SCHEMA_VERSION, records };
}

function isEnvelope(value: unknown): value is CredentialEnvelope {
  if (typeof value !== 'object' || value === null || Array.isArray(value)) return false;
  const candidate = value as Record<string, unknown>;
  return (
    candidate.v === ENVELOPE_VERSION &&
    candidate.alg === ENVELOPE_ALGORITHM &&
    typeof candidate.iv === 'string' &&
    typeof candidate.ct === 'string'
  );
}

function decodeBase64Field(field: string, label: 'iv' | 'ct'): Buffer {
  try {
    const decoded = Buffer.from(field, 'base64');
    if (decoded.length === 0) throw new Error('empty');
    return decoded;
  } catch {
    throw new CredentialRecordCorruptError(
      `The OAuth credential envelope ${label} field is not valid base64.`,
    );
  }
}

/**
 * Strip common token-shaped fragments from log messages so we never echo a
 * stolen refresh token back through the operator console. Mirrors the spirit
 * of the TUI redaction helper without taking a cross-package dependency.
 */
function redactCredentialText(value: string): string {
  return value
    .replace(/\bBearer\s+[^\s,;]+/giu, 'Bearer [redacted]')
    .replace(
      /\b(api[-_ ]?key|access[-_ ]?token|refresh[-_ ]?token|token|password|secret)(\s*[:=]\s*)(?:"[^"]*"|'[^']*'|[^\s,;]+)/giu,
      '$1$2[redacted]',
    );
}

function warnOnce(message: string): void {
  if (process.env.MCODE_OAUTH_SUPPRESS_MIGRATION_WARNING === '1') return;
  // Use console.warn (instead of an injected logger) so this package remains
  // a leaf with no cross-package dependencies. Operators can redirect stderr.
  // eslint-disable-next-line no-console
  console.warn(redactCredentialText(message));
}

export class FileStore implements CredentialStore {
  readonly kind = 'file' as const;

  private readonly authHome: string;
  private readonly path: string;
  private readonly encryptionKey: Buffer;
  private cached: CredentialFilePayload | undefined;
  private legacyWarned = false;

  constructor(options: FileStoreOptions) {
    this.authHome = options.authHome;
    this.path = join(options.authHome, 'auth.json');
    // Derive the key once per FileStore instance. HKDF maps the resolved
    // authHome path plus a fixed application-level salt+info to a 32-byte key.
    // The same authHome always yields the same key on this host, so moving
    // the directory invalidates prior ciphertexts (treated as recoverable).
    const ikm = Buffer.from(resolve(this.authHome), 'utf8');
    this.encryptionKey = Buffer.from(
      hkdfSync(
        'sha256',
        ikm,
        Buffer.from(ENVELOPE_HKDF_SALT, 'utf8'),
        Buffer.from(ENVELOPE_HKDF_INFO, 'utf8'),
        32,
      ),
    );
  }

  async get(key: CredentialKey): Promise<StoredCredential | null> {
    const payload = await this.readPayload();
    return payload.records[recordKey(key)] ?? null;
  }

  async put(key: CredentialKey, credential: StoredCredential): Promise<void> {
    const payload = await this.readPayload();
    payload.records[recordKey(key)] = parseStoredCredential(credential);
    await this.writePayload(payload);
  }

  async delete(key: CredentialKey): Promise<void> {
    const payload = await this.readPayload();
    delete payload.records[recordKey(key)];
    await this.writePayload(payload);
  }

  async healthCheck(): Promise<void> {
    await ensurePrivateDirectory(this.authHome);
    await this.assertPrivatePermissions();
  }

  private async readPayload(): Promise<CredentialFilePayload> {
    if (this.cached) return this.cached;

    let raw: string;
    try {
      await this.assertPrivatePermissions();
      raw = await readFile(this.path, 'utf8');
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') {
        const empty: CredentialFilePayload = { schemaVersion: FILE_SCHEMA_VERSION, records: {} };
        this.cached = empty;
        return empty;
      }
      throw error;
    }

    let parsed: unknown;
    try {
      parsed = JSON.parse(raw);
    } catch (error) {
      // Malformed JSON is treated as a recoverable error: drop the in-memory
      // cache and start fresh, but warn the operator so a partial write isn't
      // mistaken for an authenticated session.
      this.cached = { schemaVersion: FILE_SCHEMA_VERSION, records: {} };
      warnOnce(
        `oauth-core: credential file at ${this.path} is not valid JSON (${redactCredentialText(
          (error as Error).message,
        )}); starting from an empty store.`,
      );
      return this.cached;
    }

    if (isEnvelope(parsed)) {
      try {
        const decrypted = decryptPayload(parsed, this.encryptionKey);
        const payload = parsePayload(decrypted);
        this.cached = payload;
        return payload;
      } catch (error) {
        if (error instanceof CredentialRecordCorruptError) {
          this.cached = { schemaVersion: FILE_SCHEMA_VERSION, records: {} };
          warnOnce(
            `oauth-core: credential file at ${this.path} failed envelope validation; starting from an empty store.`,
          );
          return this.cached;
        }
        throw error;
      }
    }

    // Legacy plaintext shape (no `v` field). Parse it once and mark the file
    // so the next write rewrites the envelope automatically.
    try {
      const payload = parsePayload(parsed);
      this.cached = payload;
      if (!this.legacyWarned) {
        this.legacyWarned = true;
        warnOnce(
          'oauth-core: detected plaintext v1 credential file; it will be rewritten as an encrypted envelope on the next save.',
        );
      }
      return payload;
    } catch (error) {
      if (error instanceof CredentialRecordCorruptError) {
        this.cached = { schemaVersion: FILE_SCHEMA_VERSION, records: {} };
        warnOnce(
          `oauth-core: credential file at ${this.path} is in an unrecognised shape; starting from an empty store.`,
        );
        return this.cached;
      }
      throw error;
    }
  }

  private async assertPrivatePermissions(): Promise<void> {
    if (process.platform === 'win32') return;
    try {
      const [directory, file] = await Promise.all([stat(this.authHome), stat(this.path)]);
      if ((directory.mode & 0o077) !== 0 || (file.mode & 0o077) !== 0) {
        throw new CredentialStorePermissionError();
      }
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code === 'ENOENT') return;
      throw error;
    }
  }

  private async writePayload(payload: CredentialFilePayload): Promise<void> {
    const validated = parsePayload(payload);
    const envelope = encryptPayload(validated, this.encryptionKey);
    await atomicWritePrivateFile(this.path, `${JSON.stringify(envelope)}\n`);
    // After a successful write we are no longer in a legacy-migration state.
    this.cached = validated;
  }
}

function encryptPayload(payload: CredentialFilePayload, key: Buffer): CredentialEnvelope {
  const iv = randomBytes(IV_BYTES);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const plaintext = Buffer.from(JSON.stringify(payload), 'utf8');
  const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const tag = cipher.getAuthTag();
  if (tag.length !== AUTH_TAG_BYTES) {
    throw new CredentialRecordCorruptError(
      'The OAuth credential envelope produced an unexpected authentication tag length.',
    );
  }
  return {
    v: ENVELOPE_VERSION,
    alg: ENVELOPE_ALGORITHM,
    iv: iv.toString('base64'),
    ct: Buffer.concat([ciphertext, tag]).toString('base64'),
  };
}

function decryptPayload(envelope: CredentialEnvelope, key: Buffer): CredentialFilePayload {
  const iv = decodeBase64Field(envelope.iv, 'iv');
  const payload = decodeBase64Field(envelope.ct, 'ct');
  if (iv.length !== IV_BYTES) {
    throw new CredentialRecordCorruptError('The OAuth credential envelope IV has the wrong size.');
  }
  if (payload.length < AUTH_TAG_BYTES) {
    throw new CredentialRecordCorruptError(
      'The OAuth credential envelope ciphertext is shorter than the authentication tag.',
    );
  }
  const tag = payload.subarray(payload.length - AUTH_TAG_BYTES);
  const ciphertext = payload.subarray(0, payload.length - AUTH_TAG_BYTES);
  const decipher = createDecipheriv('aes-256-gcm', key, iv);
  decipher.setAuthTag(tag);
  let plaintext: Buffer;
  try {
    plaintext = Buffer.concat([decipher.update(ciphertext), decipher.final()]);
  } catch {
    // GCM auth-tag verification failure is the canonical tamper signal.
    throw new CredentialRecordCorruptError(
      'The OAuth credential envelope failed authentication tag verification.',
    );
  }
  try {
    return JSON.parse(plaintext.toString('utf8')) as CredentialFilePayload;
  } catch {
    throw new CredentialRecordCorruptError(
      'The OAuth credential envelope decrypted payload is not valid JSON.',
    );
  }
}