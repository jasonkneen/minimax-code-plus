/**
 * Feishu webhook envelope decryption boundary.
 *
 * Pins:
 *   - Round-tripping a JSON payload through AES-256-GCM with a valid
 *     16-byte authentication tag returns the original object.
 *   - Any tampering with the ciphertext, IV, or tag fails the GCM
 *     authentication check and returns `undefined` — the JSON parser is
 *     never reached for tampered payloads.
 *   - Malformed envelopes (too short, missing tag) are rejected up front.
 */

import { createCipheriv, createHash, randomBytes } from 'node:crypto';

import { describe, expect, it } from 'vitest';

import {
  decryptFeishuEvent,
  unwrapMaybeEncryptedFeishuEvent,
} from '../../src/channels/adapters/feishu/feishu-card.js';

const ENCRYPT_KEY = 'test-feishu-encrypt-key';

function encryptFeishuGcm(plaintext: string, keyString: string = ENCRYPT_KEY): string {
  const key = createHash('sha256').update(keyString, 'utf8').digest();
  const iv = randomBytes(16);
  const cipher = createCipheriv('aes-256-gcm', key, iv);
  const ciphertext = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  return Buffer.concat([iv, ciphertext, tag]).toString('base64');
}

describe('decryptFeishuEvent AES-256-GCM envelope', () => {
  it('round-trips a JSON payload when the GCM tag is valid', () => {
    const plaintext = JSON.stringify({ event: { type: 'message' }, ts: '1700000000' });
    const encryptedBase64 = encryptFeishuGcm(plaintext);

    expect(decryptFeishuEvent(encryptedBase64, ENCRYPT_KEY)).toEqual({
      event: { type: 'message' },
      ts: '1700000000',
    });
  });

  it('rejects ciphertext that has been tampered with after encryption', () => {
    const encryptedBase64 = encryptFeishuGcm('{"hello":"world"}');
    const bytes = Buffer.from(encryptedBase64, 'base64');
    // Flip one byte in the ciphertext region (between IV and tag).
    const tamperIndex = 16 + Math.floor(bytes.length / 4);
    bytes[tamperIndex] = bytes[tamperIndex]! ^ 0xff;
    const tampered = bytes.toString('base64');

    expect(decryptFeishuEvent(tampered, ENCRYPT_KEY)).toBeUndefined();
  });

  it('rejects a payload whose GCM authentication tag has been replaced', () => {
    const encryptedBase64 = encryptFeishuGcm('{"hello":"world"}');
    const bytes = Buffer.from(encryptedBase64, 'base64');
    // Overwrite the trailing 16-byte tag with random bytes.
    randomBytes(16).copy(bytes, bytes.length - 16);
    const tampered = bytes.toString('base64');

    expect(decryptFeishuEvent(tampered, ENCRYPT_KEY)).toBeUndefined();
  });

  it('rejects envelopes that are too short to carry both IV and tag', () => {
    const tooShort = Buffer.concat([randomBytes(16), randomBytes(8)]).toString('base64');
    expect(decryptFeishuEvent(tooShort, ENCRYPT_KEY)).toBeUndefined();
  });

  it('returns undefined when the wrong key is supplied', () => {
    const encryptedBase64 = encryptFeishuGcm('{"hello":"world"}');
    expect(decryptFeishuEvent(encryptedBase64, 'other-key')).toBeUndefined();
  });

  it('returns undefined for empty inputs without throwing', () => {
    expect(decryptFeishuEvent('', ENCRYPT_KEY)).toBeUndefined();
    expect(decryptFeishuEvent(encryptFeishuGcm('{}'), '')).toBeUndefined();
  });
});

describe('unwrapMaybeEncryptedFeishuEvent AES-256-GCM envelope', () => {
  it('decrypts an enveloped body when the encrypt key is configured', () => {
    const plaintext = JSON.stringify({ event: { type: 'card_action' } });
    const body = { encrypt: encryptFeishuGcm(plaintext) };

    expect(unwrapMaybeEncryptedFeishuEvent(body, ENCRYPT_KEY)).toEqual({
      event: { type: 'card_action' },
    });
  });

  it('falls back to undefined for an enveloped body when the key is missing', () => {
    const body = { encrypt: encryptFeishuGcm('{}') };
    expect(unwrapMaybeEncryptedFeishuEvent(body)).toBeUndefined();
  });

  it('passes an unencrypted body through unchanged', () => {
    const body = { event: { type: 'message' } };
    expect(unwrapMaybeEncryptedFeishuEvent(body, ENCRYPT_KEY)).toEqual(body);
  });
});