import { createHmac } from 'node:crypto';

import { getRuntimeBuildEnv, getRuntimeRegion } from '@mavis/config';

import type {
  EncryptedPromptBundle,
  EncryptedPromptEnvelope,
  PromptConfigClient,
} from './contracts.js';

// Client attribution constants for the `yy` / `x-timestamp` / `x-signature` headers.
//
// These tag a request as coming from a first-party MiniMax client. They are shared
// across clients and are not credentials or a security boundary: request
// authorization is the bearer token sent alongside them.
//
// The signature is HMAC-SHA256(salt, payload) hex-encoded. The `yy` header is
// HMAC-SHA256 of a server-defined composite. Header names are kept stable for
// backward compatibility; rolling out a new salt invalidates MD5 signatures
// still produced by older clients during the migration window.
//
// Changing the salt or the signed-payload format requires a coordinated
// server-side rollout, so treat them as wire-protocol constants.
const SIGNATURE_SALT = 'hmac-sha256-v2:pconfig:5c2a9b8e-3f14-4d6a-9f7e-1a8b3c4d5e6f';
const YY_SUFFIX = 'ooui';
const REQUEST_PATH = '/minimax-cloud/api/v1/desktop/p-config';
const DEFAULT_TIMEOUT_MS = 30_000;
const MAX_RESPONSE_BYTES = 1024 * 1024;
type PromptConfigFetchResult = Awaited<ReturnType<PromptConfigClient['fetch']>>;

export interface PromptConfigCloudClientOptions {
  readonly baseUrl: string;
  readonly fetchImpl: typeof fetch;
  readonly appVersion?: string;
  readonly previewSecret?: string;
  readonly lane?: string;
  readonly nowMs?: () => number;
  readonly timeoutMs?: number;
}

class PromptConfigCloudClientError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly status?: number,
  ) {
    super(message);
    this.name = 'PromptConfigCloudClientError';
  }
}

/** Archon-biz client. Its response is the already merged, account-selected bundle. */
export class PromptConfigCloudClient implements PromptConfigClient {
  private readonly nowMs: () => number;
  private readonly timeoutMs: number;

  constructor(private readonly options: PromptConfigCloudClientOptions) {
    if (!/^https?:\/\//u.test(options.baseUrl.trim())) {
      throw new PromptConfigCloudClientError(
        'BASE_URL_INVALID',
        'Prompt config base URL is invalid',
      );
    }
    this.nowMs = options.nowMs ?? Date.now;
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
  }

  async fetch(input: Parameters<PromptConfigClient['fetch']>[0]): Promise<PromptConfigFetchResult> {
    const now = this.nowMs();
    const signedPath = appendQuery(
      REQUEST_PATH,
      buildPublicParams({
        now,
        appVersion: this.options.appVersion,
        userId: input.auth.accessToken ? input.auth.subject : undefined,
      }),
    );
    const headers = buildHeaders({
      now,
      signedPath,
      accessToken: input.auth.accessToken,
      etag: input.etag,
      previewSecret: this.options.previewSecret,
      lane: this.options.lane,
    });
    let response: Response;
    try {
      response = await this.options.fetchImpl(joinUrl(this.options.baseUrl, signedPath), {
        method: 'GET',
        headers,
        signal: AbortSignal.any([input.signal, AbortSignal.timeout(this.timeoutMs)]),
      });
    } catch (error) {
      throw transportFailure(error);
    }
    if (response.status === 304) {
      return { kind: 'not_modified' };
    }
    if (response.status === 204) {
      return { kind: 'disabled' };
    }
    if (!response.ok) {
      throw new PromptConfigCloudClientError(
        `HTTP_${response.status}`,
        'Prompt config request failed',
        response.status,
      );
    }
    const rawPayload = await readBoundedText(response);
    const bundle = parseBundle(rawPayload);
    return {
      kind: 'updated',
      etag: response.headers.get('etag') ?? bundle.version,
      bundle,
      rawPayload,
    };
  }
}

/** Uses the same archon-biz deployment routing as the Desktop plugin client. */
export function resolvePromptConfigCloudBaseUrl(): string {
  const configured = process.env.NEXT_PUBLIC_DOMAIN_URL?.trim();
  if (configured) return configured;
  const region = getRuntimeRegion();
  const build = getRuntimeBuildEnv();
  if (region === 'cn') {
    if (build === 'test' || build === 'dev') return 'https://matrix-test.example.invalid';
    if (build === 'staging') return 'https://matrix-pre.example.invalid';
    return 'https://agent.minimaxi.com';
  }
  if (build === 'test' || build === 'dev') return 'https://matrix-overseas-test.example.invalid';
  if (build === 'staging') return 'https://matrix-overseas-pre.example.invalid';
  return 'https://agent.minimax.io';
}

function buildPublicParams(input: {
  readonly now: number;
  readonly appVersion?: string;
  readonly userId?: string;
}): Record<string, string | number> {
  const region = getRuntimeRegion();
  return {
    device_platform: 'web',
    biz_id: 3,
    app_id: '3001',
    version_code: '22201',
    unix: input.now,
    timezone_offset: new Date(input.now).getTimezoneOffset() * -60,
    sys_language: region === 'en' ? 'en' : 'zh',
    lang: region === 'en' ? 'en' : 'zh',
    device_id: 0,
    ...(input.userId ? { user_id: input.userId } : {}),
    client: 'desktop',
    region,
    is_desktop: 1,
    ...(input.appVersion ? { desktop_version: input.appVersion } : {}),
  };
}

function buildHeaders(input: {
  readonly now: number;
  readonly signedPath: string;
  readonly accessToken?: string;
  readonly etag?: string;
  readonly previewSecret?: string;
  readonly lane?: string;
}): Record<string, string> {
  const second = Math.floor(input.now / 1000);
  const headers: Record<string, string> = {
    'content-type': 'application/json',
    yy: sha256Hmac(
      SIGNATURE_SALT,
      `${encodeURIComponent(input.signedPath)}_${sha256Hmac(SIGNATURE_SALT, String(input.now))}${YY_SUFFIX}`,
    ),
    'x-timestamp': String(second),
    'x-signature': sha256Hmac(SIGNATURE_SALT, String(second)),
  };
  if (input.accessToken) headers.Authorization = `Bearer ${input.accessToken}`;
  else headers['X-Mavis-Anonymous'] = 'true';
  if (input.etag) headers['if-none-match'] = input.etag;
  if (input.previewSecret?.trim())
    headers['X-Minimax-Agent-Preview-Secret'] = input.previewSecret.trim();
  if (input.lane?.trim()) {
    headers.lane = input.lane.trim();
    headers.bedrock_lane = input.lane.trim();
    headers['bedrock-lane'] = input.lane.trim();
  }
  return headers;
}

async function readBoundedText(response: Response): Promise<string> {
  const declared = Number(response.headers.get('content-length'));
  if (Number.isFinite(declared) && declared > MAX_RESPONSE_BYTES) {
    throw new PromptConfigCloudClientError(
      'RESPONSE_TOO_LARGE',
      'Prompt config response is too large',
    );
  }
  const text = await response.text();
  if (Buffer.byteLength(text, 'utf8') > MAX_RESPONSE_BYTES) {
    throw new PromptConfigCloudClientError(
      'RESPONSE_TOO_LARGE',
      'Prompt config response is too large',
    );
  }
  return text;
}

function parseBundle(raw: string): EncryptedPromptBundle {
  let value: unknown;
  try {
    value = JSON.parse(raw);
  } catch {
    throw invalidResponse();
  }
  if (!record(value)) throw invalidResponse();
  const { version, key_version: keyVersion } = value;
  if (
    value.algorithm !== 'AES-256-GCM' ||
    typeof version !== 'string' ||
    typeof keyVersion !== 'string' ||
    !Array.isArray(value.files)
  )
    throw invalidResponse();
  const files = value.files.map((file) => parseFile(file, version));
  if (files.some((file) => file === undefined)) throw invalidResponse();
  return {
    version,
    algorithm: 'AES-256-GCM',
    keyVersion,
    files: files as EncryptedPromptEnvelope[],
  };
}

function parseFile(value: unknown, version: string): EncryptedPromptEnvelope | undefined {
  if (
    !record(value) ||
    typeof value.path !== 'string' ||
    typeof value.nonce !== 'string' ||
    typeof value.ciphertext !== 'string'
  )
    return undefined;
  return {
    version,
    algorithm: 'AES-256-GCM',
    path: value.path,
    nonce: value.nonce,
    ciphertext: value.ciphertext,
  };
}

function invalidResponse(): PromptConfigCloudClientError {
  return new PromptConfigCloudClientError('RESPONSE_INVALID', 'Prompt config response is invalid');
}
function appendQuery(path: string, query: Readonly<Record<string, string | number>>): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(query)) params.set(key, String(value));
  return `${path}?${params.toString()}`;
}
function joinUrl(baseUrl: string, path: string): string {
  return `${baseUrl.replace(/\/+$/u, '')}${path}`;
}
function sha256Hmac(secret: string, value: string): string {
  return createHmac('sha256', secret).update(value).digest('hex');
}
function record(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}
function transportFailure(error: unknown): PromptConfigCloudClientError {
  if (error instanceof PromptConfigCloudClientError) return error;
  if (error instanceof Error && error.name === 'AbortError')
    return new PromptConfigCloudClientError('REQUEST_ABORTED', 'Prompt config request was aborted');
  if (error instanceof Error && error.name === 'TimeoutError')
    return new PromptConfigCloudClientError('REQUEST_TIMEOUT', 'Prompt config request timed out');
  return new PromptConfigCloudClientError('NETWORK_ERROR', 'Prompt config request failed');
}
