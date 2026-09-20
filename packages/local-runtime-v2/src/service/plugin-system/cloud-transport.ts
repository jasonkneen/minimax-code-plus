import { createHmac } from 'node:crypto';
import { open } from 'node:fs/promises';

import { getRuntimeRegion } from '@mavis/config';

import { writeFileChunkFully } from './file-chunk-writer.js';
import { PLUGIN_PACKAGE_V1_LIMITS } from './plugin/package/package-contract.js';

// Client attribution constants for the `yy` / `x-timestamp` / `x-signature` headers.
//
// These tag a request as coming from a first-party MiniMax client. They are shared
// across clients and are not credentials or a security boundary: request
// authorization is the bearer token sent alongside them.
//
// The signature is HMAC-SHA256(salt, payload) hex-encoded. Header names are kept
// stable for backward compatibility; rolling out a new salt invalidates MD5
// signatures still produced by older clients during the migration window.
//
// Changing the salt or the signed-payload format requires a coordinated
// server-side rollout, so treat them as wire-protocol constants.
const SIGNATURE_SALT = 'hmac-sha256-v2:plugin:9a7b4d2f-6e18-4c53-8d7a-2b9e5f1c0a3e';
const YY_SUFFIX = 'ooui';
const DEFAULT_TIMEOUT_MS = 30_000;
const DEFAULT_DOWNLOAD_TIMEOUT_MS = 120_000;

interface PluginSystemCloudAuthContext {
  readonly accessToken?: string;
  readonly realUserID?: string;
}

export interface PluginSystemCloudTransportOptions {
  readonly baseUrl: string;
  readonly fetchImpl: typeof fetch;
  readonly authContextGetter: () => PluginSystemCloudAuthContext | undefined;
  readonly appVersion?: string;
  readonly previewSecret?: string;
  readonly lane?: string;
  readonly nowMs?: () => number;
  readonly timeoutMs?: number;
  readonly downloadTimeoutMs?: number;
}

export interface PluginSystemCloudRequest {
  readonly method: 'GET' | 'POST';
  readonly path: string;
  readonly query?: Readonly<Record<string, string | number | boolean | undefined>>;
  readonly body?: Readonly<Record<string, unknown>>;
  readonly auth: 'none' | 'optional' | 'required';
  /** Immutable host-owned credential captured by an admission gate. */
  readonly authContext?: PluginSystemCloudAuthContext;
  readonly onDispatch?: () => void;
  readonly signal?: AbortSignal;
  readonly timeoutMs?: number;
}

export class PluginSystemCloudTransportError extends Error {
  constructor(
    readonly code: string,
    message: string,
    readonly status?: number,
  ) {
    super(message);
    this.name = 'PluginSystemCloudTransportError';
  }
}

/** Signed archon_biz transport owned by the Desktop utility runtime. */
export class PluginSystemCloudTransport {
  private readonly nowMs: () => number;
  private readonly timeoutMs: number;
  private readonly downloadTimeoutMs: number;

  constructor(private readonly options: PluginSystemCloudTransportOptions) {
    const baseUrl = options.baseUrl.trim();
    if (!/^https?:\/\//u.test(baseUrl)) {
      throw new PluginSystemCloudTransportError(
        'BASE_URL_INVALID',
        'Plugin System Cloud base URL is invalid',
      );
    }
    this.nowMs = options.nowMs ?? Date.now;
    this.timeoutMs = options.timeoutMs ?? DEFAULT_TIMEOUT_MS;
    this.downloadTimeoutMs = options.downloadTimeoutMs ?? DEFAULT_DOWNLOAD_TIMEOUT_MS;
  }

  async request(request: PluginSystemCloudRequest): Promise<unknown> {
    const auth = readAuth(
      resolveAuthContext(request, this.options.authContextGetter),
      request.auth,
    );
    const now = this.nowMs();
    const route = buildRoute(request.path, request.query);
    const publicParams = buildPublicParams({
      now,
      appVersion: this.options.appVersion,
      userId: auth?.realUserID,
    });
    const signedPath = appendQuery(route, publicParams);
    const body =
      request.method === 'POST'
        ? {
            ...(request.body ?? {}),
            ...(auth ? { common_param: { user_id: auth.realUserID } } : {}),
          }
        : undefined;
    const bodyText = body ? JSON.stringify(body) : '';
    const signal = composeSignal(request.signal, request.timeoutMs ?? this.timeoutMs);
    let response: Response;
    try {
      const responsePromise = this.options.fetchImpl(joinUrl(this.options.baseUrl, signedPath), {
        method: request.method,
        headers: buildHeaders({
          auth,
          body,
          bodyText,
          now,
          signedPath,
          previewSecret: this.options.previewSecret,
          lane: this.options.lane,
        }),
        ...(bodyText ? { body: bodyText } : {}),
        signal,
      });
      request.onDispatch?.();
      response = await responsePromise;
    } catch (error) {
      throw transportFailure(error);
    }
    if (!response.ok) {
      throw new PluginSystemCloudTransportError(
        'HTTP_ERROR',
        `Plugin Cloud request failed with HTTP ${response.status}`,
        response.status,
      );
    }
    let payload: unknown;
    try {
      payload = await response.json();
    } catch {
      throw new PluginSystemCloudTransportError(
        'RESPONSE_INVALID',
        'Plugin System Cloud response is not JSON',
      );
    }
    assertBusinessSuccess(payload);
    return payload;
  }

  async downloadToFile(url: string, targetPath: string, signal?: AbortSignal): Promise<void> {
    const parsed = parseDownloadUrl(url);
    let response: Response;
    try {
      response = await this.options.fetchImpl(parsed, {
        method: 'GET',
        signal: composeSignal(signal, this.downloadTimeoutMs),
      });
    } catch (error) {
      throw transportFailure(error);
    }
    if (!response.ok || !response.body) {
      throw new PluginSystemCloudTransportError(
        'DOWNLOAD_HTTP_ERROR',
        `Plugin package download failed with HTTP ${response.status}`,
        response.status,
      );
    }
    await writeBoundedBody(response, targetPath);
  }
}

function resolveAuthContext(
  request: PluginSystemCloudRequest,
  getter: () => PluginSystemCloudAuthContext | undefined,
): PluginSystemCloudAuthContext | undefined {
  return request.authContext === undefined ? getter() : request.authContext;
}

function buildPublicParams(input: {
  now: number;
  appVersion?: string;
  userId?: string;
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
  auth: Required<Pick<PluginSystemCloudAuthContext, 'accessToken' | 'realUserID'>> | undefined;
  body: Record<string, unknown> | undefined;
  bodyText: string;
  now: number;
  signedPath: string;
  previewSecret?: string;
  lane?: string;
}): Record<string, string> {
  const second = Math.floor(input.now / 1000);
  const yyBody = input.body ? JSON.stringify(input.body) : '{}';
  const headers: Record<string, string> = {
    'content-type': 'application/json',
    yy: sha256Hmac(
      SIGNATURE_SALT,
      `${encodeURIComponent(input.signedPath)}_${yyBody}${sha256Hmac(SIGNATURE_SALT, String(input.now))}${YY_SUFFIX}`,
    ),
    'x-timestamp': String(second),
    'x-signature': sha256Hmac(SIGNATURE_SALT, `${second}${input.bodyText}`),
  };
  if (input.auth) headers.Authorization = `Bearer ${input.auth.accessToken}`;
  if (input.previewSecret?.trim()) {
    headers['X-Minimax-Agent-Preview-Secret'] = input.previewSecret.trim();
  }
  if (input.lane?.trim()) {
    headers.lane = input.lane.trim();
    headers.bedrock_lane = input.lane.trim();
    headers['bedrock-lane'] = input.lane.trim();
  }
  return headers;
}

function readAuth(
  context: PluginSystemCloudAuthContext | undefined,
  mode: PluginSystemCloudRequest['auth'],
): Required<Pick<PluginSystemCloudAuthContext, 'accessToken' | 'realUserID'>> | undefined {
  if (mode === 'none') return undefined;
  const accessToken = context?.accessToken?.trim();
  const realUserID = context?.realUserID?.trim();
  if (accessToken && realUserID) return { accessToken, realUserID };
  if (mode === 'required') {
    throw new PluginSystemCloudTransportError(
      'AUTH_REQUIRED',
      'Plugin System Cloud request requires login',
    );
  }
  return undefined;
}

function buildRoute(path: string, query: PluginSystemCloudRequest['query']): string {
  if (!path.startsWith('/') || path.includes('://')) {
    throw new PluginSystemCloudTransportError(
      'PATH_INVALID',
      'Plugin System Cloud request path is invalid',
    );
  }
  return appendQuery(path, query ?? {});
}

function appendQuery(
  value: string,
  query: Readonly<Record<string, string | number | boolean | undefined>>,
): string {
  const [pathname, existing = ''] = value.split('?', 2);
  const params = new URLSearchParams(existing);
  for (const [key, item] of Object.entries(query)) {
    if (item !== undefined) params.set(key, String(item));
  }
  const suffix = params.toString();
  return suffix ? `${pathname}?${suffix}` : (pathname ?? value);
}

function joinUrl(baseUrl: string, path: string): string {
  return `${baseUrl.replace(/\/+$/u, '')}${path}`;
}

function parseDownloadUrl(value: string): string {
  let parsed: URL;
  try {
    parsed = new URL(value);
  } catch {
    throw new PluginSystemCloudTransportError(
      'DOWNLOAD_URL_INVALID',
      'Plugin download URL is invalid',
    );
  }
  if (
    parsed.protocol !== 'https:' &&
    parsed.hostname !== '127.0.0.1' &&
    parsed.hostname !== 'localhost'
  ) {
    throw new PluginSystemCloudTransportError(
      'DOWNLOAD_URL_INVALID',
      'Plugin download URL must use HTTPS',
    );
  }
  return parsed.toString();
}

function composeSignal(signal: AbortSignal | undefined, timeoutMs: number): AbortSignal {
  const timeout = AbortSignal.timeout(timeoutMs);
  return signal ? AbortSignal.any([signal, timeout]) : timeout;
}

function assertBusinessSuccess(payload: unknown): void {
  if (!isRecord(payload)) {
    throw new PluginSystemCloudTransportError(
      'RESPONSE_INVALID',
      'Plugin System Cloud response is invalid',
    );
  }
  const base = readRecord(payload, 'base_resp', 'baseResp');
  if (!base) return;
  const status = readNumber(base, 'status_code', 'statusCode');
  if (status !== undefined && status !== 0) {
    throw new PluginSystemCloudTransportError(
      'BUSINESS_ERROR',
      'Plugin System Cloud request was rejected',
    );
  }
}

async function writeBoundedBody(response: Response, targetPath: string): Promise<void> {
  const contentLength = Number(response.headers.get('content-length'));
  if (Number.isFinite(contentLength) && contentLength > PLUGIN_PACKAGE_V1_LIMITS.maxArchiveBytes) {
    throw new PluginSystemCloudTransportError(
      'DOWNLOAD_TOO_LARGE',
      'Plugin package exceeds the byte limit',
    );
  }
  const reader = response.body?.getReader();
  if (!reader)
    throw new PluginSystemCloudTransportError('DOWNLOAD_EMPTY', 'Plugin package body is empty');
  const handle = await open(targetPath, 'wx', 0o600);
  let total = 0;
  let done = false;
  try {
    while (!done) {
      const result = await reader.read();
      if (result.done) {
        done = true;
        continue;
      }
      total += result.value.byteLength;
      if (total > PLUGIN_PACKAGE_V1_LIMITS.maxArchiveBytes) {
        await reader.cancel();
        throw new PluginSystemCloudTransportError(
          'DOWNLOAD_TOO_LARGE',
          'Plugin package exceeds the byte limit',
        );
      }
      await writeFileChunkFully(
        handle,
        result.value,
        () =>
          new PluginSystemCloudTransportError(
            'DOWNLOAD_WRITE_FAILED',
            'Plugin package download could not be written completely',
          ),
      );
    }
  } finally {
    await handle.close();
  }
}

function transportFailure(error: unknown): PluginSystemCloudTransportError {
  if (error instanceof PluginSystemCloudTransportError) return error;
  const aborted = error instanceof Error && error.name === 'AbortError';
  const timedOut = error instanceof Error && error.name === 'TimeoutError';
  if (aborted) {
    return new PluginSystemCloudTransportError(
      'REQUEST_ABORTED',
      'Plugin System Cloud request was aborted',
    );
  }
  if (timedOut) {
    return new PluginSystemCloudTransportError(
      'REQUEST_TIMEOUT',
      'Plugin System Cloud request timed out',
    );
  }
  return new PluginSystemCloudTransportError('NETWORK_ERROR', 'Plugin System Cloud request failed');
}

function sha256Hmac(secret: string, value: string): string {
  return createHmac('sha256', secret).update(value).digest('hex');
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function readRecord(
  value: Record<string, unknown>,
  snake: string,
  camel: string,
): Record<string, unknown> | undefined {
  const field = value[snake] ?? value[camel];
  return isRecord(field) ? field : undefined;
}

function readNumber(
  value: Record<string, unknown>,
  snake: string,
  camel: string,
): number | undefined {
  const field = value[snake] ?? value[camel];
  return typeof field === 'number' ? field : undefined;
}
