import { randomUUID } from 'node:crypto';
import { watchFile, unwatchFile } from 'node:fs';

import {
  MCODE_OAUTH_AUDIENCE,
  MCODE_OAUTH_CLIENT_ID,
  MCODE_OAUTH_SCOPES,
  type AccessTokenLease,
  type UnauthorizedContext,
} from './contracts.js';
import { CrossProcessAuthLock } from './cross-process-lock.js';
import type { CredentialStore, StoredCredential } from './credential-store/types.js';
import type { AuthNamespace } from './namespace.js';
import {
  OAuthProtocolError,
  type DeviceAuthorization,
  type OAuthClient,
  type OAuthTokenGrant,
} from './oauth-client.js';
import {
  AUTH_STATE_SCHEMA_VERSION,
  AuthStateStore,
  type AuthState,
  type AuthStatus,
} from './state-store.js';

const DEFAULT_AUTHORIZATION_LEASE_MS = 10 * 60 * 1_000;
const DEFAULT_STATE_POLL_INTERVAL_MS = 250;

export class AuthRequiredError extends Error {
  readonly code = 'AUTH_REQUIRED';

  constructor(options?: ErrorOptions) {
    super('MCode authentication is required.', options);
    this.name = 'AuthRequiredError';
  }
}

export class AuthLoginCancelledError extends Error {
  readonly code = 'AUTH_LOGIN_CANCELLED';

  constructor() {
    super('MCode OAuth device authorization was cancelled.');
    this.name = 'AuthLoginCancelledError';
  }
}

/** Rejects only the stale request; the current shared account remains signed in. */
export class AuthSessionChangedError extends Error {
  readonly code = 'AUTH_SESSION_CHANGED';

  constructor() {
    super('The login changed while this request was in progress.');
    this.name = 'AuthSessionChangedError';
  }
}

export function assertSameLoginEpoch(
  expected: string | undefined,
  current: string | undefined,
): void {
  if (!expected || expected !== current) throw new AuthSessionChangedError();
}

export class AuthScopeUpgradeRequiredError extends Error {
  readonly code = 'AUTH_SCOPE_UPGRADE_REQUIRED';

  constructor(readonly missingScopes: string[]) {
    super('The current MCode authorization does not include the required scope.');
    this.name = 'AuthScopeUpgradeRequiredError';
  }
}

export class AuthResourceContractMismatchError extends Error {
  readonly code = 'AUTH_RESOURCE_CONTRACT_MISMATCH';

  constructor() {
    super('The stored credential does not match the MCode resource contract.');
    this.name = 'AuthResourceContractMismatchError';
  }
}

export function requiresInteractiveLogin(error: unknown): boolean {
  return (
    error instanceof AuthRequiredError ||
    error instanceof AuthScopeUpgradeRequiredError ||
    error instanceof AuthResourceContractMismatchError
  );
}

export class AuthDomainConflictError extends Error {
  readonly code = 'AUTH_DOMAIN_CONFLICT';

  constructor(
    readonly active: Pick<AuthNamespace, 'buildEnv' | 'region'>,
    readonly requested: Pick<AuthNamespace, 'buildEnv' | 'region'>,
  ) {
    super(
      `MCode is signed in to ${active.buildEnv}/${active.region}; sign out before using ${requested.buildEnv}/${requested.region}.`,
    );
    this.name = 'AuthDomainConflictError';
  }
}

export interface MCodeOAuthCoreOptions {
  namespace: AuthNamespace;
  credentialStore: CredentialStore;
  oauthClient: OAuthClient;
  initialize?: () => Promise<void>;
  now?: () => number;
  sleep?: (durationMs: number) => Promise<void>;
  authorizationLeaseMs?: number;
  statePollIntervalMs?: number;
  createLeaseId?: () => string;
}

export interface LoginOptions {
  onDeviceAuthorization?: (authorization: DeviceAuthorizationPrompt) => void;
}

export interface DeviceAuthorizationPrompt {
  userCode: string;
  verificationUri: string;
  verificationUriComplete?: string;
  expiresInSec: number;
}

export interface LoginResult {
  status: 'authenticated';
  generation: number;
}

export interface LogoutResult {
  status: 'anonymous' | 'logout_pending';
  generation: number;
}

export interface AccessTokenOptions {
  requiredScopes: string[];
  minValidityMs: number;
}

export interface AuthStatusSnapshot {
  status: AuthStatus;
  generation: number;
  scopes: string[];
  buildEnv?: AuthNamespace['buildEnv'];
  region?: AuthNamespace['region'];
  expiresAtMs?: number;
}

export class MCodeOAuthCore {
  private readonly stateStore: AuthStateStore;
  private readonly lock: CrossProcessAuthLock;
  private readonly now: () => number;
  private readonly sleep: (durationMs: number) => Promise<void>;
  private readonly authorizationLeaseMs: number;
  private readonly statePollIntervalMs: number;
  private readonly createLeaseId: () => string;
  private loginPromise: Promise<LoginResult> | undefined;
  private loginAbortController: AbortController | undefined;
  private initializePromise: Promise<void> | undefined;

  constructor(private readonly options: MCodeOAuthCoreOptions) {
    this.stateStore = new AuthStateStore(options.namespace.statePath);
    this.lock = new CrossProcessAuthLock(options.namespace.lockPath);
    this.now = options.now ?? Date.now;
    this.sleep =
      options.sleep ?? ((durationMs) => new Promise((resolve) => setTimeout(resolve, durationMs)));
    this.authorizationLeaseMs = options.authorizationLeaseMs ?? DEFAULT_AUTHORIZATION_LEASE_MS;
    this.statePollIntervalMs = options.statePollIntervalMs ?? DEFAULT_STATE_POLL_INTERVAL_MS;
    this.createLeaseId = options.createLeaseId ?? randomUUID;
  }

  async getStatus(): Promise<AuthStatusSnapshot> {
    await this.initialize();
    const state = await this.stateStore.read();
    if (!state) return { status: 'anonymous', generation: 0, scopes: [] };
    if (state.status === 'authorizing' || state.status === 'refreshing') {
      const recovered = await this.recoverInterruptedCredentialCommit(state);
      return toStatusSnapshot(recovered);
    }
    if (state.status === 'authenticated' || state.status === 'expired') {
      const credential = await this.options.credentialStore.get(
        this.options.namespace.credentialKey,
      );
      if (!credential || credential.generation !== state.generation) {
        return toStatusSnapshot({ ...state, status: 'error' });
      }
      try {
        assertCredentialContract(credential, [...MCODE_OAUTH_SCOPES]);
      } catch (error) {
        if (error instanceof AuthScopeUpgradeRequiredError) {
          return toStatusSnapshot({
            ...authenticatedState(
              credential,
              this.options.credentialStore.kind,
              this.options.namespace,
            ),
            status: 'scope_upgrade_required',
          });
        }
        if (error instanceof AuthResourceContractMismatchError) {
          return toStatusSnapshot({ ...state, status: 'error' });
        }
        throw error;
      }
      const current = authenticatedState(
        credential,
        this.options.credentialStore.kind,
        this.options.namespace,
      );
      if (state.status === 'expired' || credential.expiresAtMs <= this.now()) {
        return toStatusSnapshot({ ...current, status: 'expired' });
      }
      return toStatusSnapshot(current);
    }
    return toStatusSnapshot(state);
  }

  login(options: LoginOptions = {}): Promise<LoginResult> {
    if (!this.loginPromise) {
      const controller = new AbortController();
      const promise = this.initialize()
        .then(() => this.runLogin(options, controller.signal))
        .finally(() => {
          if (this.loginPromise !== promise) return;
          this.loginPromise = undefined;
          this.loginAbortController = undefined;
        });
      this.loginAbortController = controller;
      this.loginPromise = promise;
    }
    return this.loginPromise;
  }

  async cancelLogin(): Promise<void> {
    const controller = this.loginAbortController;
    const promise = this.loginPromise;
    if (!controller || !promise) return;
    controller.abort();
    try {
      await promise;
    } catch (error) {
      if (!(error instanceof AuthLoginCancelledError)) throw error;
    }
  }

  async getAccessToken(options: AccessTokenOptions): Promise<AccessTokenLease> {
    await this.initialize();
    validateRequestedScopes(options.requiredScopes);
    try {
      const initial = await this.readUsableCredential(options.requiredScopes);
      if (this.satisfiesMinValidity(initial, options.minValidityMs)) {
        return toAccessTokenLease(initial.credential);
      }
    } catch (error) {
      if (!(error instanceof AuthRequiredError)) throw error;
      // A concurrent writer may have committed credentials before their state.
      // Recheck under the domain lock before reporting authentication as missing.
    }

    return this.lock.withLock(async () => {
      const current = await this.readUsableCredential(options.requiredScopes);
      if (this.satisfiesMinValidity(current, options.minValidityMs)) {
        return toAccessTokenLease(current.credential);
      }
      return this.refreshCredential(current);
    });
  }

  /**
   * Only committed authenticated leases can be reused. A refresh in progress
   * must finish under the shared lock; an expired lease must refresh successfully.
   */
  private satisfiesMinValidity(
    current: { state: AuthState; credential: StoredCredential },
    minValidityMs: number,
  ): boolean {
    if (current.state.status !== 'authenticated') return false;
    const remainingMs = current.credential.expiresAtMs - this.now();
    return remainingMs > 0 && remainingMs >= minValidityMs;
  }

  async handleUnauthorized(context: UnauthorizedContext): Promise<'retry' | 'logout'> {
    await this.initialize();
    try {
      return await this.lock.withLock(async () => {
        const current = await this.readUsableCredential([...MCODE_OAUTH_SCOPES]);
        if (context.loginEpoch !== undefined) {
          assertSameLoginEpoch(context.loginEpoch, current.credential.loginEpoch);
        } else if (current.credential.generation > context.generation) {
          // Older callers cannot prove that a newer generation belongs to their login.
          throw new AuthSessionChangedError();
        }
        if (current.credential.generation > context.generation) return 'retry';
        if (current.credential.generation < context.generation) return 'logout';
        await this.refreshCredential(current, { rejected: true });
        return 'retry';
      });
    } catch (error) {
      if (requiresInteractiveLogin(error)) return 'logout';
      throw error;
    }
  }

  async logout(options: { revoke: boolean }): Promise<LogoutResult> {
    await this.initialize();
    return this.lock.withLock(async () => {
      const state = await this.stateStore.read();
      const credential = await this.options.credentialStore.get(
        this.options.namespace.credentialKey,
      );
      const currentGeneration = Math.max(state?.generation ?? 0, credential?.generation ?? 0);
      if (!credential && (!state || state.status === 'anonymous')) {
        return { status: 'anonymous', generation: currentGeneration };
      }

      const logoutGeneration = currentGeneration + 1;
      await this.stateStore.write(
        baseState(
          {
            status: 'logging_out',
            generation: logoutGeneration,
            storeKind: this.options.credentialStore.kind,
          },
          this.options.namespace,
        ),
      );

      if (options.revoke && credential) {
        try {
          await this.options.oauthClient.revokeToken(credential.refreshToken);
        } catch {
          await this.stateStore.write(
            baseState(
              {
                status: 'logout_pending',
                generation: logoutGeneration,
                storeKind: this.options.credentialStore.kind,
              },
              this.options.namespace,
            ),
          );
          return { status: 'logout_pending', generation: logoutGeneration };
        }
      }

      await this.options.credentialStore.delete(this.options.namespace.credentialKey);
      await this.stateStore.write(
        baseState(
          {
            status: 'anonymous',
            generation: logoutGeneration,
            storeKind: this.options.credentialStore.kind,
          },
          this.options.namespace,
        ),
      );
      return { status: 'anonymous', generation: logoutGeneration };
    });
  }

  watch(listener: (status: AuthStatusSnapshot) => void): () => void {
    const onChange = () => {
      void this.getStatus()
        .then(listener)
        .catch(() => undefined);
    };
    watchFile(this.options.namespace.statePath, { interval: this.statePollIntervalMs }, onChange);
    return () => unwatchFile(this.options.namespace.statePath, onChange);
  }

  private initialize(): Promise<void> {
    this.initializePromise ??= (async () => {
      await this.options.initialize?.();
      await this.options.credentialStore.healthCheck();
    })().catch((error) => {
      this.initializePromise = undefined;
      throw error;
    });
    return this.initializePromise;
  }

  private async runLogin(options: LoginOptions, signal: AbortSignal): Promise<LoginResult> {
    while (true) {
      assertLoginNotCancelled(signal);
      const leaseId = this.createLeaseId();
      const decision = await this.lock.withLock(async () => {
        const state = await this.stateStore.read();
        assertLoginStateDomain(state, this.options.namespace);
        const credential = await this.options.credentialStore.get(
          this.options.namespace.credentialKey,
        );
        if (
          state &&
          credential &&
          state.generation === credential.generation &&
          (state.status === 'authenticated' ||
            state.status === 'expired' ||
            state.status === 'refreshing')
        ) {
          try {
            assertCredentialContract(credential, [...MCODE_OAUTH_SCOPES]);
            if (state.status === 'authenticated' && credential.expiresAtMs > this.now()) {
              return { kind: 'authenticated' as const, generation: credential.generation };
            }
            return { kind: 'refresh' as const, generation: credential.generation };
          } catch (error) {
            if (
              !(error instanceof AuthScopeUpgradeRequiredError) &&
              !(error instanceof AuthResourceContractMismatchError)
            ) {
              throw error;
            }
          }
        }
        if (
          state?.status === 'authorizing' &&
          state.authorization &&
          state.authorization.leaseExpiresAtMs > this.now()
        ) {
          return { kind: 'wait' as const, leaseExpiresAtMs: state.authorization.leaseExpiresAtMs };
        }
        const generation = Math.max(state?.generation ?? 0, credential?.generation ?? 0);
        await this.stateStore.write({
          ...baseState(
            {
              status: 'authorizing',
              generation,
              storeKind: this.options.credentialStore.kind,
            },
            this.options.namespace,
          ),
          authorization: {
            leaseId,
            leaseExpiresAtMs: this.now() + this.authorizationLeaseMs,
          },
        });
        return { kind: 'owner' as const };
      });

      if (decision.kind === 'authenticated') {
        return { status: 'authenticated', generation: decision.generation };
      }
      if (decision.kind === 'refresh') {
        try {
          await this.lock.withLock(async () => {
            const current = await this.readUsableCredential([...MCODE_OAUTH_SCOPES]);
            if (
              current.credential.generation > decision.generation &&
              this.satisfiesMinValidity(current, 1)
            )
              return;
            await this.refreshCredential(current);
          });
        } catch (error) {
          // The credential changed or vanished concurrently; re-evaluate.
          if (requiresInteractiveLogin(error)) continue;
          throw error;
        }
        const state = await this.stateStore.read();
        if (state?.status === 'authenticated') {
          return { status: 'authenticated', generation: state.generation };
        }
        continue;
      }
      if (decision.kind === 'wait') {
        const result = await this.waitForAuthorization(
          decision.leaseExpiresAtMs,
          options.onDeviceAuthorization,
          signal,
        );
        if (result) return result;
        continue;
      }

      try {
        const authorization = await this.options.oauthClient.startDeviceAuthorization({ signal });
        await this.publishAuthorizationProgress(leaseId, authorization);
        options.onDeviceAuthorization?.(toAuthorizationPrompt(authorization));
        const grant = await this.options.oauthClient.pollDeviceToken(authorization, { signal });
        return await this.commitLogin(leaseId, grant, signal);
      } catch (error) {
        const cancelled = signal.aborted;
        await this.releaseAuthorizationLease(leaseId, cancelled ? 'anonymous' : 'error');
        if (cancelled) throw new AuthLoginCancelledError();
        throw error;
      }
    }
  }

  private async commitLogin(
    leaseId: string,
    grant: OAuthTokenGrant,
    signal: AbortSignal,
  ): Promise<LoginResult> {
    return this.lock.withLock(async () => {
      assertLoginNotCancelled(signal);
      const state = await this.stateStore.read();
      if (state?.status !== 'authorizing' || state.authorization?.leaseId !== leaseId) {
        throw new AuthRequiredError();
      }
      assertNonceMatchesLease(grant.nonce, state.authorization?.nonce);
      const credential = await this.options.credentialStore.get(
        this.options.namespace.credentialKey,
      );
      assertLoginNotCancelled(signal);
      const generation = Math.max(state.generation, credential?.generation ?? 0) + 1;
      const stored = credentialFromGrant(grant, generation, this.now(), randomUUID());
      await this.options.credentialStore.put(this.options.namespace.credentialKey, stored);
      try {
        assertLoginNotCancelled(signal);
        await this.stateStore.write(
          authenticatedState(stored, this.options.credentialStore.kind, this.options.namespace),
        );
        assertLoginNotCancelled(signal);
      } catch (error) {
        if (error instanceof AuthLoginCancelledError) {
          // Roll back under the same lock; another client's login cannot be erased.
          await this.stateStore.write(state);
          if (credential) {
            await this.options.credentialStore.put(
              this.options.namespace.credentialKey,
              credential,
            );
          } else {
            await this.options.credentialStore.delete(this.options.namespace.credentialKey);
          }
        }
        throw error;
      }
      return { status: 'authenticated', generation };
    });
  }

  private async waitForAuthorization(
    leaseExpiresAtMs: number,
    onDeviceAuthorization?: (authorization: DeviceAuthorizationPrompt) => void,
    signal?: AbortSignal,
  ): Promise<LoginResult | undefined> {
    let progressPublished = false;
    while (this.now() < leaseExpiresAtMs) {
      assertLoginNotCancelled(signal);
      const state = await this.stateStore.read();
      if (
        !progressPublished &&
        state?.status === 'authorizing' &&
        state.authorization?.userCode &&
        state.authorization.verificationUri
      ) {
        onDeviceAuthorization?.({
          userCode: state.authorization.userCode,
          verificationUri: state.authorization.verificationUri,
          ...(state.authorization.verificationUriComplete
            ? { verificationUriComplete: state.authorization.verificationUriComplete }
            : {}),
          expiresInSec: Math.max(
            1,
            Math.ceil((state.authorization.leaseExpiresAtMs - this.now()) / 1_000),
          ),
        });
        progressPublished = true;
      }
      if (state?.status === 'authenticated') {
        const credential = await this.options.credentialStore.get(
          this.options.namespace.credentialKey,
        );
        if (credential && credential.generation === state.generation) {
          assertCredentialContract(credential, [...MCODE_OAUTH_SCOPES]);
          return { status: 'authenticated', generation: state.generation };
        }
      }
      if (state?.status !== 'authorizing') return undefined;
      await sleepWithSignal(this.sleep, this.statePollIntervalMs, signal);
    }
    return undefined;
  }

  private async publishAuthorizationProgress(
    leaseId: string,
    authorization: DeviceAuthorization,
  ): Promise<void> {
    await this.lock.withLock(async () => {
      const state = await this.stateStore.read();
      if (state?.status !== 'authorizing' || state.authorization?.leaseId !== leaseId) {
        throw new AuthRequiredError();
      }
      await this.stateStore.write({
        ...state,
        authorization: {
          ...state.authorization,
          userCode: authorization.userCode,
          verificationUri: authorization.verificationUri,
          ...(authorization.verificationUriComplete
            ? { verificationUriComplete: authorization.verificationUriComplete }
            : {}),
          ...(authorization.nonce ? { nonce: authorization.nonce } : {}),
        },
      });
    });
  }

  private async releaseAuthorizationLease(
    leaseId: string,
    status: Extract<AuthStatus, 'anonymous' | 'error'>,
  ): Promise<void> {
    await this.lock.withLock(async () => {
      const state = await this.stateStore.read();
      if (state?.status !== 'authorizing' || state.authorization?.leaseId !== leaseId) return;
      await this.stateStore.write(
        baseState(
          {
            status,
            generation: state.generation,
            storeKind: this.options.credentialStore.kind,
          },
          this.options.namespace,
        ),
      );
    });
  }

  private async recoverInterruptedCredentialCommit(observedState: AuthState): Promise<AuthState> {
    const observedCredential = await this.options.credentialStore.get(
      this.options.namespace.credentialKey,
    );
    if (!observedCredential || observedCredential.generation <= observedState.generation) {
      return observedState;
    }
    assertCredentialContract(observedCredential, [...MCODE_OAUTH_SCOPES]);
    return this.lock.withLock(async () => {
      const state = await this.stateStore.read();
      const credential = await this.options.credentialStore.get(
        this.options.namespace.credentialKey,
      );
      if (
        !state ||
        !credential ||
        (state.status !== 'authorizing' && state.status !== 'refreshing') ||
        credential.generation <= state.generation
      ) {
        return state ?? observedState;
      }
      assertCredentialContract(credential, [...MCODE_OAUTH_SCOPES]);
      const recovered = authenticatedState(
        credential,
        this.options.credentialStore.kind,
        this.options.namespace,
      );
      await this.stateStore.write(recovered);
      return recovered;
    });
  }

  private async readUsableCredential(requiredScopes: string[]): Promise<{
    state: AuthState;
    credential: StoredCredential;
  }> {
    const state = await this.stateStore.read();
    if (
      !state ||
      (state.status !== 'authenticated' &&
        state.status !== 'expired' &&
        state.status !== 'refreshing')
    ) {
      throw new AuthRequiredError();
    }
    const credential = await this.options.credentialStore.get(this.options.namespace.credentialKey);
    if (!credential || state.generation !== credential.generation) throw new AuthRequiredError();
    assertCredentialContract(credential, requiredScopes);
    return { state, credential };
  }

  private async refreshCredential(
    current: { state: AuthState; credential: StoredCredential },
    options: { rejected?: boolean } = {},
  ): Promise<AccessTokenLease> {
    await this.stateStore.write({ ...current.state, status: 'refreshing' });
    let grant: OAuthTokenGrant;
    try {
      grant = await this.options.oauthClient.refreshToken(current.credential.refreshToken);
    } catch (error) {
      if (isInvalidRefreshGrant(error)) {
        // Publish the invalidation before deleting the secret. Both mutations
        // use the caller's lock, so another owner cannot commit a login between them.
        await this.stateStore.write(
          baseState(
            {
              status: 'anonymous',
              generation: current.credential.generation + 1,
              storeKind: this.options.credentialStore.kind,
            },
            this.options.namespace,
          ),
        );
        await this.options.credentialStore.delete(this.options.namespace.credentialKey);
        throw new AuthRequiredError({ cause: error });
      } else {
        const preserveSession =
          !options.rejected &&
          current.state.status === 'authenticated' &&
          current.credential.expiresAtMs > this.now();
        await this.stateStore.write({
          ...current.state,
          status: preserveSession ? 'authenticated' : 'expired',
        });
      }
      throw error;
    }
    const stored = credentialFromGrant(
      grant,
      Math.max(current.state.generation, current.credential.generation) + 1,
      this.now(),
      current.credential.loginEpoch,
    );
    await this.options.credentialStore.put(this.options.namespace.credentialKey, stored);
    await this.stateStore.write(
      authenticatedState(stored, this.options.credentialStore.kind, this.options.namespace),
    );
    return toAccessTokenLease(stored);
  }
}

function assertLoginNotCancelled(signal: AbortSignal | undefined): void {
  if (signal?.aborted) throw new AuthLoginCancelledError();
}

/**
 * Enforce that the nonce returned by the OAuth client matches the one
 * persisted on the namespace lease. The legacy case (lease carries no nonce
 * yet because it was written by an older build) is accepted so existing
 * in-flight logins survive the upgrade; otherwise mismatched nonces fail.
 */
function assertNonceMatchesLease(
  grantNonce: string | undefined,
  leaseNonce: string | undefined,
): void {
  if (leaseNonce === undefined) return;
  if (grantNonce === undefined) {
    throw new OAuthProtocolError(
      'state_mismatch',
      'The persisted lease carries a device-flow nonce that the grant did not return.',
    );
  }
  if (grantNonce !== leaseNonce) {
    throw new OAuthProtocolError(
      'state_mismatch',
      'The OAuth device-flow nonce does not match the persisted lease.',
    );
  }
}

function isInvalidRefreshGrant(error: unknown): boolean {
  return (
    error instanceof OAuthProtocolError &&
    error.code === 'invalid_grant' &&
    error.httpStatus === 400
  );
}

async function sleepWithSignal(
  sleep: (durationMs: number) => Promise<void>,
  durationMs: number,
  signal: AbortSignal | undefined,
): Promise<void> {
  if (!signal) {
    await sleep(durationMs);
    return;
  }
  assertLoginNotCancelled(signal);
  let rejectCancellation!: (error: AuthLoginCancelledError) => void;
  const onAbort = () => rejectCancellation(new AuthLoginCancelledError());
  const cancelled = new Promise<never>((_resolve, reject) => {
    rejectCancellation = reject;
  });
  signal.addEventListener('abort', onAbort, { once: true });
  try {
    await Promise.race([sleep(durationMs), cancelled]);
  } finally {
    signal.removeEventListener('abort', onAbort);
  }
}

function toAuthorizationPrompt(authorization: DeviceAuthorization): DeviceAuthorizationPrompt {
  return {
    userCode: authorization.userCode,
    verificationUri: authorization.verificationUri,
    ...(authorization.verificationUriComplete
      ? { verificationUriComplete: authorization.verificationUriComplete }
      : {}),
    expiresInSec: authorization.expiresInSec,
  };
}

function baseState(
  input: {
    status: AuthStatus;
    generation: number;
    storeKind: CredentialStore['kind'];
  },
  namespace: AuthNamespace,
): AuthState {
  return {
    schemaVersion: AUTH_STATE_SCHEMA_VERSION,
    status: input.status,
    storeKind: input.storeKind,
    clientId: MCODE_OAUTH_CLIENT_ID,
    scopes: [...MCODE_OAUTH_SCOPES],
    audience: MCODE_OAUTH_AUDIENCE,
    buildEnv: namespace.buildEnv,
    region: namespace.region,
    generation: input.generation,
  };
}

function authenticatedState(
  credential: StoredCredential,
  storeKind: CredentialStore['kind'],
  namespace: AuthNamespace,
): AuthState {
  return {
    ...baseState(
      { status: 'authenticated', generation: credential.generation, storeKind },
      namespace,
    ),
    scopes: credential.scopes,
    expiresAtMs: credential.expiresAtMs,
  };
}

function credentialFromGrant(
  grant: OAuthTokenGrant,
  generation: number,
  now: number,
  loginEpoch: string = randomUUID(),
): StoredCredential {
  const credential: StoredCredential = {
    schemaVersion: 1,
    accessToken: grant.accessToken,
    refreshToken: grant.refreshToken,
    tokenType: grant.tokenType,
    clientId: MCODE_OAUTH_CLIENT_ID,
    scopes: grant.scopes,
    audience: MCODE_OAUTH_AUDIENCE,
    expiresAtMs: now + grant.expiresInSec * 1_000,
    generation,
    loginEpoch,
    ...(grant.subject ? { subject: grant.subject } : {}),
    ...(grant.accountId ? { accountId: grant.accountId } : {}),
  };
  assertCredentialContract(credential, [...MCODE_OAUTH_SCOPES]);
  if (grant.audience !== MCODE_OAUTH_AUDIENCE) throw new AuthResourceContractMismatchError();
  return credential;
}

function validateRequestedScopes(requiredScopes: string[]): void {
  const unsupported = requiredScopes.filter(
    (scope) => !MCODE_OAUTH_SCOPES.includes(scope as 'agent.default'),
  );
  if (unsupported.length > 0) throw new AuthScopeUpgradeRequiredError(unsupported);
}

function assertCredentialContract(credential: StoredCredential, requiredScopes: string[]): void {
  if (
    credential.clientId !== MCODE_OAUTH_CLIENT_ID ||
    credential.audience !== MCODE_OAUTH_AUDIENCE ||
    credential.tokenType !== 'Bearer'
  ) {
    throw new AuthResourceContractMismatchError();
  }
  const missing = requiredScopes.filter((scope) => !credential.scopes.includes(scope));
  if (missing.length > 0) throw new AuthScopeUpgradeRequiredError(missing);
}

function toStatusSnapshot(state: AuthState): AuthStatusSnapshot {
  return {
    status: state.status,
    generation: state.generation,
    scopes: state.scopes,
    ...(state.buildEnv === undefined ? {} : { buildEnv: state.buildEnv }),
    ...(state.region === undefined ? {} : { region: state.region }),
    ...(state.expiresAtMs === undefined ? {} : { expiresAtMs: state.expiresAtMs }),
  };
}

function assertLoginStateDomain(state: AuthState | null, namespace: AuthNamespace): void {
  if (
    !state ||
    state.status === 'anonymous' ||
    state.buildEnv === undefined ||
    state.region === undefined ||
    (state.buildEnv === namespace.buildEnv && state.region === namespace.region)
  ) {
    return;
  }
  throw new AuthDomainConflictError(
    { buildEnv: state.buildEnv, region: state.region },
    { buildEnv: namespace.buildEnv, region: namespace.region },
  );
}

function toAccessTokenLease(credential: StoredCredential): AccessTokenLease {
  return {
    accessToken: credential.accessToken,
    ...(credential.loginEpoch ? { loginEpoch: credential.loginEpoch } : {}),
    expiresAtMs: credential.expiresAtMs,
    generation: credential.generation,
    scopes: MCODE_OAUTH_SCOPES,
    audience: MCODE_OAUTH_AUDIENCE,
  };
}
