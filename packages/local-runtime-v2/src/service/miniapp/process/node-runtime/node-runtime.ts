import { spawn as nodeSpawn, type ChildProcess, type SpawnOptions } from 'node:child_process';
import { createHash, randomUUID } from 'node:crypto';
import { lstat, mkdir, mkdtemp, realpath, rm } from 'node:fs/promises';
import { createConnection } from 'node:net';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

import { sanitizeBashSubprocessEnv } from '@mavis/agent-core/bash-subprocess-env';

import type {
  MiniAppHostConnectorSession,
  MiniAppHostConnectorSessionFactory,
  MiniAppNodeRuntime,
  MiniAppNodeRuntimeFactory,
  MiniAppRuntimeExit,
  ProcessMiniAppCandidate,
} from '../../contracts.js';
import { selectFailureAfterCleanup } from '../../supervisor/cleanup-settlement.js';
import { MiniAppCleanupUnprovenError, markMiniAppRootTerminationProven } from '../../errors.js';
import { sanitizeMiniAppRuntimeLogEvent } from '../../runtime-log.js';
import type { MiniAppRunnerInitMessage } from './host-runner.js';
import {
  createDirectNodeRootTerminator,
  type DirectNodeRootTerminator,
  type DirectNodeRootTerminatorOptions,
} from './direct-root.js';
import {
  attachStartupFailureDetail,
  captureStartupError,
  isRunnerErrorMessage,
  MiniAppNodeRuntimeError,
  runnerFailure,
} from './node-runtime-startup-error.js';

const LOOPBACK_HOST = '127.0.0.1' as const;
const PORT_MIN = 49_152;
const PORT_MAX = 65_535;
const PORT_COUNT = PORT_MAX - PORT_MIN + 1;
const MAX_RUNNING_PLUGIN_SERVICES = 3;
const runtimeObservations = new Set<Promise<void>>();
interface SpawnLike {
  (command: string, args: string[], options: SpawnOptions): ChildProcess;
}

interface TcpConnectInput {
  readonly host: typeof LOOPBACK_HOST;
  readonly port: number;
  readonly timeoutMs: number;
  readonly signal: AbortSignal;
}

interface PathStat {
  isDirectory(): boolean;
  isSymbolicLink(): boolean;
}

interface NodeRuntimeOptions {
  readonly resolvePluginDataDir: (pluginId: string) => string | Promise<string>;
  readonly verifyCandidate: (candidate: ProcessMiniAppCandidate) => Promise<boolean>;
  readonly materializePackage: (input: {
    readonly sourceRoot: string;
    readonly targetRoot: string;
  }) => Promise<void>;
  readonly isPortReserved: (input: { readonly pluginId: string; readonly port: number }) => boolean;
  readonly reservePort?: (input: {
    readonly pluginId: string;
    readonly port: number;
    readonly processGeneration: string;
  }) => { release(): void } | undefined;
  readonly hostConnectorSessionFactory?: MiniAppHostConnectorSessionFactory;
  readonly execPath?: string;
  readonly runnerPath?: string;
  readonly platform?: NodeJS.Platform;
  readonly env?: NodeJS.ProcessEnv;
  readonly spawn?: SpawnLike;
  readonly connectPort?: (input: TcpConnectInput) => Promise<void>;
  readonly createTerminator?: (
    child: ChildProcess,
    options: DirectNodeRootTerminatorOptions,
  ) => DirectNodeRootTerminator;
  readonly createRuntimeDir?: () => Promise<string>;
  readonly lstatPath?: (target: string) => Promise<PathStat>;
  readonly removeRuntimeDir?: (directory: string) => Promise<void>;
  readonly ensureDirectory?: (directory: string) => Promise<void>;
  readonly resolveRealPath?: (target: string) => Promise<string>;
  readonly makeStartupToken?: () => string;
  readonly nowMs?: () => number;
  readonly wait?: (ms: number, signal: AbortSignal) => Promise<void>;
  readonly runnerStartTimeoutMs?: number;
  readonly tcpConnectTimeoutMs?: number;
  readonly tcpRetryMs?: number;
  readonly maxPortAttempts?: number;
}

type ResolvedOptions = Required<
  Pick<
    NodeRuntimeOptions,
    | 'resolvePluginDataDir'
    | 'verifyCandidate'
    | 'materializePackage'
    | 'isPortReserved'
    | 'execPath'
    | 'runnerPath'
    | 'platform'
    | 'env'
    | 'spawn'
    | 'connectPort'
    | 'createTerminator'
    | 'createRuntimeDir'
    | 'lstatPath'
    | 'removeRuntimeDir'
    | 'ensureDirectory'
    | 'resolveRealPath'
    | 'makeStartupToken'
    | 'nowMs'
    | 'wait'
    | 'runnerStartTimeoutMs'
    | 'tcpConnectTimeoutMs'
    | 'tcpRetryMs'
    | 'maxPortAttempts'
  >
> &
  Pick<NodeRuntimeOptions, 'reservePort' | 'hostConnectorSessionFactory'>;

interface Attempt {
  readonly child: ChildProcess;
  readonly terminator: DirectNodeRootTerminator;
  readonly init: MiniAppRunnerInitMessage;
  readonly connector?: MiniAppHostConnectorSession;
  readonly fatal: AbortController;
  readonly closed: Promise<MiniAppRuntimeExit>;
  readonly startupErrorCapture: ReturnType<typeof captureStartupError>;
  rejectClosed(reason: unknown): void;
  markShutdown(): void;
}

interface PhysicalRootCapacity {
  acquire(pluginId: string): { release(): void };
}

export function createMiniAppNodeRuntimeAdapter(
  options: NodeRuntimeOptions,
): MiniAppNodeRuntimeFactory {
  const resolved = resolveOptions(options);
  const physicalRoots = createPhysicalRootCapacity(MAX_RUNNING_PLUGIN_SERVICES);
  return {
    async prepare(input) {
      assertCapabilities(resolved, input.candidate);
      throwIfAborted(input.signal);
      const dataDir = await resolveDataDir(resolved, input.candidate.pluginId);
      const runtimeDir = await resolved.createRuntimeDir();
      try {
        const candidate = await materializeProcessCandidate({
          options: resolved,
          candidate: input.candidate,
          runtimeDir,
          signal: input.signal,
        });
        return await prepareRuntime({
          ...input,
          options: resolved,
          physicalRoots,
          candidate,
          dataDir,
          runtimeDir,
        });
      } catch (error) {
        if (isCleanupUnproven(error)) throw error;
        const failure = await selectFailureAfterCleanup(error, () =>
          resolved.removeRuntimeDir(runtimeDir),
        );
        attachStartupFailureDetail(error, failure);
        throw failure;
      }
    },
  };
}

async function materializeProcessCandidate(input: {
  readonly options: ResolvedOptions;
  readonly candidate: ProcessMiniAppCandidate;
  readonly runtimeDir: string;
  readonly signal: AbortSignal;
}): Promise<ProcessMiniAppCandidate> {
  const packageRoot = path.join(input.runtimeDir, 'package');
  await input.options.materializePackage({
    sourceRoot: input.candidate.packageRoot,
    targetRoot: packageRoot,
  });
  throwIfAborted(input.signal);
  const packageStat = await input.options.lstatPath(packageRoot);
  if (packageStat.isSymbolicLink() || !packageStat.isDirectory()) throw artifactRootError();
  const [canonicalRuntimeDir, canonicalPackageRoot] = await Promise.all([
    input.options.resolveRealPath(input.runtimeDir),
    input.options.resolveRealPath(packageRoot),
  ]);
  if (path.dirname(canonicalPackageRoot) !== canonicalRuntimeDir) throw artifactRootError();
  const candidate = { ...input.candidate, packageRoot: canonicalPackageRoot };
  if (!(await input.options.verifyCandidate(candidate))) {
    throw new MiniAppNodeRuntimeError(
      'CANDIDATE_CHANGED',
      'Mini App process artifact did not match the accepted candidate',
    );
  }
  throwIfAborted(input.signal);
  return candidate;
}

function artifactRootError(): MiniAppNodeRuntimeError {
  return new MiniAppNodeRuntimeError(
    'CANDIDATE_CHANGED',
    'Mini App process artifact root is not an owned physical directory',
  );
}

async function prepareRuntime(input: {
  readonly options: ResolvedOptions;
  readonly physicalRoots: PhysicalRootCapacity;
  readonly candidate: ProcessMiniAppCandidate;
  readonly processGeneration: string;
  readonly preferredPort?: number;
  readonly signal: AbortSignal;
  readonly onLog: Parameters<MiniAppNodeRuntimeFactory['prepare']>[0]['onLog'];
  readonly dataDir: string;
  readonly runtimeDir: string;
}): Promise<MiniAppNodeRuntime> {
  let lastError: unknown;
  for (let index = 0; index < input.options.maxPortAttempts; index += 1) {
    const port = candidatePort(input, index);
    const reservation = input.options.reservePort?.({
      pluginId: input.candidate.pluginId,
      port,
      processGeneration: input.processGeneration,
    });
    if (input.options.reservePort && !reservation) continue;
    const deadline = input.options.nowMs() + input.options.runnerStartTimeoutMs;
    let attempt: Attempt | undefined;
    try {
      attempt = await spawnAttempt(input, port);
      const readinessSignal = AbortSignal.any([input.signal, attempt.fatal.signal]);
      await waitForStarted(
        attempt,
        readinessSignal,
        Math.min(input.options.runnerStartTimeoutMs, remaining(deadline, input.options.nowMs)),
      );
      await waitForTcp({
        options: input.options,
        port,
        signal: readinessSignal,
        deadline,
      });
      attempt.startupErrorCapture.complete();
      return preparedRuntime({
        ...input,
        attempt,
        port,
        reservation,
      });
    } catch (error) {
      const failure = await selectFailureAfterCleanup(error, () =>
        cleanupFailedPreparation(attempt, reservation, error),
      );
      attachStartupFailureDetail(error, failure);
      attempt?.startupErrorCapture.attachFailure(failure, error);
      lastError = failure;
      if (!retryablePortError(failure) || index + 1 >= input.options.maxPortAttempts) throw failure;
    }
  }
  throw (
    lastError ??
    new MiniAppNodeRuntimeError('NO_CANDIDATE_PORT', 'No Host-approved port is available')
  );
}

async function cleanupFailedAttempt(
  attempt: Attempt | undefined,
  cause: unknown,
): Promise<{ readonly postStopErrors: readonly unknown[] }> {
  if (!attempt) return { postStopErrors: [] };
  return stopAttempt(attempt, cause);
}

async function cleanupFailedPreparation(
  attempt: Attempt | undefined,
  reservation: { release(): void } | undefined,
  cause: unknown,
): Promise<void> {
  const cleanup = await cleanupFailedAttempt(attempt, cause);
  if (!attempt && isCleanupUnproven(cause)) throw cause;
  const postStopErrors = [...cleanup.postStopErrors];
  try {
    reservation?.release();
  } catch (releaseError) {
    postStopErrors.push(releaseError);
  }
  throwPostStopErrors(postStopErrors);
}

async function spawnAttempt(
  input: Parameters<typeof prepareRuntime>[0],
  port: number,
): Promise<Attempt> {
  const init: MiniAppRunnerInitMessage = {
    type: 'miniapp:init',
    protocolVersion: 1,
    pluginId: input.candidate.pluginId,
    processGeneration: input.processGeneration,
    packageRoot: input.candidate.packageRoot,
    nodeEntry: input.candidate.nodeEntry,
    dataDir: input.dataDir,
    listen: { host: LOOPBACK_HOST, port },
    readiness: {
      startupToken: input.options.makeStartupToken(),
      nodeDigest: input.candidate.nodeDigest,
    },
    hostConnectorPolicy: input.candidate.hostConnectorPolicy,
  };
  const physicalRoot = input.physicalRoots.acquire(input.candidate.pluginId);
  let child: ChildProcess;
  try {
    child = input.options.spawn(input.options.execPath, [input.options.runnerPath], {
      cwd: input.candidate.packageRoot,
      detached: false,
      windowsHide: true,
      shell: false,
      env: runnerEnvironment(input.options.env),
      stdio: ['pipe', 'pipe', 'pipe', 'ipc'],
    });
  } catch (error) {
    physicalRoot.release();
    throw error;
  }
  observePhysicalRoot(child, physicalRoot);
  const startupErrorCapture = captureStartupError(child);
  const terminatorOptions = {
    platform: input.options.platform,
  } satisfies DirectNodeRootTerminatorOptions;
  let terminator: DirectNodeRootTerminator;
  try {
    terminator = input.options.createTerminator(child, terminatorOptions);
  } catch (error) {
    return proveSpawnCleanupAndThrow(
      startupErrorCapture,
      createDirectNodeRootTerminator(child, terminatorOptions),
      error,
    );
  }
  const fatal = new AbortController();
  let connector: MiniAppHostConnectorSession | undefined;
  try {
    connector = createConnectorSession(input, child, fatal);
  } catch (error) {
    return proveSpawnCleanupAndThrow(startupErrorCapture, terminator, error);
  }
  captureChildLogs(child, {
    processGeneration: input.processGeneration,
    onLog: input.onLog,
    fatal,
    connectorEnabled: Boolean(connector),
  });
  let shutdownRequested = false;
  let resolveClosed: (exit: MiniAppRuntimeExit) => void = () => undefined;
  let rejectClosed: (reason: unknown) => void = () => undefined;
  const closed = new Promise<MiniAppRuntimeExit>((resolve, reject) => {
    resolveClosed = resolve;
    rejectClosed = reject;
  });
  observeRuntimeOperation(ignoreClosedRejection(closed));
  child.once('error', (error) => fatal.abort(error));
  child.once('exit', (code, signal) => {
    const exit = { code, signal, shutdownRequested };
    if (!exit.shutdownRequested) {
      fatal.abort(
        new MiniAppNodeRuntimeError('RUNNER_EXITED', 'Runner exited without Host shutdown'),
      );
    }
    observeRuntimeOperation(connector?.close() ?? Promise.resolve());
    resolveClosed(exit);
  });
  return {
    child,
    terminator,
    init,
    ...(connector ? { connector } : {}),
    fatal,
    closed,
    startupErrorCapture,
    rejectClosed,
    markShutdown() {
      shutdownRequested = true;
    },
  };
}

async function proveSpawnCleanup(
  terminator: DirectNodeRootTerminator,
  cause: unknown,
): Promise<void> {
  let result: { readonly proven: boolean };
  try {
    result = await terminator.stop();
  } catch (cleanupError) {
    throw unproven(cleanupError);
  }
  if (!result.proven) throw unproven(cause);
}

async function proveSpawnCleanupAndThrow(
  startupErrorCapture: ReturnType<typeof captureStartupError>,
  terminator: DirectNodeRootTerminator,
  cause: unknown,
): Promise<never> {
  let failure = cause;
  try {
    await proveSpawnCleanup(terminator, cause);
  } catch (cleanupError) {
    failure = cleanupError;
  }
  startupErrorCapture.attachFailure(failure, cause);
  throw failure;
}

function createPhysicalRootCapacity(maxPluginServices: number): PhysicalRootCapacity {
  const occupants = new Map<string, symbol>();
  return {
    acquire(pluginId) {
      if (occupants.has(pluginId)) {
        throw new MiniAppNodeRuntimeError(
          'BUSY',
          'Mini App plugin service already owns a direct root',
          { busyReason: 'operation_busy' },
        );
      }
      if (occupants.size >= maxPluginServices) {
        throw new MiniAppNodeRuntimeError(
          'BUSY',
          'At most three distinct MiniApp plugin services may run concurrently',
          { busyReason: 'capacity_busy' },
        );
      }
      const identity = Symbol(pluginId);
      occupants.set(pluginId, identity);
      let released = false;
      return {
        release() {
          if (released) return;
          released = true;
          if (occupants.get(pluginId) === identity) occupants.delete(pluginId);
        },
      };
    },
  };
}

function observePhysicalRoot(child: ChildProcess, ownership: { release(): void }): void {
  let spawned = child.pid !== undefined;
  const release = () => ownership.release();
  if (
    (child.exitCode !== null && child.exitCode !== undefined) ||
    (child.signalCode !== null && child.signalCode !== undefined)
  ) {
    release();
    return;
  }
  child.once('spawn', () => {
    spawned = true;
  });
  child.once('error', () => {
    if (!spawned && child.pid === undefined) release();
  });
  child.once('exit', release);
}

async function ignoreClosedRejection(closed: Promise<MiniAppRuntimeExit>): Promise<void> {
  try {
    await closed;
  } catch {
    // The Supervisor observes terminal cleanup proof through this same promise.
  }
}

function createConnectorSession(
  input: Parameters<typeof prepareRuntime>[0],
  child: ChildProcess,
  fatal: AbortController,
): MiniAppHostConnectorSession | undefined {
  if (input.candidate.hostConnectorPolicy.kind !== 'allowlist') return undefined;
  if (!child.stdout || !child.stdin || !input.options.hostConnectorSessionFactory) {
    throw new MiniAppNodeRuntimeError(
      'HOST_CONNECTOR_UNAVAILABLE',
      'Host Connector stdio or session factory is unavailable',
    );
  }
  return input.options.hostConnectorSessionFactory.create({
    pluginId: input.candidate.pluginId,
    processGeneration: input.processGeneration,
    providers: input.candidate.hostConnectorPolicy.providers,
    request: child.stdout,
    response: child.stdin,
    onFatal: (error) => fatal.abort(error),
  });
}

function captureChildLogs(
  child: ChildProcess,
  options: {
    readonly processGeneration: string;
    readonly onLog: Parameters<MiniAppNodeRuntimeFactory['prepare']>[0]['onLog'];
    readonly fatal: AbortController;
    readonly connectorEnabled: boolean;
  },
): void {
  child.on('message', (raw: unknown) => {
    if (isRunnerErrorMessage(raw)) {
      options.fatal.abort(
        runnerFailure(raw.code, `Mini App runner reported ${raw.code}`, raw.errorText),
      );
      return;
    }
    if (!isRunnerLogMessage(raw)) return;
    options.onLog(
      sanitizeMiniAppRuntimeLogEvent({
        processGeneration: options.processGeneration,
        level: raw.level,
        message: raw.message,
        byteLength: Buffer.byteLength(raw.message),
        fieldKeys: raw.fieldKeys,
      }),
    );
  });
  child.stderr?.on('data', (chunk: Buffer | string) => {
    const bytes = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
    options.onLog(
      sanitizeMiniAppRuntimeLogEvent({
        processGeneration: options.processGeneration,
        level: 'error',
        message: bytes.toString('utf8').trim(),
        byteLength: bytes.byteLength,
        fieldKeys: [],
      }),
    );
  });
  if (!options.connectorEnabled) {
    child.stdout?.once('data', () => {
      options.fatal.abort(
        new MiniAppNodeRuntimeError(
          'HOST_CONNECTOR_PROTOCOL_VIOLATION',
          'Mini App wrote to reserved stdout',
        ),
      );
    });
  }
}

function waitForStarted(attempt: Attempt, signal: AbortSignal, timeoutMs: number): Promise<void> {
  throwIfAborted(signal);
  return new Promise((resolve, reject) => {
    let settled = false;
    const finish = (error?: unknown) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal.removeEventListener('abort', onAbort);
      attempt.child.removeListener('message', onMessage);
      attempt.child.removeListener('error', onError);
      attempt.child.removeListener('exit', onExit);
      if (error) reject(error);
      else resolve();
    };
    const onAbort = () => finish(signal.reason);
    const onError = (error: Error) => finish(error);
    const onExit = () =>
      finish(new MiniAppNodeRuntimeError('RUNNER_EXITED', 'Runner exited before readiness'));
    const onMessage = (raw: unknown) => {
      if (isRunnerErrorMessage(raw)) {
        finish(runnerFailure(raw.code, 'Runner rejected MiniApp entry', raw.errorText));
      } else if (isRunnerStartedMessage(raw)) {
        const matches =
          raw.pluginId === attempt.init.pluginId &&
          raw.processGeneration === attempt.init.processGeneration &&
          raw.readiness.startupToken === attempt.init.readiness.startupToken &&
          raw.readiness.nodeDigest === attempt.init.readiness.nodeDigest;
        finish(
          matches
            ? undefined
            : new MiniAppNodeRuntimeError(
                'RUNNER_IDENTITY_MISMATCH',
                'Runner identity did not match the candidate',
              ),
        );
      }
    };
    const timer = setTimeout(
      () => finish(new MiniAppNodeRuntimeError('READINESS_TIMEOUT', 'Runner start timed out')),
      Math.max(1, timeoutMs),
    );
    timer.unref();
    signal.addEventListener('abort', onAbort, { once: true });
    attempt.child.on('message', onMessage);
    attempt.child.once('error', onError);
    attempt.child.once('exit', onExit);
    try {
      attempt.connector?.startHandshake();
      attempt.child.send?.(attempt.init);
    } catch (error) {
      finish(error);
    }
  });
}

async function waitForTcp(input: {
  readonly options: ResolvedOptions;
  readonly port: number;
  readonly signal: AbortSignal;
  readonly deadline: number;
}): Promise<void> {
  let lastError: unknown;
  for (;;) {
    throwIfAborted(input.signal);
    try {
      await input.options.connectPort({
        host: LOOPBACK_HOST,
        port: input.port,
        timeoutMs: Math.min(
          input.options.tcpConnectTimeoutMs,
          remaining(input.deadline, input.options.nowMs),
        ),
        signal: input.signal,
      });
      return;
    } catch (error) {
      lastError = error;
    }
    const delay = Math.min(
      input.options.tcpRetryMs,
      remaining(input.deadline, input.options.nowMs),
    );
    await input.options.wait(delay, input.signal);
    if (input.options.nowMs() >= input.deadline) {
      throw new MiniAppNodeRuntimeError('READINESS_TIMEOUT', 'TCP readiness timed out', {
        cause: lastError,
      });
    }
  }
}

function preparedRuntime(
  input: Parameters<typeof prepareRuntime>[0] & {
    readonly attempt: Attempt;
    readonly port: number;
    readonly reservation?: { release(): void };
  },
): MiniAppNodeRuntime {
  let stopPromise: Promise<{ readonly proven: boolean }> | undefined;
  let cleanupPromise: Promise<{ readonly proven: boolean }> | undefined;
  let removeRuntimeDirPromise: Promise<void> | undefined;
  let reservationReleased = false;
  const releaseReservation = () => {
    if (reservationReleased) return;
    input.reservation?.release();
    reservationReleased = true;
  };
  input.attempt.child.once('exit', releaseReservation);
  const removeRuntimeDir = () => {
    removeRuntimeDirPromise ??= input.options.removeRuntimeDir(input.runtimeDir);
    return removeRuntimeDirPromise;
  };
  input.attempt.child.once('exit', () => {
    observeRuntimeOperation(removeRuntimeDir());
  });
  const cleanup = () => {
    cleanupPromise ??= (async () => {
      const result = await stopAttempt(input.attempt);
      const postStopErrors = [...result.postStopErrors];
      try {
        releaseReservation();
      } catch (releaseError) {
        postStopErrors.push(releaseError);
      }
      try {
        await removeRuntimeDir();
      } catch (removeError) {
        postStopErrors.push(removeError);
      }
      throwPostStopErrors(postStopErrors);
      return { proven: true };
    })();
    return cleanupPromise;
  };
  input.attempt.fatal.signal.addEventListener(
    'abort',
    () => {
      observeRuntimeOperation(cleanupAfterFatal(cleanup, input.attempt.rejectClosed));
    },
    { once: true },
  );
  return {
    processGeneration: input.processGeneration,
    nodeDigest: input.candidate.nodeDigest,
    port: input.port,
    origin: `http://${LOOPBACK_HOST}:${input.port}`,
    ...(input.attempt.connector ? { hostConnectorSession: input.attempt.connector } : {}),
    closed: input.attempt.closed,
    stop() {
      input.attempt.markShutdown();
      stopPromise ??= cleanup();
      return stopPromise;
    },
  };
}

async function cleanupAfterFatal(
  cleanup: () => Promise<unknown>,
  rejectClosed: (reason: unknown) => void,
): Promise<void> {
  try {
    await cleanup();
  } catch (error) {
    if (isCleanupUnproven(error)) rejectClosed(error);
  }
}

function observeRuntimeOperation(operation: Promise<unknown>): void {
  const observed = settleRuntimeOperation(operation, () => runtimeObservations.delete(observed));
  runtimeObservations.add(observed);
}

async function settleRuntimeOperation(
  operation: Promise<unknown>,
  complete: () => void,
): Promise<void> {
  try {
    await operation;
  } catch {
    // Runtime exit and cleanup proof are observed through the owning lifecycle state.
  } finally {
    complete();
  }
}

async function stopAttempt(
  attempt: Attempt,
  cleanupCause?: unknown,
): Promise<{ readonly proven: true; readonly postStopErrors: readonly unknown[] }> {
  const postStopErrors: unknown[] = [];
  try {
    await attempt.connector?.retire();
  } catch (error) {
    postStopErrors.push(error);
  }
  try {
    attempt.child.send?.({ type: 'miniapp:stop' });
  } catch {
    // Direct-root exit proof remains authoritative.
  }
  let result: { readonly proven: boolean };
  try {
    result = await attempt.terminator.stop();
  } catch (error) {
    throw unproven(error);
  }
  if (!result.proven) {
    throw unproven(
      cleanupCause ??
        new MiniAppNodeRuntimeError(
          'NODE_ROOT_TERMINATION_UNPROVEN',
          'Mini App direct Node root termination could not be proven',
        ),
    );
  }
  return { proven: true, postStopErrors };
}

function resolveOptions(options: NodeRuntimeOptions): ResolvedOptions {
  // Default to a sanitized env so the miniapp host-runner child never
  // inherits `MAVIS_ACCESS_TOKEN` / `MATRIX_TOKEN` / `*_API_KEY` from the
  // desktop parent via `process.env`. The whitelist in `runnerEnvironment`
  // narrows this further (PATH, HOME, TMP, …) before the actual spawn, but
  // scrubbing here ensures the wider env is never exposed even if the
  // whitelist drifts. Test override paths can still pass `options.env`
  // explicitly.
  const defaults = {
    execPath: process.execPath,
    runnerPath: fileURLToPath(new URL('./host-runner.js', import.meta.url)),
    platform: process.platform,
    env: sanitizeBashSubprocessEnv(process.env, { mode: 'scrub' }).env,
    spawn: nodeSpawn,
    connectPort: connectMiniAppPort,
    createTerminator: createDirectNodeRootTerminator,
    createRuntimeDir: () => mkdtemp(path.join(os.tmpdir(), 'mavis-miniapp-')),
    lstatPath: lstat,
    removeRuntimeDir: async (directory: string) => {
      await rm(directory, { recursive: true, force: true });
    },
    ensureDirectory: async (directory: string) => {
      await mkdir(directory, { recursive: true });
    },
    resolveRealPath: realpath,
    makeStartupToken: randomUUID,
    nowMs: Date.now,
    wait: defaultWait,
    runnerStartTimeoutMs: 10_000,
    tcpConnectTimeoutMs: 500,
    tcpRetryMs: 50,
    maxPortAttempts: 3,
  };
  const defined = Object.fromEntries(
    Object.entries(options).filter((entry) => entry[1] !== undefined),
  );
  return {
    ...defaults,
    ...defined,
    resolvePluginDataDir: options.resolvePluginDataDir,
    verifyCandidate: options.verifyCandidate,
    materializePackage: options.materializePackage,
    isPortReserved: options.isPortReserved,
  } as ResolvedOptions;
}

function assertCapabilities(options: ResolvedOptions, candidate: ProcessMiniAppCandidate): void {
  if (candidate.hostConnectorPolicy.kind === 'allowlist' && !options.hostConnectorSessionFactory) {
    throw new MiniAppNodeRuntimeError(
      'HOST_CONNECTOR_UNAVAILABLE',
      'Host Connector session is unavailable',
    );
  }
}

async function resolveDataDir(options: ResolvedOptions, pluginId: string): Promise<string> {
  const requested = await options.resolvePluginDataDir(pluginId);
  if (!path.isAbsolute(requested))
    throw new MiniAppNodeRuntimeError(
      'PLUGIN_DATA_DIR_INVALID',
      'Plugin data directory must be absolute',
    );
  await options.ensureDirectory(requested);
  return options.resolveRealPath(requested);
}

function candidatePort(input: Parameters<typeof prepareRuntime>[0], index: number): number {
  const preferred = input.preferredPort;
  const digest = createHash('sha256').update(input.candidate.pluginId).digest();
  const base =
    preferred !== undefined && preferred >= PORT_MIN && preferred <= PORT_MAX
      ? preferred
      : PORT_MIN + (digest.readUInt32BE(0) % PORT_COUNT);
  let available = 0;
  for (let offset = 0; offset < PORT_COUNT; offset += 1) {
    const port = PORT_MIN + ((base - PORT_MIN + offset) % PORT_COUNT);
    if (input.options.isPortReserved({ pluginId: input.candidate.pluginId, port })) continue;
    if (available === index) return port;
    available += 1;
  }
  throw new MiniAppNodeRuntimeError('NO_CANDIDATE_PORT', 'No Host-approved port is available');
}

function runnerEnvironment(env: NodeJS.ProcessEnv): NodeJS.ProcessEnv {
  const result: NodeJS.ProcessEnv = { ELECTRON_RUN_AS_NODE: '1' };
  for (const key of [
    'PATH',
    'Path',
    'SystemRoot',
    'WINDIR',
    'TEMP',
    'TMP',
    'TMPDIR',
    'HOME',
    'USERPROFILE',
    'LANG',
    'LC_ALL',
  ]) {
    if (env[key] !== undefined) result[key] = env[key];
  }
  return result;
}

/**
 * Build the env passed to the host-runner child.
 *
 * @internal Not part of the public API; exported for testability of the
 * env-scrubbing contract without forcing tests to drive the full prepare
 * flow (filesystem state, port reservation, IPC handshake).
 */
export function buildHostRunnerEnv(inputEnv: NodeJS.ProcessEnv = process.env): NodeJS.ProcessEnv {
  const { env } = sanitizeBashSubprocessEnv(inputEnv, { mode: 'scrub' });
  return runnerEnvironment(env);
}

function connectMiniAppPort(input: TcpConnectInput): Promise<void> {
  if (input.signal.aborted) return Promise.reject(input.signal.reason);
  return new Promise((resolve, reject) => {
    const socket = createConnection({ host: input.host, port: input.port });
    let settled = false;
    const finish = (error?: unknown) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      input.signal.removeEventListener('abort', onAbort);
      socket.removeListener('connect', onConnect);
      socket.removeListener('error', onError);
      socket.destroy();
      if (error) reject(error);
      else resolve();
    };
    const onConnect = () => finish();
    const onError = (error: Error) => finish(error);
    const onAbort = () => finish(input.signal.reason);
    const timer = setTimeout(
      () => finish(new MiniAppNodeRuntimeError('TCP_CONNECT_TIMEOUT', 'TCP connect timed out')),
      Math.max(1, input.timeoutMs),
    );
    timer.unref();
    socket.once('connect', onConnect);
    socket.once('error', onError);
    input.signal.addEventListener('abort', onAbort, { once: true });
  });
}

function remaining(deadline: number, now: () => number): number {
  const value = deadline - now();
  if (value <= 0)
    throw new MiniAppNodeRuntimeError('READINESS_TIMEOUT', 'Readiness deadline expired');
  return value;
}

function defaultWait(ms: number, signal: AbortSignal): Promise<void> {
  if (signal.aborted) return Promise.reject(signal.reason);
  return new Promise((resolve, reject) => {
    const timer = setTimeout(resolve, ms);
    timer.unref();
    signal.addEventListener(
      'abort',
      () => {
        clearTimeout(timer);
        reject(signal.reason);
      },
      { once: true },
    );
  });
}

function throwIfAborted(signal: AbortSignal): void {
  if (signal.aborted) throw signal.reason;
}

function retryablePortError(error: unknown): boolean {
  return errorCode(error) === 'EADDRINUSE';
}

function errorCode(error: unknown): string {
  return isRecord(error) && typeof error.code === 'string' ? error.code : 'RUNTIME_START_FAILED';
}

function isCleanupUnproven(error: unknown): error is MiniAppCleanupUnprovenError {
  return error instanceof MiniAppCleanupUnprovenError;
}

function throwPostStopErrors(errors: readonly unknown[]): void {
  if (errors.length === 1) {
    const [error] = errors;
    if (error && (typeof error === 'object' || typeof error === 'function')) {
      markMiniAppRootTerminationProven(error);
      throw error;
    }
    const aggregate = new AggregateError(errors, 'Mini App post-stop cleanup failed');
    markMiniAppRootTerminationProven(aggregate);
    throw aggregate;
  }
  if (errors.length > 1) {
    const aggregate = new AggregateError(errors, 'Mini App post-stop cleanup failed');
    markMiniAppRootTerminationProven(aggregate);
    throw aggregate;
  }
}

function unproven(cause: unknown): MiniAppCleanupUnprovenError {
  return new MiniAppCleanupUnprovenError(
    'Mini App direct Node root termination could not be proven',
    { cause },
  );
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function isRunnerStartedMessage(value: unknown): value is {
  readonly type: 'miniapp:started';
  readonly pluginId: string;
  readonly processGeneration: string;
  readonly readiness: { readonly startupToken: string; readonly nodeDigest: string };
} {
  if (!isRecord(value) || value.type !== 'miniapp:started' || !isRecord(value.readiness)) {
    return false;
  }
  return (
    typeof value.pluginId === 'string' &&
    typeof value.processGeneration === 'string' &&
    typeof value.readiness.startupToken === 'string' &&
    typeof value.readiness.nodeDigest === 'string'
  );
}

function isRunnerLogMessage(value: unknown): value is {
  readonly type: 'miniapp:log';
  readonly level: 'debug' | 'info' | 'warn' | 'error';
  readonly message: string;
  readonly fieldKeys: readonly string[];
} {
  if (!isRecord(value) || value.type !== 'miniapp:log') return false;
  return (
    (value.level === 'debug' ||
      value.level === 'info' ||
      value.level === 'warn' ||
      value.level === 'error') &&
    typeof value.message === 'string' &&
    Array.isArray(value.fieldKeys) &&
    value.fieldKeys.every((field) => typeof field === 'string')
  );
}
