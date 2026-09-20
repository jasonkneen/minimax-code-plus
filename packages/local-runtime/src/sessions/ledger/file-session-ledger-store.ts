import { Buffer } from 'node:buffer';
import { appendFile as asyncAppendFile } from 'node:fs/promises';
import { randomUUID } from 'node:crypto';

import {
  LOCAL_SESSION_LEDGER_SCHEMA_VERSION,
  type AppendLocalSessionLedgerResult,
  type LocalSessionLedgerEvent,
  type LocalSessionLedgerEventDraft,
  type LocalSessionLedgerWatermark,
} from './ledger-event.js';
import {
  MAX_LEDGER_LINE_BYTES,
  assertLedgerCursorOffsetSync,
  compareLedgerEvents,
  readLedgerWatermarkSync,
  streamLedgerEvents,
  type ParsedLedgerEventWithOffset,
} from './ledger-read.js';
import type { MetricsClient } from '../../common/metrics.js';
import { logger } from '../../common/logger.js';
import { type DataDirInput, type DatabaseLike, withLocalRuntimeDb } from '../../persistence/db.js';
import { resolveV2DirectoryContract } from '../../persistence/layout/v2-paths.js';
import {
  appendV2SessionDisplayTranscriptSync,
  deleteV2SessionArtifactsSync,
  ensureV2SessionArtifactManifestSync,
  ensureV2ArtifactParentDirSync,
  resolveV2SessionArtifactPathsSync,
} from '../../persistence/layout/v2-session-artifacts.js';
import {
  ledgerFileSizeSync,
  logLedgerMetricFailure,
  needsJsonlLineBoundarySync,
  recoverFailedLedgerAppendSync,
  runInTransaction,
} from './ledger-append-recovery.js';

export { LocalSessionLedgerCommitUncertainError } from './ledger-append-recovery.js';

export interface LocalSessionLedgerStore {
  append(
    sessionId: string,
    events: readonly LocalSessionLedgerEventDraft[],
  ): Promise<AppendLocalSessionLedgerResult>;
  readEvents(sessionId: string): AsyncIterable<LocalSessionLedgerEvent>;
  readEventsAfter(
    sessionId: string,
    cursor: LocalSessionLedgerWatermark,
  ): AsyncIterable<LocalSessionLedgerEvent>;
  getWatermark(sessionId: string): Promise<LocalSessionLedgerWatermark | undefined>;
  deleteSession(sessionId: string): Promise<void>;
}

export interface FileSessionLedgerStoreOptions {
  nowMs?: () => number;
  makeEventId?: (sessionId: string, kind: string, seq: number) => string;
  metricsClient?: MetricsClient;
}

interface LedgerWatermarkRow {
  last_seq?: unknown;
  last_event_id?: unknown;
  updated_at_ms?: unknown;
  last_byte_offset?: unknown;
}

/**
 * Lightweight watermark projection carried in SQLite (table
 * `local_runtime_ledger_watermarks`). The trailing byte offset lets the hot
 * append path skip the whole-file scan that used to run inside the SQLite
 * IMMEDIATE transaction; recovery is the only case that still falls back to
 * `readLedgerWatermarkSync`.
 */
interface LedgerWatermarkRecord {
  lastSeq: number;
  lastEventId: string;
  updatedAtMs: number;
  lastByteOffset: number | null;
}

export class FileSessionLedgerStore implements LocalSessionLedgerStore {
  private readonly nowMs: () => number;
  private readonly makeEventId: (sessionId: string, kind: string, seq: number) => string;
  private readonly metricsClient?: MetricsClient;
  private readonly appendChains = new Map<string, Promise<void>>();

  constructor(
    private readonly dataDir: DataDirInput,
    options: FileSessionLedgerStoreOptions = {},
  ) {
    this.nowMs = options.nowMs ?? (() => Date.now());
    this.makeEventId = options.makeEventId ?? defaultEventId;
    this.metricsClient = options.metricsClient;
  }

  async append(
    sessionId: string,
    drafts: readonly LocalSessionLedgerEventDraft[],
  ): Promise<AppendLocalSessionLedgerResult> {
    if (drafts.length === 0) {
      const watermark = (await this.getWatermark(sessionId)) ?? {
        sessionId,
        lastSeq: 0,
        lastEventId: '',
        updatedAtMs: this.nowMs(),
      };
      return { events: [], watermark };
    }
    return this.withSessionAppendLock(sessionId, async () => {
      // Duration measured from inside the lock: actual write work, excluding lock wait.
      const startMs = this.nowMs();
      let committedResult: AppendLocalSessionLedgerResult | undefined;
      let ledgerPath: string | undefined;
      let preAppendSize: number | undefined;
      let appendContents: string | undefined;
      try {
        // The SQLite IMMEDIATE transaction only does the bookkeeping work
        // (read the cached watermark, allocate seq ids, write the new
        // watermark row). The actual file append happens AFTER the
        // transaction commits, so the writer lock is never held during the
        // sync file scan/write.
        const result = withLocalRuntimeDb(this.dataDir, (db) =>
          runInTransaction(db, () => {
            const artifactPaths = ensureV2SessionArtifactManifestSync(this.dataDir, sessionId, {
              createdAtMs: inferArtifactCreatedAtMs(drafts, this.nowMs()),
              updatedAtMs: this.nowMs(),
              source: inferArtifactSource(drafts),
            });
            const managedRoot = resolveV2DirectoryContract(this.dataDir).root;
            ensureV2ArtifactParentDirSync(artifactPaths.ledger, artifactPaths.sessionDir, managedRoot);
            // O(1) read: if the cached watermark matches the file's true
            // trailing offset, skip the file scan entirely. Only call
            // `readLedgerWatermarkSync` on the recovery path (cold start,
            // crash between SQLite commit and file append, schema drift).
            const { fileWatermark, sqliteWatermark } = resolveAppendWatermark(
              db,
              artifactPaths.ledger,
              sessionId,
            );
            const events = this.allocateEvents(
              sessionId,
              drafts,
              sqliteWatermark,
              fileWatermark,
            );
            const boundary = needsJsonlLineBoundarySync(artifactPaths.ledger) ? '\n' : '';
            const contents = `${boundary}${events.map((event) => JSON.stringify(event)).join('\n')}\n`;
            const size = ledgerFileSizeSync(artifactPaths.ledger);
            const byteOffset = size + Buffer.byteLength(contents, 'utf-8');
            const last = events[events.length - 1]!;
            const appendResult: AppendLocalSessionLedgerResult = {
              events,
              watermark: {
                sessionId,
                lastSeq: last.seq,
                lastEventId: last.eventId,
                updatedAtMs: last.createdAtMs,
                byteOffset,
              },
            };
            // Persist the new watermark INSIDE the transaction so the next
            // append sees the updated trailing offset without a file scan.
            upsertLedgerWatermark(db, sessionId, appendResult.watermark, byteOffset);
            committedResult = appendResult;
            ledgerPath = artifactPaths.ledger;
            preAppendSize = size;
            appendContents = contents;
            appendDisplayTranscriptBestEffort(artifactPaths, events, managedRoot);
            return committedResult;
          }),
        );
        // File append is intentionally outside the SQLite writer lock: a
        // multi-MiB `fs.appendFile` no longer blocks every other writer
        // in the process (it runs on libuv's worker pool). The
        // `withSessionAppendLock` guard keeps two appenders to the same
        // session serialized; the SQLite watermark row carries the
        // trailing offset, so the next append picks up where we wrote —
        // even after a crash that interrupts the file append (recovery
        // converges the row via `readLedgerWatermarkSync`).
        if (ledgerPath !== undefined && appendContents !== undefined) {
          try {
            await asyncAppendFile(ledgerPath, appendContents, { encoding: 'utf-8' });
          } catch (error) {
            if (
              preAppendSize === undefined ||
              !recoverFailedLedgerAppendSync(ledgerPath, preAppendSize, appendContents, error)
            ) {
              throw error;
            }
          }
        }
        this.recordAppendMetrics(sessionId, 'ok', startMs);
        return result;
      } catch (err) {
        // `committedResult` is set only when the SQLite transaction
        // commits — i.e. the SQLite state already records the new
        // watermark. Recovery will resync on next open. Returning the
        // committed result preserves the original contract: a committed
        // append is never rolled back just because the post-commit file
        // append threw after recovery failed.
        if (committedResult) {
          logger.warn(
            {
              session_id: sessionId,
              error_type: err instanceof Error ? err.name : typeof err,
            },
            '[file-session-ledger] allocator transaction committed but file append failed; recovery will resync on next open',
          );
          this.recordAppendMetrics(sessionId, 'ok', startMs);
          return committedResult;
        }
        this.recordAppendMetrics(sessionId, 'error', startMs);
        throw err;
      }
    });
  }

  async *readEvents(sessionId: string): AsyncIterable<LocalSessionLedgerEvent> {
    // Stream the ledger line-by-line instead of materializing the whole file
    // into a single JS string. A heavy session's ledger (many large tool
    // outputs / image / PPT dumps) can exceed V8's max string length
    // (0x1fffffe8, ~512MB); `readFile(..., 'utf-8')` on such a file throws
    // `RangeError: Cannot create a string longer than 0x1fffffe8`, which used
    // to turn one oversized session into a hard history-load failure.
    const events: LocalSessionLedgerEvent[] = [];
    for await (const { event } of streamLedgerEvents(
      resolveLocalSessionLedgerPath(this.dataDir, sessionId),
      sessionId,
    )) {
      events.push(event);
    }
    events.sort(compareLedgerEvents);
    for (const event of events) yield event;
  }

  async *readEventsAfter(
    sessionId: string,
    cursor: LocalSessionLedgerWatermark,
  ): AsyncIterable<LocalSessionLedgerEvent> {
    if (cursor.byteOffset !== undefined) {
      const ledgerPath = resolveLocalSessionLedgerPath(this.dataDir, sessionId);
      assertLedgerCursorOffsetSync(ledgerPath, sessionId, cursor);
      for await (const { event } of streamLedgerEvents(
        ledgerPath,
        sessionId,
        MAX_LEDGER_LINE_BYTES,
        cursor.byteOffset,
      )) {
        if (event.seq > cursor.lastSeq) yield event;
      }
      return;
    }
    for await (const event of this.readEvents(sessionId)) {
      if (event.seq > cursor.lastSeq) yield event;
    }
  }

  async getWatermark(sessionId: string): Promise<LocalSessionLedgerWatermark | undefined> {
    let last: ParsedLedgerEventWithOffset | undefined;
    for await (const parsed of streamLedgerEvents(
      resolveLocalSessionLedgerPath(this.dataDir, sessionId),
      sessionId,
    )) {
      if (!last || compareLedgerEvents(parsed.event, last.event) > 0) last = parsed;
    }
    if (!last) return undefined;
    return {
      sessionId,
      lastSeq: last.event.seq,
      lastEventId: last.event.eventId,
      updatedAtMs: last.event.createdAtMs,
      byteOffset: last.byteOffset,
    };
  }

  async deleteSession(sessionId: string): Promise<void> {
    await deleteLocalSessionLedger(this.dataDir, sessionId);
    withLocalRuntimeDb(this.dataDir, (db) => {
      db.prepare('DELETE FROM local_runtime_ledger_watermarks WHERE session_id = ?').run(sessionId);
    });
  }

  private allocateEvents(
    sessionId: string,
    drafts: readonly LocalSessionLedgerEventDraft[],
    sqliteWatermark: LedgerWatermarkRecord | null,
    fileWatermark?: LocalSessionLedgerWatermark,
  ): LocalSessionLedgerEvent[] {
    // Hot path: the SQLite row is authoritative when its trailing offset
    // matches the file's true size. The reconciliation step in
    // `resolveAppendWatermark` keeps the two in lockstep, so a normal
    // append sees `sqliteWatermark` and `fileWatermark` agree on `lastSeq`.
    // We still take `max(sqlite, file)` defensively in case the trailing
    // offset is stale (older binary wrote the row before the column
    // existed, manual truncation, etc.).
    const sqliteSeq =
      sqliteWatermark && Number.isInteger(sqliteWatermark.lastSeq)
        ? sqliteWatermark.lastSeq
        : 0;
    let nextSeq = Math.max(sqliteSeq, fileWatermark?.lastSeq ?? 0) + 1;
    const events = drafts.map((draft) => {
      const seq = nextSeq++;
      return {
        ...draft,
        schemaVersion: LOCAL_SESSION_LEDGER_SCHEMA_VERSION,
        eventId: this.makeEventId(sessionId, draft.kind, seq),
        seq,
        createdAtMs: this.nowMs(),
      } as LocalSessionLedgerEvent;
    });
    return events;
  }

  private async withSessionAppendLock<T>(sessionId: string, fn: () => Promise<T>): Promise<T> {
    const previous = this.appendChains.get(sessionId) ?? Promise.resolve();
    let release!: () => void;
    const current = new Promise<void>((resolve) => {
      release = resolve;
    });
    const chain = previous.then(
      () => current,
      () => current,
    );
    this.appendChains.set(sessionId, chain);
    await previous.catch(() => undefined);
    try {
      return await fn();
    } finally {
      release();
      if (this.appendChains.get(sessionId) === chain) this.appendChains.delete(sessionId);
    }
  }

  private recordAppendMetrics(sessionId: string, status: 'ok' | 'error', startMs: number): void {
    try {
      this.metricsClient?.counter('session_ledger_append_total', 1, { status });
    } catch (error) {
      logLedgerMetricFailure(sessionId, 'session_ledger_append_total', error);
    }
    if (status === 'error') return;
    try {
      this.metricsClient?.histogram('session_ledger_append_duration_ms', this.nowMs() - startMs);
    } catch (error) {
      logLedgerMetricFailure(sessionId, 'session_ledger_append_duration_ms', error);
    }
  }
}

export function resolveLocalSessionLedgerPath(dataDir: DataDirInput, sessionId: string): string {
  return resolveV2SessionArtifactPathsSync(dataDir, sessionId).ledger;
}

export async function deleteLocalSessionLedger(
  dataDir: DataDirInput,
  sessionId: string,
): Promise<void> {
  deleteV2SessionArtifactsSync(dataDir, sessionId);
}

function appendDisplayTranscriptBestEffort(
  artifactPaths: ReturnType<typeof resolveV2SessionArtifactPathsSync>,
  events: readonly LocalSessionLedgerEvent[],
  managedRoot: string,
): void {
  try {
    appendV2SessionDisplayTranscriptSync(
      artifactPaths,
      events.flatMap((event) =>
        event.kind === 'message.display_upserted'
          ? [
              {
                sessionId: event.sessionId,
                seq: event.seq,
                eventId: event.eventId,
                createdAtMs: event.createdAtMs,
                ...(event.turnId ? { turnId: event.turnId } : {}),
                message: event.message,
              },
            ]
          : [],
      ),
      { managedRoot },
    );
  } catch {
    // The canonical event was already committed to the ledger. Display JSONL is a
    // human-readable mirror, so it must not turn a successful ledger append into
    // a retry that would duplicate canonical events.
  }
}

function inferArtifactCreatedAtMs(
  drafts: readonly LocalSessionLedgerEventDraft[],
  fallback: number,
): number {
  for (const draft of drafts) {
    if (
      (draft.kind === 'session.created' || draft.kind === 'session.metadata_updated') &&
      typeof draft.record.createdAtMs === 'number'
    ) {
      return draft.record.createdAtMs;
    }
  }
  return fallback;
}

function inferArtifactSource(
  drafts: readonly LocalSessionLedgerEventDraft[],
): 'local-runtime' | 'legacy-migration' {
  return drafts.some((draft) => draft.kind === 'session.metadata_updated')
    ? 'legacy-migration'
    : 'local-runtime';
}

function sanitizeLedgerPathSegment(value: string): string {
  return `session_${Buffer.from(value || 'unknown-session', 'utf-8').toString('base64url')}`;
}

function defaultEventId(sessionId: string, kind: string, seq: number): string {
  return `evt_${sanitizeLedgerPathSegment(sessionId)}_${sanitizeLedgerPathSegment(kind)}_${seq}_${randomSuffix()}`;
}

function randomSuffix(): string {
  return randomUUID().replace(/-/g, '');
}

/**
 * Read the cached watermark row from SQLite (O(1), single-row lookup) and
 * decide whether the file scan is still needed. Returns both pieces so the
 * caller can pass them into `allocateEvents`:
 *  - `sqliteWatermark` is the row as read, or `null` if no row exists.
 *  - `fileWatermark` is only set on the recovery path (mismatch / first
 *    append for a session whose file already has events).
 *
 * When the file scan runs, the SQLite row is back-filled in the same
 * transaction so subsequent appends skip the scan. The write is idempotent.
 */
function resolveAppendWatermark(
  db: DatabaseLike,
  ledgerPath: string,
  sessionId: string,
): { fileWatermark?: LocalSessionLedgerWatermark; sqliteWatermark: LedgerWatermarkRecord | null } {
  const sqliteRow = readLedgerWatermarkRow(db, sessionId);
  if (sqliteRow === null) {
    // No row yet. If the file is non-empty we still want to find the
    // trailing offset (e.g. session was migrated from an older binary,
    // or the row was lost to disk corruption). Once we sync the row the
    // next append takes the O(1) path.
    const fileWatermark = ledgerFileSizeSync(ledgerPath) === 0
      ? undefined
      : readLedgerWatermarkSync(ledgerPath, sessionId);
    if (fileWatermark) {
      upsertLedgerWatermark(db, sessionId, fileWatermark, fileWatermark.byteOffset ?? null);
    }
    return { fileWatermark, sqliteWatermark: null };
  }
  const fileSize = ledgerFileSizeSync(ledgerPath);
  if (
    sqliteRow.lastByteOffset !== null &&
    sqliteRow.lastByteOffset === fileSize
  ) {
    // Hot path: the cached trailing offset matches the file's true size.
    // Trust the SQLite row, no scan required.
    return { sqliteWatermark: sqliteRow };
  }
  // Recovery: cached offset is missing or disagrees with the file. Either
  // (a) the row was written before v34 (last_byte_offset IS NULL), (b) the
  // process crashed between the SQLite commit and the file append leaving
  // SQLite ahead of the file, or (c) the file was truncated/rewound out of
  // band. In every case, rebuild the row from the file so subsequent
  // appends converge.
  const fileWatermark =
    fileSize === 0
      ? undefined
      : readLedgerWatermarkSync(ledgerPath, sessionId);
  if (fileWatermark) {
    upsertLedgerWatermark(db, sessionId, fileWatermark, fileWatermark.byteOffset ?? null);
    return { fileWatermark, sqliteWatermark: readLedgerWatermarkRow(db, sessionId) };
  }
  // File is empty (or vanished): SQLite row was for events that no longer
  // exist on disk. Reset the row to a zero-state so subsequent appends
  // start from seq=1. Keep the lastByteOffset aligned with the empty file.
  upsertLedgerWatermark(
    db,
    sessionId,
    {
      lastSeq: 0,
      lastEventId: '',
      updatedAtMs: sqliteRow.updatedAtMs,
    },
    fileSize,
  );
  return { sqliteWatermark: null };
}

function readLedgerWatermarkRow(
  db: DatabaseLike,
  sessionId: string,
): LedgerWatermarkRecord | null {
  const row = db
    .prepare(
      `SELECT last_seq, last_event_id, updated_at_ms, last_byte_offset
       FROM local_runtime_ledger_watermarks
       WHERE session_id = ?`,
    )
    .get(sessionId) as LedgerWatermarkRow | undefined;
  if (!row) return null;
  const lastSeq = Number(row.last_seq);
  const lastByteOffsetRaw = row.last_byte_offset;
  return {
    lastSeq: Number.isInteger(lastSeq) ? lastSeq : 0,
    lastEventId: typeof row.last_event_id === 'string' ? row.last_event_id : '',
    updatedAtMs:
      typeof row.updated_at_ms === 'number' && Number.isFinite(row.updated_at_ms)
        ? row.updated_at_ms
        : 0,
    lastByteOffset:
      typeof lastByteOffsetRaw === 'number' && Number.isFinite(lastByteOffsetRaw)
        ? lastByteOffsetRaw
        : null,
  };
}

function upsertLedgerWatermark(
  db: DatabaseLike,
  sessionId: string,
  watermark: { lastSeq: number; lastEventId: string; updatedAtMs: number },
  lastByteOffset: number | null,
): void {
  db.prepare(
    `
    INSERT INTO local_runtime_ledger_watermarks (
      session_id,
      last_seq,
      last_event_id,
      updated_at_ms,
      last_byte_offset
    ) VALUES (?, ?, ?, ?, ?)
    ON CONFLICT(session_id) DO UPDATE SET
      last_seq = excluded.last_seq,
      last_event_id = excluded.last_event_id,
      updated_at_ms = excluded.updated_at_ms,
      last_byte_offset = excluded.last_byte_offset
  `,
  ).run(sessionId, watermark.lastSeq, watermark.lastEventId, watermark.updatedAtMs, lastByteOffset);
}
