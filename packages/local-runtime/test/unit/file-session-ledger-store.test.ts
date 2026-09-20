/**
 * Tests for the FileSessionLedgerStore incremental-watermark behaviour
 * introduced by perf/file-ledger-incremental-watermark (finding #25).
 *
 * The hot path must read the watermark from the SQLite side-table (a single
 * row lookup) instead of re-scanning the JSONL file. The recovery path must
 * still fall back to a file scan when the SQLite row is missing or stale,
 * and concurrent appenders must not trample each other's watermarks.
 */

import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import { afterEach, describe, expect, it, vi } from 'vitest';

import type { LocalSessionLedgerEventDraft } from '../../src/sessions/ledger/index.js';
import {
  FileSessionLedgerStore,
  resolveLocalSessionLedgerPath,
} from '../../src/sessions/ledger/index.js';
import * as ledgerReadModule from '../../src/sessions/ledger/ledger-read.js';
import { closeLocalRuntimeDb, openLocalRuntimeDb } from '../../src/persistence/db.js';

const directories: string[] = [];

afterEach(async () => {
  vi.restoreAllMocks();
  for (const dataDir of directories.splice(0)) {
    closeLocalRuntimeDb(dataDir);
    await rm(dataDir, { recursive: true, force: true });
  }
});

async function freshDataDir(): Promise<string> {
  const dataDir = await mkdtemp(join(tmpdir(), 'file-session-ledger-store-'));
  directories.push(dataDir);
  // Eagerly open the DB so the schema migration runs before the test starts.
  openLocalRuntimeDb(dataDir);
  return dataDir;
}

function draft(sessionId: string, idx: number, payloadBytes = 256): LocalSessionLedgerEventDraft {
  return {
    kind: 'message.display_upserted',
    sessionId,
    message: {
      msg_id: `m_${sessionId}_${idx}`,
      role: 'user',
      // 'x'.repeat keeps the byte size predictable for the file-scan timing
      // assertions; the store treats this as opaque JSON.
      content: 'x'.repeat(payloadBytes),
    },
  };
}

function appendMany(
  store: FileSessionLedgerStore,
  sessionId: string,
  count: number,
  payloadBytes = 256,
): Promise<unknown> {
  return store.append(
    sessionId,
    Array.from({ length: count }, (_, idx) => draft(sessionId, idx, payloadBytes)),
  );
}

describe('FileSessionLedgerStore — incremental watermark', () => {
  it('reads the watermark from SQLite on the hot path (no file scan)', async () => {
    const dataDir = await freshDataDir();
    const store = new FileSessionLedgerStore(dataDir);
    const sessionId = 'hot-path';

    // Seed a non-trivial ledger so a file scan would be measurable.
    await appendMany(store, sessionId, 200, 1024);

    // Hot-path: subsequent appends must NOT touch the full-file scanner.
    const readSpy = vi.spyOn(ledgerReadModule, 'readLedgerWatermarkSync');
    try {
      const started = Date.now();
      const result = await store.append(sessionId, [draft(sessionId, 200, 1024)]);
      const elapsed = Date.now() - started;

      expect(readSpy).not.toHaveBeenCalled();
      expect(result.events).toHaveLength(1);
      expect(result.events[0]!.seq).toBe(201);
      expect(result.watermark.lastSeq).toBe(201);
      expect(result.watermark.byteOffset).toBeGreaterThan(0);
      // 200 events of ~1 KiB is well below the 100ms bar even on slow CI.
      expect(elapsed).toBeLessThan(200);
    } finally {
      readSpy.mockRestore();
    }
  });

  it('falls back to a file scan when the SQLite watermark row is missing', async () => {
    const dataDir = await freshDataDir();
    const store = new FileSessionLedgerStore(dataDir);
    const sessionId = 'recovery-missing-row';

    // First append establishes both the file and the SQLite row.
    await appendMany(store, sessionId, 10, 256);

    // Simulate a corrupted / pre-migration database: the SQLite row is
    // gone but the ledger on disk still has the events. The next append
    // must rebuild the row from the file (recovery path) and pick up
    // where the file ends without allocating duplicate seq ids.
    closeLocalRuntimeDb(dataDir);
    openLocalRuntimeDb(dataDir); // re-open
    // Drop the row without touching the file:
    const db = openLocalRuntimeDb(dataDir);
    db.prepare('DELETE FROM local_runtime_ledger_watermarks WHERE session_id = ?').run(sessionId);

    const readSpy = vi.spyOn(ledgerReadModule, 'readLedgerWatermarkSync');
    try {
      // The first append after the row loss must rebuild the watermark
      // by scanning the file (recovery path). The next append must take
      // the hot path: the SQLite row is now authoritative again.
      const recovery = await store.append(sessionId, [draft(sessionId, 99, 256)]);
      expect(readSpy).toHaveBeenCalledTimes(1);
      expect(recovery.events[0]!.seq).toBe(11);
      expect(recovery.watermark.lastSeq).toBe(11);

      const callsAfterRecovery = readSpy.mock.calls.length;
      const hotPath = await store.append(sessionId, [draft(sessionId, 100, 256)]);
      // Hot path must not invoke another file scan.
      expect(readSpy.mock.calls.length).toBe(callsAfterRecovery);
      expect(hotPath.events[0]!.seq).toBe(12);
      expect(hotPath.watermark.lastSeq).toBe(12);
    } finally {
      readSpy.mockRestore();
    }
  });

  it('falls back to a file scan when the cached offset is stale (post-crash)', async () => {
    const dataDir = await freshDataDir();
    const store = new FileSessionLedgerStore(dataDir);
    const sessionId = 'recovery-stale-offset';

    await appendMany(store, sessionId, 5, 128);
    const ledgerPath = resolveLocalSessionLedgerPath(dataDir, sessionId);

    // Simulate a process that crashed between the SQLite commit and the
    // file append: SQLite is ahead of the file. Force the SQLite row to
    // point at a byte offset that does not exist on disk yet.
    closeLocalRuntimeDb(dataDir);
    openLocalRuntimeDb(dataDir);
    const db = openLocalRuntimeDb(dataDir);
    db.prepare(
      `UPDATE local_runtime_ledger_watermarks
         SET last_byte_offset = 999999
       WHERE session_id = ?`,
    ).run(sessionId);

    const readSpy = vi.spyOn(ledgerReadModule, 'readLedgerWatermarkSync');
    try {
      const result = await store.append(sessionId, [draft(sessionId, 50, 128)]);
      expect(readSpy).toHaveBeenCalledTimes(1);
      // Recovery must roll the SQLite row back to the file's true state
      // and allocate the new event at seq=6, not seq=6 with a corrupted
      // file gap.
      expect(result.events[0]!.seq).toBe(6);
      const row = db
        .prepare(
          'SELECT last_seq, last_byte_offset FROM local_runtime_ledger_watermarks WHERE session_id = ?',
        )
        .get(sessionId) as { last_seq: number; last_byte_offset: number | null };
      expect(row.last_seq).toBe(6);
      // After the recovery write + append, the cached offset must match
      // the file's true trailing offset.
      expect(row.last_byte_offset).not.toBeNull();
      const { statSync } = await import('node:fs');
      expect(row.last_byte_offset).toBe(statSync(ledgerPath).size);
    } finally {
      readSpy.mockRestore();
    }
  });

  it('serializes concurrent appenders per session without losing events', async () => {
    const dataDir = await freshDataDir();
    const store = new FileSessionLedgerStore(dataDir);
    const sessionId = 'concurrent-appenders';

    // Two interleaved batches racing for the same session. The per-session
    // append chain plus the SQLite IMMEDIATE transaction must serialize
    // them so the final seq is monotonic and the file and SQLite row agree.
    const batchA = Array.from({ length: 8 }, (_, i) => draft(sessionId, i, 256));
    const batchB = Array.from({ length: 8 }, (_, i) => draft(sessionId, 100 + i, 256));

    const [resultA, resultB] = await Promise.all([
      store.append(sessionId, batchA),
      store.append(sessionId, batchB),
    ]);

    // The two batches must not have allocated overlapping seq ids.
    const seqsA = resultA.events.map((event) => event.seq);
    const seqsB = resultB.events.map((event) => event.seq);
    const overlap = seqsA.filter((seq) => seqsB.includes(seq));
    expect(overlap).toEqual([]);

    // Watermarks advance monotonically: the later finishing batch owns the
    // higher watermark. We don't assume a particular ordering — only that
    // the two watermarks are consistent (one dominates the other).
    const finalWatermark = await store.getWatermark(sessionId);
    expect(finalWatermark).toBeDefined();
    const combinedLast = Math.max(resultA.watermark.lastSeq, resultB.watermark.lastSeq);
    expect(finalWatermark!.lastSeq).toBe(combinedLast);

    // Replaying the ledger yields exactly 16 events with unique seq ids.
    const events: number[] = [];
    for await (const event of store.readEvents(sessionId)) events.push(event.seq);
    expect(events).toHaveLength(16);
    expect(new Set(events).size).toBe(16);
    expect(Math.min(...events)).toBe(1);
    expect(Math.max(...events)).toBe(16);
  });
});