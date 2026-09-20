import fs from 'node:fs';
import { randomUUID } from 'node:crypto';
import path from 'node:path';

import { FEATURE_MIGRATIONS } from './feature-migrations.js';
import { loadBetterSqlite3Module } from './better-sqlite3-loader.js';
import { resolveV2DirectoryContract } from './layout/v2-paths.js';

export type DataDirInput = string | (() => string);

export type DatabaseConstructor = new (
  filename?: string | Buffer,
  options?: Record<string, unknown>,
) => DatabaseLike;

export interface DatabaseLike {
  exec(sql: string): void;
  prepare(sql: string): StatementLike;
  close(): void;
  transaction?<T>(fn: () => T): DatabaseTransaction<T>;
}

export interface DatabaseTransaction<T> {
  (): T;
  immediate(): T;
}

export interface StatementLike {
  get(...args: unknown[]): unknown;
  all(...args: unknown[]): unknown[];
  run(...args: unknown[]): unknown;
}

export interface Migration {
  version: number;
  sql: string;
}

interface MigrationRow {
  version?: number;
}
interface TableInfoRow {
  name?: unknown;
}

const dbCache = new Map<string, DatabaseLike>();

const MIGRATIONS: Migration[] = [
  {
    version: 1,
    sql: `
      CREATE TABLE IF NOT EXISTS local_runtime_sessions (
        session_id TEXT PRIMARY KEY,
        record_json TEXT NOT NULL,
        updated_at_ms INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS local_runtime_agents (
        name TEXT PRIMARY KEY,
        record_json TEXT NOT NULL,
        updated_at_ms INTEGER NOT NULL
      );
      CREATE TABLE IF NOT EXISTS local_runtime_messages (
        session_id TEXT PRIMARY KEY,
        display_messages_json TEXT NOT NULL,
        pi_history_json TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS local_runtime_queues (
        session_id TEXT PRIMARY KEY,
        items_json TEXT NOT NULL
      );
      CREATE TABLE IF NOT EXISTS local_runtime_preferences (
        key TEXT PRIMARY KEY,
        value_json TEXT NOT NULL
      );
    `,
  },
  {
    version: 2,
    sql: `
      CREATE TABLE IF NOT EXISTS local_runtime_message_rows (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT NOT NULL,
        msg_id TEXT NOT NULL,
        role TEXT,
        turn_id TEXT,
        created_at_ms INTEGER NOT NULL,
        data_json TEXT NOT NULL,
        UNIQUE(session_id, msg_id)
      );
      CREATE INDEX IF NOT EXISTS idx_local_runtime_message_rows_session_id
        ON local_runtime_message_rows(session_id, id);
      CREATE INDEX IF NOT EXISTS idx_local_runtime_message_rows_session_msg_id
        ON local_runtime_message_rows(session_id, msg_id);
      CREATE TABLE IF NOT EXISTS local_runtime_message_row_migrations (
        session_id TEXT PRIMARY KEY,
        display_rows_backfilled_at_ms INTEGER NOT NULL
      );
    `,
  },
  {
    version: 3,
    sql: `
      CREATE TABLE IF NOT EXISTS local_runtime_pi_history_rows (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT NOT NULL,
        role TEXT,
        created_at_ms INTEGER NOT NULL,
        data_json TEXT NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_local_runtime_pi_history_rows_session_id
        ON local_runtime_pi_history_rows(session_id, id);
      CREATE TABLE IF NOT EXISTS local_runtime_pi_history_row_migrations (
        session_id TEXT PRIMARY KEY,
        history_rows_backfilled_at_ms INTEGER NOT NULL
      );
    `,
  },
  {
    version: 4,
    sql: `
      CREATE TABLE IF NOT EXISTS local_runtime_queue_items (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT NOT NULL,
        item_id TEXT NOT NULL,
        status TEXT,
        created_at_ms INTEGER NOT NULL,
        data_json TEXT NOT NULL,
        UNIQUE(session_id, item_id)
      );
      CREATE INDEX IF NOT EXISTS idx_local_runtime_queue_items_session_id
        ON local_runtime_queue_items(session_id, id);
      CREATE INDEX IF NOT EXISTS idx_local_runtime_queue_items_session_item_id
        ON local_runtime_queue_items(session_id, item_id);
      CREATE TABLE IF NOT EXISTS local_runtime_queue_row_migrations (
        session_id TEXT PRIMARY KEY,
        queue_rows_backfilled_at_ms INTEGER NOT NULL
      );
    `,
  },
  {
    version: 5,
    sql: `
      CREATE TABLE IF NOT EXISTS local_runtime_legacy_migrations (
        legacy_session_id TEXT PRIMARY KEY,
        local_session_id TEXT NOT NULL,
        source_runtime TEXT NOT NULL,
        status TEXT NOT NULL,
        migrated_at_ms INTEGER NOT NULL,
        source_updated_at_ms INTEGER,
        source_fingerprint TEXT,
        error_json TEXT
      );
      CREATE UNIQUE INDEX IF NOT EXISTS idx_local_runtime_legacy_migrations_local_session_id
        ON local_runtime_legacy_migrations(local_session_id);
    `,
  },
  {
    version: 6,
    sql: `
      CREATE TABLE IF NOT EXISTS local_runtime_session_locks (
        session_id TEXT PRIMARY KEY,
        owner_id TEXT NOT NULL,
        owner_kind TEXT NOT NULL,
        acquired_at_ms INTEGER NOT NULL,
        expires_at_ms INTEGER NOT NULL
      );
    `,
  },
  {
    version: 7,
    sql: `
      CREATE TABLE IF NOT EXISTS local_runtime_ledger_watermarks (
        session_id TEXT PRIMARY KEY,
        last_seq INTEGER NOT NULL,
        last_event_id TEXT NOT NULL,
        updated_at_ms INTEGER NOT NULL
      );
    `,
  },
  {
    version: 8,
    sql: `
      CREATE TABLE IF NOT EXISTS local_runtime_session_projection_watermarks (
        session_id TEXT PRIMARY KEY,
        last_seq INTEGER NOT NULL,
        last_event_id TEXT NOT NULL,
        updated_at_ms INTEGER NOT NULL
      );
    `,
  },
  {
    version: 9,
    sql: `
      SELECT 1;
    `,
  },
  {
    version: 10,
    sql: `
      CREATE TABLE IF NOT EXISTS local_runtime_token_usage (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT NOT NULL,
        agent_name TEXT NOT NULL,
        framework_type TEXT NOT NULL,
        turn_id TEXT,
        model TEXT,
        ts INTEGER NOT NULL,
        input_tokens INTEGER NOT NULL,
        output_tokens INTEGER NOT NULL,
        reasoning_tokens INTEGER NOT NULL,
        cache_read_tokens INTEGER NOT NULL,
        cache_write_tokens INTEGER NOT NULL,
        cost_usd REAL,
        raw TEXT
      );
      CREATE INDEX IF NOT EXISTS idx_local_runtime_token_usage_session_ts
        ON local_runtime_token_usage(session_id, ts, id);
      CREATE INDEX IF NOT EXISTS idx_local_runtime_token_usage_agent_ts
        ON local_runtime_token_usage(agent_name, ts, id);
      CREATE INDEX IF NOT EXISTS idx_local_runtime_token_usage_ts
        ON local_runtime_token_usage(ts, id);

      CREATE TABLE IF NOT EXISTS local_runtime_turn_diffs (
        change_set_id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        turn_id TEXT NOT NULL,
        assistant_message_id TEXT,
        workspace_dir TEXT NOT NULL,
        captured_at_ms INTEGER NOT NULL,
        status TEXT NOT NULL,
        file_changes_json TEXT NOT NULL,
        raw_diff TEXT,
        reverted_at_ms INTEGER,
        UNIQUE(session_id, turn_id)
      );
      CREATE INDEX IF NOT EXISTS idx_local_runtime_turn_diffs_session_captured
        ON local_runtime_turn_diffs(session_id, captured_at_ms, change_set_id);
      CREATE INDEX IF NOT EXISTS idx_local_runtime_turn_diffs_session_assistant
        ON local_runtime_turn_diffs(session_id, assistant_message_id);
    `,
  },
  {
    version: 11,
    sql: `
      CREATE TABLE IF NOT EXISTS local_runtime_communication_messages (
        message_id TEXT PRIMARY KEY,
        from_session TEXT NOT NULL,
        to_session TEXT NOT NULL,
        command TEXT NOT NULL,
        content TEXT NOT NULL,
        status TEXT NOT NULL,
        error TEXT,
        created_at_ms INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_local_runtime_communication_messages_from_to
        ON local_runtime_communication_messages(from_session, to_session, created_at_ms);
      CREATE INDEX IF NOT EXISTS idx_local_runtime_communication_messages_to
        ON local_runtime_communication_messages(to_session, created_at_ms);
      CREATE INDEX IF NOT EXISTS idx_local_runtime_communication_messages_status
        ON local_runtime_communication_messages(status, created_at_ms);
    `,
  },
  {
    version: 12,
    sql: `
      CREATE TABLE IF NOT EXISTS local_runtime_crons (
        agent_name TEXT NOT NULL,
        cron_name TEXT NOT NULL,
        config_json TEXT NOT NULL,
        updated_at_ms INTEGER NOT NULL,
        PRIMARY KEY (agent_name, cron_name)
      );
      CREATE INDEX IF NOT EXISTS idx_local_runtime_crons_agent
        ON local_runtime_crons(agent_name, cron_name);

      CREATE TABLE IF NOT EXISTS local_runtime_cron_session_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        agent_name TEXT NOT NULL,
        cron_name TEXT NOT NULL,
        session_id TEXT NOT NULL,
        created_at_ms INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_local_runtime_cron_history_task
        ON local_runtime_cron_session_history(agent_name, cron_name, created_at_ms, id);
      CREATE INDEX IF NOT EXISTS idx_local_runtime_cron_history_session
        ON local_runtime_cron_session_history(session_id);
    `,
  },
  {
    version: 13,
    sql: `
      CREATE TABLE IF NOT EXISTS local_runtime_thread_goals (
        goal_id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL UNIQUE,
        objective TEXT NOT NULL,
        status TEXT NOT NULL,
        created_at_ms INTEGER NOT NULL,
        updated_at_ms INTEGER NOT NULL
      );
      CREATE INDEX IF NOT EXISTS idx_local_runtime_thread_goals_session
        ON local_runtime_thread_goals(session_id);
    `,
  },
  {
    // Thread Goal accounting (codex `accounting.rs` parity): per-goal
    // running totals of model tokens spent and turn-active wall time. The
    // banner renders `(12.5K · 2m)` from these; v15 adds `token_budget`
    // on top so the same column reads can support BudgetLimited.
    //
    // Existing rows are bootstrapped to 0/0 by SQLite's column default —
    // ALTER TABLE … ADD COLUMN with DEFAULT 0 backfills atomically.
    version: 14,
    sql: `
      ALTER TABLE local_runtime_thread_goals
        ADD COLUMN tokens_used INTEGER NOT NULL DEFAULT 0;
      ALTER TABLE local_runtime_thread_goals
        ADD COLUMN time_used_seconds INTEGER NOT NULL DEFAULT 0;
    `,
  },
  {
    // Thread Goal token_budget (codex `thread_goals.token_budget` parity).
    // Nullable INTEGER — `NULL` means "no cap", matching codex's
    // `token_budget Option<i64>`. Existing rows get NULL automatically.
    //
    // We deliberately do NOT use `DEFAULT 0`: `0` would mean "the goal
    // hits its budget instantly" (`tokens_used >= 0` is always true),
    // which would flip every pre-v15 goal to `budget_limited` on the
    // next turn-end bump. NULL is the safe sentinel.
    version: 15,
    sql: `
      ALTER TABLE local_runtime_thread_goals
        ADD COLUMN token_budget INTEGER;
    `,
  },
  {
    version: 16,
    sql: `
      CREATE TABLE IF NOT EXISTS local_runtime_turn_diffs (
        change_set_id TEXT PRIMARY KEY,
        session_id TEXT NOT NULL,
        turn_id TEXT NOT NULL,
        assistant_message_id TEXT,
        workspace_dir TEXT NOT NULL,
        captured_at_ms INTEGER NOT NULL,
        status TEXT NOT NULL,
        file_changes_json TEXT NOT NULL,
        raw_diff TEXT,
        reverted_at_ms INTEGER,
        UNIQUE(session_id, turn_id)
      );
      CREATE INDEX IF NOT EXISTS idx_local_runtime_turn_diffs_session_captured
        ON local_runtime_turn_diffs(session_id, captured_at_ms, change_set_id);
      CREATE INDEX IF NOT EXISTS idx_local_runtime_turn_diffs_session_assistant
        ON local_runtime_turn_diffs(session_id, assistant_message_id);

      CREATE TABLE IF NOT EXISTS local_runtime_turn_diff_journal (
        journal_id           TEXT PRIMARY KEY,
        row_type             TEXT NOT NULL,
        turn_id              TEXT NOT NULL,
        session_id           TEXT NOT NULL,
        agent_name           TEXT,
        workspace_dir        TEXT,
        start_message_row_id INTEGER,
        turn_status          TEXT,
        tool_call_id         TEXT,
        tool_name            TEXT,
        sequence             INTEGER,
        paths_json           TEXT NOT NULL DEFAULT '[]',
        before_json          TEXT NOT NULL DEFAULT '[]',
        after_json           TEXT NOT NULL DEFAULT '[]',
        tool_status          TEXT,
        ambiguity_reason     TEXT,
        created_at_ms        INTEGER NOT NULL,
        finalized_at_ms      INTEGER,
        completed_at_ms      INTEGER
      );

      CREATE UNIQUE INDEX IF NOT EXISTS idx_local_runtime_turn_diff_journal_turn
        ON local_runtime_turn_diff_journal(session_id, turn_id, row_type)
        WHERE row_type = 'turn';

      CREATE UNIQUE INDEX IF NOT EXISTS idx_local_runtime_turn_diff_journal_tool
        ON local_runtime_turn_diff_journal(session_id, turn_id, tool_call_id)
        WHERE row_type = 'tool';

      CREATE INDEX IF NOT EXISTS idx_local_runtime_turn_diff_journal_pending
        ON local_runtime_turn_diff_journal(session_id, row_type, turn_status, created_at_ms);

      CREATE INDEX IF NOT EXISTS idx_local_runtime_turn_diff_journal_tools
        ON local_runtime_turn_diff_journal(session_id, turn_id, row_type, tool_status, sequence);
    `,
  },
  {
    version: 17,
    // Rename the two cron-history indexes to the canonical names documented in
    // the middleware-dependency spec (§8): `..._cron_session_history_task` /
    // `..._cron_session_history_session`. Migration is append-only, so older
    // DBs that already created the v12 `..._cron_history_*` names get the old
    // index dropped and the documented name created (index columns unchanged).
    sql: `
      DROP INDEX IF EXISTS idx_local_runtime_cron_history_task;
      DROP INDEX IF EXISTS idx_local_runtime_cron_history_session;
      CREATE INDEX IF NOT EXISTS idx_local_runtime_cron_session_history_task
        ON local_runtime_cron_session_history(agent_name, cron_name, created_at_ms, id);
      CREATE INDEX IF NOT EXISTS idx_local_runtime_cron_session_history_session
        ON local_runtime_cron_session_history(session_id);
    `,
  },
  {
    // Cron unification Step 1 (storage foundation): add a stable `cron_id`
    // to `local_runtime_crons` so the local runtime can align with the
    // archon_biz cron contract (mutations key on cron_id). The engine/store
    // keep keying on (agent_name, cron_name) internally — this column is a
    // thin alias plus a UNIQUE index for cron_id lookups.
    //
    // SQLite treats NULLs as distinct under UNIQUE, so legacy rows can stay
    // NULL until back-filled. The back-fill itself (minting a UUID per NULL
    // row) lives in `ensureCronTableCompatibility`, which also repairs older
    // dbs whose schema_migrations bookkeeping predates this ALTER.
    version: 18,
    sql: `
      ALTER TABLE local_runtime_crons ADD COLUMN cron_id TEXT;
      CREATE UNIQUE INDEX IF NOT EXISTS idx_local_runtime_crons_cron_id
        ON local_runtime_crons(cron_id);
    `,
  },
  ...FEATURE_MIGRATIONS,
  {
    // Session search reads a recency-bounded window
    // (`ORDER BY updated_at_ms DESC LIMIT ?`); back that scan with an index
    // so SQLite stops after N index entries instead of sorting the whole
    // table. Versions 19-24 are taken by FEATURE_MIGRATIONS above.
    version: 25,
    sql: `
      CREATE INDEX IF NOT EXISTS idx_local_runtime_sessions_updated_at
        ON local_runtime_sessions(updated_at_ms DESC);
    `,
  },
  {
    // Version 26 was already occupied by Session Assets when an unreleased
    // Goal migration briefly reused it. Keep the published Goal marker at 27
    // without replaying ALTER statements: the compatibility pass below adds
    // missing columns/indexes conditionally. Retired Workspace Indexing also
    // used 27 and 28; preserve those historical markers without recreating it.
    version: 27,
    sql: `SELECT 1;`,
  },
  {
    // Version 28 remains reserved for retired Workspace Indexing databases.
    // Goal policy columns therefore use the next append-only marker;
    // the compatibility pass below performs guarded ALTERs for both fresh
    // and partially migrated databases.
    version: 29,
    sql: `SELECT 1;`,
  },
  {
    // Goal execution-wait columns are installed by the guarded compatibility
    // pass below. Keep an append-only marker so schema history still records
    // when that projection became part of the local database contract.
    version: 30,
    sql: `SELECT 1;`,
  },
  {
    // `execution_wait_epoch` joined the same guarded pass. A pre-existing row
    // gets a NULL epoch, which never matches `updated_at_ms`, so any wait
    // persisted before this column existed reads as "no wait" instead of
    // resurfacing against a newer admission epoch.
    version: 31,
    sql: `SELECT 1;`,
  },
  {
    // Retention is intentionally incremental: existing Turn Diff rows are not
    // backfilled. New writes are registered by compatibility triggers below,
    // so a retention pass can read a time-ordered bounded queue instead of
    // sorting the complete journal/diff/rewind tables.
    version: 32,
    sql: `
      CREATE TABLE IF NOT EXISTS local_runtime_turn_diff_retention_queue (
        entry_kind TEXT NOT NULL CHECK (entry_kind IN ('turn', 'diff', 'rewind')),
        session_id TEXT NOT NULL,
        item_id TEXT NOT NULL,
        eligible_at_ms INTEGER NOT NULL,
        PRIMARY KEY (entry_kind, session_id, item_id)
      );
      CREATE INDEX IF NOT EXISTS idx_local_runtime_turn_diff_retention_due
        ON local_runtime_turn_diff_retention_queue(
          entry_kind, eligible_at_ms, session_id, item_id
         );
    `,
  },
  {
    // Turn Diff retention took the published version-32 marker, so objective
    // resources move to the next append-only slot. The column itself is
    // installed by the guarded compatibility pass below.
    version: 33,
    sql: `SELECT 1;`,
  },
  {
    // Ledger watermark incremental: track the trailing byte offset of each
    // session's ledger alongside the seq/event id, so `append()` no longer
    // has to open and parse the whole JSONL file under a SQLite IMMEDIATE
    // transaction. The compatibility pass below guarantees the new column is
    // present even on dbs whose `schema_migrations` bookkeeping predates
    // v34 (e.g. fresh dbs created on an older binary, then upgraded).
    //
    // The column is NULLABLE on purpose: rows written before v34 do not
    // know the trailing offset, so the read path treats NULL as "rebuild
    // from the file" rather than "offset = 0". Once the next `append()`
    // runs, the column is back-filled to the file's true trailing offset.
    version: 34,
    sql: `SELECT 1;`,
  },
];
export function withLocalRuntimeDb<T>(dataDir: DataDirInput, fn: (db: DatabaseLike) => T): T {
  return fn(openLocalRuntimeDb(dataDir));
}

export function runInImmediateTransaction<T>(db: DatabaseLike, fn: () => T): T {
  if (db.transaction) return db.transaction(fn).immediate();
  db.exec('BEGIN IMMEDIATE');
  try {
    const result = fn();
    db.exec('COMMIT');
    return result;
  } catch (error) {
    db.exec('ROLLBACK');
    throw error;
  }
}

export function openLocalRuntimeDb(dataDir: DataDirInput): DatabaseLike {
  const dbPath = resolveLocalRuntimeDbPath(dataDir);
  const cached = dbCache.get(dbPath);
  if (cached) return cached;

  const dbDir = path.dirname(dbPath);
  fs.mkdirSync(dbDir, { recursive: true, mode: 0o700 });
  fs.chmodSync(dbDir, 0o700);
  const Database = loadBetterSqlite3();
  const db = new Database(dbPath);
  fs.chmodSync(dbPath, 0o600);
  configureDb(db);
  ensureSchema(db);
  for (const suffix of ['-wal', '-shm']) {
    const sidecarPath = `${dbPath}${suffix}`;
    if (fs.existsSync(sidecarPath)) fs.chmodSync(sidecarPath, 0o600);
  }
  dbCache.set(dbPath, db);
  return db;
}

export function closeLocalRuntimeDb(dataDir: DataDirInput): void {
  const dbPath = resolveLocalRuntimeDbPath(dataDir);
  const db = dbCache.get(dbPath);
  if (!db) return;
  dbCache.delete(dbPath);
  db.close();
}

export function resolveLocalRuntimeDbPath(dataDir: DataDirInput): string {
  return resolveV2DirectoryContract(dataDir).db;
}

function configureDb(db: DatabaseLike): void {
  db.exec(`
    PRAGMA journal_mode = WAL;
    PRAGMA busy_timeout = 5000;
    PRAGMA foreign_keys = ON;
  `);
}

function ensureSchema(db: DatabaseLike): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS local_runtime_schema_migrations (
      version INTEGER PRIMARY KEY,
      applied_at_ms INTEGER NOT NULL
    );
  `);
  const applied = new Set(
    db
      .prepare('SELECT version FROM local_runtime_schema_migrations')
      .all()
      .map((row) => Number((row as MigrationRow).version))
      .filter((version) => Number.isInteger(version)),
  );
  for (const migration of MIGRATIONS) {
    if (applied.has(migration.version)) continue;
    runMigration(db, migration);
  }
  ensureLegacyMigrationTableCompatibility(db);
  ensureThreadGoalTableCompatibility(db);
  ensureTurnDiffTableCompatibility(db);
  ensureCronTableCompatibility(db);
  ensureLedgerWatermarkTableCompatibility(db);
}

function runMigration(db: DatabaseLike, migration: Migration): void {
  const apply = () => {
    db.exec(migration.sql);
    db.prepare(
      'INSERT OR IGNORE INTO local_runtime_schema_migrations (version, applied_at_ms) VALUES (?, ?)',
    ).run(migration.version, Date.now());
  };
  if (db.transaction) {
    db.transaction(apply)();
    return;
  }
  apply();
}

function ensureLegacyMigrationTableCompatibility(db: DatabaseLike): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS local_runtime_legacy_migrations (
      legacy_session_id TEXT PRIMARY KEY,
      local_session_id TEXT NOT NULL,
      source_runtime TEXT NOT NULL,
      status TEXT NOT NULL,
      migrated_at_ms INTEGER NOT NULL,
      source_updated_at_ms INTEGER,
      source_fingerprint TEXT,
      error_json TEXT
    );
    CREATE UNIQUE INDEX IF NOT EXISTS idx_local_runtime_legacy_migrations_local_session_id
      ON local_runtime_legacy_migrations(local_session_id);
  `);
  const columns = new Set(
    db
      .prepare('PRAGMA table_info(local_runtime_legacy_migrations)')
      .all()
      .map((row) => (row as TableInfoRow).name)
      .filter((name): name is string => typeof name === 'string'),
  );
  const addColumn = (name: string, definition: string) => {
    if (columns.has(name)) return;
    db.exec(`ALTER TABLE local_runtime_legacy_migrations ADD COLUMN ${name} ${definition};`);
    columns.add(name);
  };
  addColumn('ledger_imported_at_ms', 'INTEGER');
  addColumn('projection_ready_at_ms', 'INTEGER');
  addColumn('display_ready_at_ms', 'INTEGER');
  addColumn('pi_history_ready_at_ms', 'INTEGER');
  addColumn('legacy_daemon_session_id', 'TEXT');
  addColumn('legacy_framework_session_id', 'TEXT');
  addColumn('source_schema_fingerprint', 'TEXT');
  addColumn('source_checksum', 'TEXT');
  addColumn('display_checksum', 'TEXT');
  addColumn('pi_history_strategy', 'TEXT');
  addColumn('pi_history_converter_version', 'INTEGER');
  addColumn('source_manifest_json', 'TEXT');
  addColumn('source_message_count', 'INTEGER');
  addColumn('imported_message_count', 'INTEGER');
  addColumn('report_json', 'TEXT');
  addColumn('warnings_json', 'TEXT');
  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_local_runtime_legacy_migrations_framework_session_id
      ON local_runtime_legacy_migrations(legacy_framework_session_id);
  `);
}

function ensureThreadGoalTableCompatibility(db: DatabaseLike): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS local_runtime_thread_goals (
      goal_id TEXT PRIMARY KEY,
      session_id TEXT NOT NULL UNIQUE,
      objective TEXT NOT NULL,
      status TEXT NOT NULL,
      created_at_ms INTEGER NOT NULL,
      updated_at_ms INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_local_runtime_thread_goals_session
      ON local_runtime_thread_goals(session_id);
  `);
  const columns = new Set(
    db
      .prepare('PRAGMA table_info(local_runtime_thread_goals)')
      .all()
      .map((row) => (row as TableInfoRow).name)
      .filter((name): name is string => typeof name === 'string'),
  );
  const addColumn = (name: string, definition: string) => {
    if (columns.has(name)) return;
    db.exec(`ALTER TABLE local_runtime_thread_goals ADD COLUMN ${name} ${definition};`);
    columns.add(name);
  };
  addColumn('tokens_used', 'INTEGER NOT NULL DEFAULT 0');
  addColumn('time_used_seconds', 'INTEGER NOT NULL DEFAULT 0');
  addColumn('token_budget', 'INTEGER');
  addColumn('kickoff_attachments_json', "TEXT NOT NULL DEFAULT '[]'");
  addColumn('objective_resources_json', "TEXT NOT NULL DEFAULT '[]'");
  addColumn('kickoff_state', "TEXT NOT NULL DEFAULT 'consumed'");
  addColumn('turns_used', 'INTEGER NOT NULL DEFAULT 0');
  addColumn('reply_fingerprint', 'TEXT');
  addColumn('no_progress_streak', 'INTEGER NOT NULL DEFAULT 0');
  // Second, independent breaker counter: consecutive Goal-bound main turns that
  // ended normally without any committed tool call. Existing rows start at 0,
  // so the migration cannot resurrect a streak from history the host never
  // observed.
  addColumn('no_tool_streak', 'INTEGER NOT NULL DEFAULT 0');
  addColumn('last_verification', 'TEXT');
  addColumn('last_worker_proposal', 'TEXT');
  addColumn('status_reason', 'TEXT');
  // Execution wait projection. Deliberately separate from `status_reason`:
  // these columns describe why an `active` Goal has not started its next Turn,
  // and are written WITHOUT touching `updated_at_ms` (the admission epoch).
  //
  // `execution_wait_epoch` records the `updated_at_ms` the wait was decided
  // against. The read path only surfaces a wait whose epoch still matches, so
  // any writer that advances the epoch retires the wait for free — no writer
  // has to remember to clear these columns.
  addColumn('execution_wait_reason', 'TEXT');
  addColumn('execution_wait_since_ms', 'INTEGER');
  addColumn('execution_wait_epoch', 'INTEGER');
  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_local_runtime_thread_goals_kickoff_state
      ON local_runtime_thread_goals(kickoff_state, session_id);
  `);
}

/**
 * Cron unification Step 1 compatibility: guarantee `local_runtime_crons`
 * carries the `cron_id` column + UNIQUE index, then back-fill any NULL rows
 * with a minted UUID. Mirrors `ensureThreadGoalTableCompatibility` so dbs
 * whose `schema_migrations` bookkeeping predates the v18 ALTER (e.g. created
 * fresh on an older binary, then upgraded) still converge. Idempotent: the
 * back-fill only touches rows where `cron_id IS NULL`, so re-opening never
 * re-mints an existing id.
 */
function ensureCronTableCompatibility(db: DatabaseLike): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS local_runtime_crons (
      agent_name TEXT NOT NULL,
      cron_name TEXT NOT NULL,
      config_json TEXT NOT NULL,
      updated_at_ms INTEGER NOT NULL,
      PRIMARY KEY (agent_name, cron_name)
    );
    CREATE INDEX IF NOT EXISTS idx_local_runtime_crons_agent
      ON local_runtime_crons(agent_name, cron_name);
  `);
  const columns = new Set(
    db
      .prepare('PRAGMA table_info(local_runtime_crons)')
      .all()
      .map((row) => (row as TableInfoRow).name)
      .filter((name): name is string => typeof name === 'string'),
  );
  if (!columns.has('cron_id')) {
    db.exec('ALTER TABLE local_runtime_crons ADD COLUMN cron_id TEXT;');
    columns.add('cron_id');
  }
  db.exec(`
    CREATE UNIQUE INDEX IF NOT EXISTS idx_local_runtime_crons_cron_id
      ON local_runtime_crons(cron_id);
  `);
  backfillCronIds(db);
}

/**
 * Ledger watermark incremental compatibility: guarantee
 * `local_runtime_ledger_watermarks` carries the `last_byte_offset` column
 * introduced by migration v34. Mirrors `ensureThreadGoalTableCompatibility`:
 * the ALTER runs at open time so dbs whose `schema_migrations` bookkeeping
 * predates v34 still converge. Idempotent: a guarded `PRAGMA table_info`
 * skips the ALTER when the column is already present.
 *
 * Rows written before v34 keep `last_byte_offset IS NULL`. The append path
 * treats NULL as "rebuild from the file" — the next `append()` writes the
 * true trailing offset, so a single append is enough to converge the row.
 */
function ensureLedgerWatermarkTableCompatibility(db: DatabaseLike): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS local_runtime_ledger_watermarks (
      session_id TEXT PRIMARY KEY,
      last_seq INTEGER NOT NULL,
      last_event_id TEXT NOT NULL,
      updated_at_ms INTEGER NOT NULL
    );
  `);
  const columns = new Set(
    db
      .prepare('PRAGMA table_info(local_runtime_ledger_watermarks)')
      .all()
      .map((row) => (row as TableInfoRow).name)
      .filter((name): name is string => typeof name === 'string'),
  );
  if (!columns.has('last_byte_offset')) {
    db.exec('ALTER TABLE local_runtime_ledger_watermarks ADD COLUMN last_byte_offset INTEGER;');
  }
}

/**
 * One-time, idempotent back-fill: mint a UUID for every cron row whose
 * `cron_id` is still NULL. Wrapped in a transaction when available so the
 * sweep is atomic and re-entrant.
 */
function backfillCronIds(db: DatabaseLike): void {
  const apply = () => {
    const rows = db
      .prepare('SELECT agent_name, cron_name FROM local_runtime_crons WHERE cron_id IS NULL')
      .all() as Array<{ agent_name?: unknown; cron_name?: unknown }>;
    if (rows.length === 0) return;
    const update = db.prepare(
      'UPDATE local_runtime_crons SET cron_id = ? WHERE agent_name = ? AND cron_name = ? AND cron_id IS NULL',
    );
    for (const row of rows) {
      if (typeof row.agent_name !== 'string' || typeof row.cron_name !== 'string') continue;
      update.run(randomUUID(), row.agent_name, row.cron_name);
    }
  };
  if (db.transaction) {
    db.transaction(apply as () => unknown)();
    return;
  }
  apply();
}

function ensureTurnDiffTableCompatibility(db: DatabaseLike): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS local_runtime_turn_diffs (
      change_set_id TEXT PRIMARY KEY,
      session_id TEXT NOT NULL,
      turn_id TEXT NOT NULL,
      assistant_message_id TEXT,
      workspace_dir TEXT NOT NULL,
      captured_at_ms INTEGER NOT NULL,
      status TEXT NOT NULL,
      file_changes_json TEXT NOT NULL,
      raw_diff TEXT,
      reverted_at_ms INTEGER,
      UNIQUE(session_id, turn_id)
    );
    CREATE INDEX IF NOT EXISTS idx_local_runtime_turn_diffs_session_captured
      ON local_runtime_turn_diffs(session_id, captured_at_ms, change_set_id);
    CREATE INDEX IF NOT EXISTS idx_local_runtime_turn_diffs_session_assistant
      ON local_runtime_turn_diffs(session_id, assistant_message_id);

    CREATE TABLE IF NOT EXISTS local_runtime_turn_diff_journal (
      journal_id           TEXT PRIMARY KEY,
      row_type             TEXT NOT NULL,
      turn_id              TEXT NOT NULL,
      session_id           TEXT NOT NULL,
      agent_name           TEXT,
      workspace_dir        TEXT,
      start_message_row_id INTEGER,
      turn_status          TEXT,
      tool_call_id         TEXT,
      tool_name            TEXT,
      sequence             INTEGER,
      paths_json           TEXT NOT NULL DEFAULT '[]',
      before_json          TEXT NOT NULL DEFAULT '[]',
      after_json           TEXT NOT NULL DEFAULT '[]',
      tool_status          TEXT,
      ambiguity_reason     TEXT,
      created_at_ms        INTEGER NOT NULL,
      finalized_at_ms      INTEGER,
      completed_at_ms      INTEGER
    );
    CREATE INDEX IF NOT EXISTS idx_local_runtime_turn_diff_journal_pending
      ON local_runtime_turn_diff_journal(session_id, row_type, turn_status, created_at_ms);

    CREATE TABLE IF NOT EXISTS local_runtime_turn_diff_rewind_operations (
      operation_id TEXT PRIMARY KEY,
      session_id TEXT NOT NULL,
      plan_json TEXT NOT NULL,
      receipt_json TEXT,
      created_at_ms INTEGER NOT NULL,
      updated_at_ms INTEGER NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_local_runtime_turn_diff_rewind_session
      ON local_runtime_turn_diff_rewind_operations(session_id, updated_at_ms);
  `);
  ensureIndexColumns(
    db,
    'idx_local_runtime_turn_diff_journal_turn',
    ['session_id', 'turn_id', 'row_type'],
    `
    CREATE UNIQUE INDEX IF NOT EXISTS idx_local_runtime_turn_diff_journal_turn
      ON local_runtime_turn_diff_journal(session_id, turn_id, row_type)
      WHERE row_type = 'turn';
  `,
  );
  ensureIndexColumns(
    db,
    'idx_local_runtime_turn_diff_journal_tool',
    ['session_id', 'turn_id', 'tool_call_id'],
    `
    CREATE UNIQUE INDEX IF NOT EXISTS idx_local_runtime_turn_diff_journal_tool
      ON local_runtime_turn_diff_journal(session_id, turn_id, tool_call_id)
      WHERE row_type = 'tool';
  `,
  );
  ensureIndexColumns(
    db,
    'idx_local_runtime_turn_diff_journal_tools',
    ['session_id', 'turn_id', 'row_type', 'tool_status', 'sequence'],
    `
    CREATE INDEX IF NOT EXISTS idx_local_runtime_turn_diff_journal_tools
      ON local_runtime_turn_diff_journal(session_id, turn_id, row_type, tool_status, sequence);
  `,
  );
  const columns = new Set(
    db
      .prepare('PRAGMA table_info(local_runtime_turn_diffs)')
      .all()
      .map((row) => (row as TableInfoRow).name)
      .filter((name): name is string => typeof name === 'string'),
  );
  const addColumn = (name: string, definition: string) => {
    if (columns.has(name)) return;
    db.exec(`ALTER TABLE local_runtime_turn_diffs ADD COLUMN ${name} ${definition};`);
    columns.add(name);
  };
  addColumn('agent_name', 'TEXT');
  addColumn('undo_json', "TEXT NOT NULL DEFAULT '[]'");
  addColumn('undoable', 'INTEGER NOT NULL DEFAULT 0');
  addColumn('updated_at_ms', 'INTEGER');
  ensureTurnDiffRetentionQueue(db);
}

function ensureTurnDiffRetentionQueue(db: DatabaseLike): void {
  db.exec(`
    CREATE TABLE IF NOT EXISTS local_runtime_turn_diff_retention_queue (
      entry_kind TEXT NOT NULL CHECK (entry_kind IN ('turn', 'diff', 'rewind')),
      session_id TEXT NOT NULL,
      item_id TEXT NOT NULL,
      eligible_at_ms INTEGER NOT NULL,
      PRIMARY KEY (entry_kind, session_id, item_id)
    );
    CREATE INDEX IF NOT EXISTS idx_local_runtime_turn_diff_retention_due
      ON local_runtime_turn_diff_retention_queue(
        entry_kind, eligible_at_ms, session_id, item_id
      );

    CREATE TRIGGER IF NOT EXISTS trg_local_runtime_turn_diff_retention_turn_insert
    AFTER INSERT ON local_runtime_turn_diff_journal
    WHEN NEW.row_type = 'turn'
      AND NEW.turn_status IN ('finalized', 'empty', 'failed', 'superseded')
      AND NEW.finalized_at_ms IS NOT NULL
    BEGIN
      INSERT OR REPLACE INTO local_runtime_turn_diff_retention_queue
        (entry_kind, session_id, item_id, eligible_at_ms)
      VALUES ('turn', NEW.session_id, NEW.turn_id, NEW.finalized_at_ms);
    END;

    CREATE TRIGGER IF NOT EXISTS trg_local_runtime_turn_diff_retention_turn_update
    AFTER UPDATE OF row_type, turn_status, finalized_at_ms, session_id, turn_id
      ON local_runtime_turn_diff_journal
    WHEN NEW.row_type = 'turn'
      AND NEW.turn_status IN ('finalized', 'empty', 'failed', 'superseded')
      AND NEW.finalized_at_ms IS NOT NULL
    BEGIN
      DELETE FROM local_runtime_turn_diff_retention_queue
      WHERE entry_kind = 'turn'
        AND session_id = OLD.session_id
        AND item_id = OLD.turn_id
        AND OLD.row_type = 'turn';
      INSERT OR REPLACE INTO local_runtime_turn_diff_retention_queue
        (entry_kind, session_id, item_id, eligible_at_ms)
      VALUES ('turn', NEW.session_id, NEW.turn_id, NEW.finalized_at_ms);
    END;

    CREATE TRIGGER IF NOT EXISTS trg_local_runtime_turn_diff_retention_turn_ineligible
    AFTER UPDATE OF row_type, turn_status, finalized_at_ms, session_id, turn_id
      ON local_runtime_turn_diff_journal
    WHEN OLD.row_type = 'turn'
      AND (
        NEW.row_type != 'turn'
        OR NEW.turn_status NOT IN ('finalized', 'empty', 'failed', 'superseded')
        OR NEW.turn_status IS NULL
        OR NEW.finalized_at_ms IS NULL
      )
    BEGIN
      DELETE FROM local_runtime_turn_diff_retention_queue
      WHERE entry_kind = 'turn'
        AND session_id = OLD.session_id
        AND item_id = OLD.turn_id;
    END;

    CREATE TRIGGER IF NOT EXISTS trg_local_runtime_turn_diff_retention_turn_delete
    AFTER DELETE ON local_runtime_turn_diff_journal
    WHEN OLD.row_type = 'turn'
    BEGIN
      DELETE FROM local_runtime_turn_diff_retention_queue
      WHERE entry_kind = 'turn'
        AND session_id = OLD.session_id
        AND item_id = OLD.turn_id;
    END;

    CREATE TRIGGER IF NOT EXISTS trg_local_runtime_turn_diff_retention_diff_insert
    AFTER INSERT ON local_runtime_turn_diffs
    BEGIN
      INSERT OR REPLACE INTO local_runtime_turn_diff_retention_queue
        (entry_kind, session_id, item_id, eligible_at_ms)
      VALUES (
        'diff', NEW.session_id, NEW.turn_id,
        COALESCE(NEW.updated_at_ms, NEW.captured_at_ms)
      );
    END;

    CREATE TRIGGER IF NOT EXISTS trg_local_runtime_turn_diff_retention_diff_update
    AFTER UPDATE OF session_id, turn_id, captured_at_ms, updated_at_ms
      ON local_runtime_turn_diffs
    BEGIN
      DELETE FROM local_runtime_turn_diff_retention_queue
      WHERE entry_kind = 'diff'
        AND session_id = OLD.session_id
        AND item_id = OLD.turn_id;
      INSERT OR REPLACE INTO local_runtime_turn_diff_retention_queue
        (entry_kind, session_id, item_id, eligible_at_ms)
      VALUES (
        'diff', NEW.session_id, NEW.turn_id,
        COALESCE(NEW.updated_at_ms, NEW.captured_at_ms)
      );
    END;

    CREATE TRIGGER IF NOT EXISTS trg_local_runtime_turn_diff_retention_diff_delete
    AFTER DELETE ON local_runtime_turn_diffs
    BEGIN
      DELETE FROM local_runtime_turn_diff_retention_queue
      WHERE entry_kind = 'diff'
        AND session_id = OLD.session_id
        AND item_id = OLD.turn_id;
    END;

    CREATE TRIGGER IF NOT EXISTS trg_local_runtime_turn_diff_retention_rewind_insert
    AFTER INSERT ON local_runtime_turn_diff_rewind_operations
    WHEN NEW.receipt_json IS NOT NULL
    BEGIN
      INSERT OR REPLACE INTO local_runtime_turn_diff_retention_queue
        (entry_kind, session_id, item_id, eligible_at_ms)
      VALUES ('rewind', NEW.session_id, NEW.operation_id, NEW.updated_at_ms);
    END;

    CREATE TRIGGER IF NOT EXISTS trg_local_runtime_turn_diff_retention_rewind_update
    AFTER UPDATE OF session_id, operation_id, receipt_json, updated_at_ms
      ON local_runtime_turn_diff_rewind_operations
    WHEN NEW.receipt_json IS NOT NULL
    BEGIN
      DELETE FROM local_runtime_turn_diff_retention_queue
      WHERE entry_kind = 'rewind'
        AND session_id = OLD.session_id
        AND item_id = OLD.operation_id;
      INSERT OR REPLACE INTO local_runtime_turn_diff_retention_queue
        (entry_kind, session_id, item_id, eligible_at_ms)
      VALUES ('rewind', NEW.session_id, NEW.operation_id, NEW.updated_at_ms);
    END;

    CREATE TRIGGER IF NOT EXISTS trg_local_runtime_turn_diff_retention_rewind_ineligible
    AFTER UPDATE OF session_id, operation_id, receipt_json, updated_at_ms
      ON local_runtime_turn_diff_rewind_operations
    WHEN NEW.receipt_json IS NULL
    BEGIN
      DELETE FROM local_runtime_turn_diff_retention_queue
      WHERE entry_kind = 'rewind'
        AND session_id = OLD.session_id
        AND item_id = OLD.operation_id;
    END;

    CREATE TRIGGER IF NOT EXISTS trg_local_runtime_turn_diff_retention_rewind_delete
    AFTER DELETE ON local_runtime_turn_diff_rewind_operations
    BEGIN
      DELETE FROM local_runtime_turn_diff_retention_queue
      WHERE entry_kind = 'rewind'
        AND session_id = OLD.session_id
        AND item_id = OLD.operation_id;
    END;
  `);
}

function ensureIndexColumns(
  db: DatabaseLike,
  indexName: string,
  expectedColumns: string[],
  createSql: string,
): void {
  const currentColumns = db
    .prepare(`PRAGMA index_info('${indexName}')`)
    .all()
    .map((row) => (row as TableInfoRow).name)
    .filter((name): name is string => typeof name === 'string');
  if (
    currentColumns.length === expectedColumns.length &&
    currentColumns.every((column, index) => column === expectedColumns[index])
  ) {
    return;
  }
  db.exec(`DROP INDEX IF EXISTS ${indexName};`);
  db.exec(createSql);
}

function resolveDataDir(dataDir: DataDirInput): string {
  return typeof dataDir === 'function' ? dataDir() : dataDir;
}
function loadBetterSqlite3(): DatabaseConstructor {
  return loadBetterSqlite3Module<DatabaseConstructor>();
}
