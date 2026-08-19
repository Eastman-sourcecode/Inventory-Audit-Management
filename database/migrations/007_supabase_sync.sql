CREATE TABLE IF NOT EXISTS supabase_sync_meta(
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS supabase_sync_state(
  source_table TEXT NOT NULL,
  source_id TEXT NOT NULL,
  payload_hash TEXT NOT NULL,
  active INTEGER NOT NULL DEFAULT 1,
  synced_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY(source_table,source_id)
);

CREATE TABLE IF NOT EXISTS supabase_sync_runs(
  id INTEGER PRIMARY KEY,
  started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  completed_at TEXT,
  status TEXT NOT NULL DEFAULT 'Running',
  records_uploaded INTEGER NOT NULL DEFAULT 0,
  records_deleted INTEGER NOT NULL DEFAULT 0,
  error TEXT
);

CREATE INDEX IF NOT EXISTS idx_supabase_sync_state_active
  ON supabase_sync_state(source_table,active);
