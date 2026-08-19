CREATE TABLE IF NOT EXISTS supabase_file_sync_state(
  entity_type TEXT NOT NULL,
  entity_id TEXT NOT NULL,
  local_path TEXT NOT NULL,
  object_path TEXT,
  sha256 TEXT,
  size_bytes INTEGER,
  status TEXT NOT NULL DEFAULT 'Pending',
  attempts INTEGER NOT NULL DEFAULT 0,
  last_error TEXT,
  synced_at TEXT,
  PRIMARY KEY(entity_type,entity_id)
);

CREATE TABLE IF NOT EXISTS supabase_sync_failures(
  id INTEGER PRIMARY KEY,
  sync_type TEXT NOT NULL,
  source_table TEXT,
  source_id TEXT,
  error TEXT NOT NULL,
  attempt_count INTEGER NOT NULL DEFAULT 1,
  resolved INTEGER NOT NULL DEFAULT 0,
  first_failed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_failed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  resolved_at TEXT,
  UNIQUE(sync_type,source_table,source_id,resolved)
);

CREATE TABLE IF NOT EXISTS supabase_reconciliation_runs(
  id INTEGER PRIMARY KEY,
  checked_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  local_records INTEGER NOT NULL,
  remote_records INTEGER NOT NULL,
  matched_records INTEGER NOT NULL,
  missing_remote INTEGER NOT NULL,
  extra_remote INTEGER NOT NULL,
  hash_mismatches INTEGER NOT NULL,
  local_files INTEGER NOT NULL,
  remote_files INTEGER NOT NULL,
  matched_files INTEGER NOT NULL,
  status TEXT NOT NULL,
  details_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_supabase_failures_open
  ON supabase_sync_failures(resolved,last_failed_at);
