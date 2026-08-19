PRAGMA foreign_keys=ON;

ALTER TABLE invoices ADD COLUMN ocr_provider TEXT;
ALTER TABLE invoices ADD COLUMN ocr_confidence REAL;
ALTER TABLE invoices ADD COLUMN ocr_verified INTEGER NOT NULL DEFAULT 0;
ALTER TABLE purchase_orders ADD COLUMN cost_centre_code TEXT;
ALTER TABLE purchase_orders ADD COLUMN budget_id INTEGER;
ALTER TABLE non_po_requests ADD COLUMN cost_centre_code TEXT;
ALTER TABLE non_po_requests ADD COLUMN budget_id INTEGER;
ALTER TABLE goods_receipt_notes ADD COLUMN cost_centre_code TEXT;

CREATE TABLE IF NOT EXISTS ocr_jobs(
  id INTEGER PRIMARY KEY,
  invoice_id INTEGER NOT NULL REFERENCES invoices(id),
  provider TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'Pending',
  provider_job_id TEXT,
  confidence REAL,
  error_message TEXT,
  requested_by INTEGER NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  completed_at TEXT
);

CREATE TABLE IF NOT EXISTS whatsapp_messages(
  id INTEGER PRIMARY KEY,
  recipient TEXT NOT NULL,
  template_name TEXT,
  message_text TEXT NOT NULL,
  related_type TEXT,
  related_id INTEGER,
  provider_message_id TEXT,
  status TEXT NOT NULL DEFAULT 'Pending',
  provider_response TEXT,
  created_by INTEGER NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  sent_at TEXT
);

CREATE TABLE IF NOT EXISTS cost_centres(
  id INTEGER PRIMARY KEY,
  code TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  department TEXT,
  owner_user_id INTEGER REFERENCES users(id),
  erp_external_id TEXT,
  active INTEGER NOT NULL DEFAULT 1,
  created_by INTEGER NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS budgets(
  id INTEGER PRIMARY KEY,
  budget_code TEXT UNIQUE NOT NULL,
  cost_centre_id INTEGER NOT NULL REFERENCES cost_centres(id),
  fiscal_year TEXT NOT NULL,
  category TEXT,
  allocated_amount REAL NOT NULL,
  committed_amount REAL NOT NULL DEFAULT 0,
  consumed_amount REAL NOT NULL DEFAULT 0,
  currency TEXT NOT NULL DEFAULT 'INR',
  status TEXT NOT NULL DEFAULT 'Active',
  created_by INTEGER NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS budget_transactions(
  id INTEGER PRIMARY KEY,
  budget_id INTEGER NOT NULL REFERENCES budgets(id),
  transaction_type TEXT NOT NULL,
  amount REAL NOT NULL,
  reference_type TEXT NOT NULL,
  reference_id INTEGER NOT NULL,
  note TEXT,
  created_by INTEGER NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS erp_sync_log(
  id INTEGER PRIMARY KEY,
  direction TEXT NOT NULL,
  entity_type TEXT NOT NULL,
  record_count INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL,
  endpoint TEXT,
  request_payload TEXT,
  response_payload TEXT,
  created_by INTEGER REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS persistent_sessions(
  token_hash TEXT PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES users(id),
  csrf_token TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  ip_address TEXT,
  user_agent TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  last_seen_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS security_events(
  id INTEGER PRIMARY KEY,
  event_type TEXT NOT NULL,
  username TEXT,
  user_id INTEGER REFERENCES users(id),
  ip_address TEXT,
  details TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS backup_log(
  id INTEGER PRIMARY KEY,
  file_name TEXT NOT NULL,
  file_sha256 TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  integrity_status TEXT NOT NULL,
  created_by INTEGER REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

