PRAGMA foreign_keys=ON;

ALTER TABLE invoices ADD COLUMN file_sha256 TEXT;
ALTER TABLE invoices ADD COLUMN duplicate_status TEXT DEFAULT 'Unique';
ALTER TABLE invoices ADD COLUMN duplicate_of INTEGER REFERENCES invoices(id);
ALTER TABLE users ADD COLUMN must_change_password INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN updated_at TEXT;

CREATE TABLE IF NOT EXISTS approval_workflows(
  id INTEGER PRIMARY KEY,
  workflow_code TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  entity_type TEXT NOT NULL,
  department TEXT,
  min_amount REAL,
  max_amount REAL,
  active INTEGER NOT NULL DEFAULT 1,
  created_by INTEGER NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS approval_steps(
  id INTEGER PRIMARY KEY,
  workflow_id INTEGER NOT NULL REFERENCES approval_workflows(id) ON DELETE CASCADE,
  step_order INTEGER NOT NULL,
  step_name TEXT NOT NULL,
  approver_role TEXT NOT NULL,
  approver_user_id INTEGER REFERENCES users(id),
  sla_hours INTEGER NOT NULL DEFAULT 24,
  UNIQUE(workflow_id,step_order)
);

CREATE TABLE IF NOT EXISTS approval_instances(
  id INTEGER PRIMARY KEY,
  workflow_id INTEGER NOT NULL REFERENCES approval_workflows(id),
  entity_type TEXT NOT NULL,
  entity_id INTEGER NOT NULL,
  current_step INTEGER NOT NULL DEFAULT 1,
  status TEXT NOT NULL DEFAULT 'Pending',
  requested_by INTEGER NOT NULL REFERENCES users(id),
  requested_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  completed_at TEXT,
  UNIQUE(entity_type,entity_id,workflow_id)
);

CREATE TABLE IF NOT EXISTS approval_actions(
  id INTEGER PRIMARY KEY,
  instance_id INTEGER NOT NULL REFERENCES approval_instances(id) ON DELETE CASCADE,
  step_order INTEGER NOT NULL,
  action TEXT NOT NULL,
  note TEXT,
  acted_by INTEGER REFERENCES users(id),
  acted_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS approval_link_tokens(
  id INTEGER PRIMARY KEY,
  instance_id INTEGER NOT NULL REFERENCES approval_instances(id) ON DELETE CASCADE,
  token_hash TEXT UNIQUE NOT NULL,
  expires_at TEXT NOT NULL,
  used_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS transaction_controls(
  id INTEGER PRIMARY KEY,
  entity_type TEXT NOT NULL,
  entity_id INTEGER NOT NULL,
  control_status TEXT NOT NULL DEFAULT 'Draft',
  review_note TEXT,
  reviewed_by INTEGER REFERENCES users(id),
  approved_by INTEGER REFERENCES users(id),
  closed_by INTEGER REFERENCES users(id),
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(entity_type,entity_id)
);

CREATE TABLE IF NOT EXISTS notification_outbox(
  id INTEGER PRIMARY KEY,
  channel TEXT NOT NULL DEFAULT 'email',
  recipient TEXT NOT NULL,
  subject TEXT NOT NULL,
  body TEXT NOT NULL,
  related_type TEXT,
  related_id INTEGER,
  status TEXT NOT NULL DEFAULT 'Pending',
  provider_message TEXT,
  attempts INTEGER NOT NULL DEFAULT 0,
  created_by INTEGER REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  sent_at TEXT
);

CREATE TABLE IF NOT EXISTS document_access_log(
  id INTEGER PRIMARY KEY,
  invoice_id INTEGER NOT NULL REFERENCES invoices(id),
  user_id INTEGER NOT NULL REFERENCES users(id),
  action TEXT NOT NULL,
  ip_address TEXT,
  accessed_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

