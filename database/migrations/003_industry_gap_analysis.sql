PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS industry_profiles(
  id INTEGER PRIMARY KEY,
  code TEXT UNIQUE NOT NULL,
  name TEXT NOT NULL,
  description TEXT,
  active INTEGER NOT NULL DEFAULT 1
);

CREATE TABLE IF NOT EXISTS compliance_rules(
  id INTEGER PRIMARY KEY,
  industry_profile_id INTEGER NOT NULL REFERENCES industry_profiles(id),
  rule_code TEXT NOT NULL,
  rule_name TEXT NOT NULL,
  applies_to TEXT NOT NULL DEFAULT 'Both',
  parameter_value TEXT,
  severity TEXT NOT NULL DEFAULT 'Medium',
  enabled INTEGER NOT NULL DEFAULT 1,
  UNIQUE(industry_profile_id,rule_code)
);

CREATE TABLE IF NOT EXISTS grn_compliance_checks(
  id INTEGER PRIMARY KEY,
  grn_id INTEGER NOT NULL REFERENCES goods_receipt_notes(id) ON DELETE CASCADE,
  industry_profile_id INTEGER REFERENCES industry_profiles(id),
  rule_code TEXT NOT NULL,
  check_name TEXT NOT NULL,
  expected_value TEXT,
  actual_value TEXT,
  variance_value REAL,
  result TEXT NOT NULL CHECK(result IN ('Pass','Gap','Warning')),
  severity TEXT NOT NULL,
  gap_category TEXT NOT NULL,
  resolution_status TEXT NOT NULL DEFAULT 'Open',
  resolution_note TEXT,
  observation_id INTEGER REFERENCES observations(id),
  checked_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

ALTER TABLE goods_receipt_notes ADD COLUMN industry_profile_code TEXT DEFAULT 'MANUFACTURING';
ALTER TABLE goods_receipt_notes ADD COLUMN compliance_status TEXT DEFAULT 'Pending';
ALTER TABLE goods_receipt_notes ADD COLUMN gap_count INTEGER DEFAULT 0;

