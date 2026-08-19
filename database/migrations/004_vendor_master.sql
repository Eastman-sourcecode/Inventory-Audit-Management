PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS vendors(
  id INTEGER PRIMARY KEY,
  vendor_code TEXT UNIQUE NOT NULL,
  legal_name TEXT NOT NULL,
  trade_name TEXT,
  gstin_tax_id TEXT,
  pan_registration_no TEXT,
  contact_person TEXT,
  email TEXT,
  phone TEXT,
  address_line TEXT,
  city TEXT,
  state TEXT,
  postal_code TEXT,
  country TEXT NOT NULL DEFAULT 'India',
  payment_terms TEXT,
  department TEXT,
  approval_status TEXT NOT NULL DEFAULT 'Pending',
  active INTEGER NOT NULL DEFAULT 1,
  created_by INTEGER NOT NULL REFERENCES users(id),
  updated_by INTEGER REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

