PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS purchase_orders(
  id INTEGER PRIMARY KEY,
  po_number TEXT UNIQUE NOT NULL,
  po_date TEXT,
  vendor_code TEXT,
  vendor_name TEXT NOT NULL,
  department TEXT,
  currency TEXT NOT NULL DEFAULT 'INR',
  total_amount REAL NOT NULL DEFAULT 0,
  status TEXT NOT NULL DEFAULT 'Open',
  source TEXT NOT NULL DEFAULT 'Manual',
  created_by INTEGER NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS purchase_order_lines(
  id INTEGER PRIMARY KEY,
  purchase_order_id INTEGER NOT NULL REFERENCES purchase_orders(id) ON DELETE CASCADE,
  line_number INTEGER NOT NULL,
  material_code TEXT NOT NULL,
  material_description TEXT NOT NULL,
  ordered_qty REAL NOT NULL,
  unit TEXT NOT NULL,
  unit_price REAL NOT NULL DEFAULT 0,
  tax_rate REAL NOT NULL DEFAULT 0,
  received_qty REAL NOT NULL DEFAULT 0,
  UNIQUE(purchase_order_id,line_number)
);

CREATE TABLE IF NOT EXISTS invoices(
  id INTEGER PRIMARY KEY,
  invoice_number TEXT,
  invoice_date TEXT,
  vendor_name TEXT,
  purchase_order_id INTEGER REFERENCES purchase_orders(id),
  file_name TEXT NOT NULL,
  stored_path TEXT NOT NULL,
  mime_type TEXT,
  amount REAL,
  tax_amount REAL,
  ocr_status TEXT NOT NULL DEFAULT 'Pending',
  ocr_text TEXT,
  extracted_json TEXT,
  created_by INTEGER NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS non_po_requests(
  id INTEGER PRIMARY KEY,
  request_no TEXT UNIQUE NOT NULL,
  department TEXT NOT NULL,
  requester_id INTEGER NOT NULL REFERENCES users(id),
  vendor_name TEXT NOT NULL,
  justification TEXT NOT NULL,
  amount REAL NOT NULL DEFAULT 0,
  invoice_id INTEGER REFERENCES invoices(id),
  approver_id INTEGER REFERENCES users(id),
  status TEXT NOT NULL DEFAULT 'Pending Approval',
  approval_note TEXT,
  approved_at TEXT,
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS goods_receipt_notes(
  id INTEGER PRIMARY KEY,
  grn_number TEXT UNIQUE NOT NULL,
  receipt_type TEXT NOT NULL CHECK(receipt_type IN ('PO','Non-PO')),
  purchase_order_id INTEGER REFERENCES purchase_orders(id),
  non_po_request_id INTEGER REFERENCES non_po_requests(id),
  invoice_id INTEGER REFERENCES invoices(id),
  receipt_date TEXT NOT NULL,
  vendor_name TEXT NOT NULL,
  department TEXT,
  warehouse TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'Received',
  inspection_status TEXT NOT NULL DEFAULT 'Pending',
  observation_id INTEGER REFERENCES observations(id),
  created_by INTEGER NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS goods_receipt_lines(
  id INTEGER PRIMARY KEY,
  grn_id INTEGER NOT NULL REFERENCES goods_receipt_notes(id) ON DELETE CASCADE,
  po_line_id INTEGER REFERENCES purchase_order_lines(id),
  material_code TEXT NOT NULL,
  material_description TEXT NOT NULL,
  received_qty REAL NOT NULL,
  accepted_qty REAL NOT NULL,
  rejected_qty REAL NOT NULL DEFAULT 0,
  unit TEXT NOT NULL,
  batch_no TEXT,
  expiry_date TEXT,
  unit_cost REAL NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS inventory_stock(
  id INTEGER PRIMARY KEY,
  warehouse TEXT NOT NULL,
  material_code TEXT NOT NULL,
  material_description TEXT NOT NULL,
  unit TEXT NOT NULL,
  quantity REAL NOT NULL DEFAULT 0,
  average_cost REAL NOT NULL DEFAULT 0,
  updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
  UNIQUE(warehouse,material_code)
);

CREATE TABLE IF NOT EXISTS inventory_movements(
  id INTEGER PRIMARY KEY,
  movement_type TEXT NOT NULL,
  material_code TEXT NOT NULL,
  warehouse TEXT NOT NULL,
  quantity REAL NOT NULL,
  unit_cost REAL NOT NULL DEFAULT 0,
  reference_type TEXT NOT NULL,
  reference_id INTEGER NOT NULL,
  created_by INTEGER NOT NULL REFERENCES users(id),
  created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);

