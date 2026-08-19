create extension if not exists pgcrypto with schema extensions;

create table public.iam_roles (
  id bigint generated always as identity primary key,
  name text not null unique check (name in ('Admin','Manager','Auditor','Viewer'))
);

create table public.iam_profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  full_name text not null,
  role_id bigint not null references public.iam_roles(id),
  department text,
  active boolean not null default true,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

create table public.iam_vendors (
  id bigint generated always as identity primary key,
  vendor_code text not null unique,
  legal_name text not null,
  trade_name text,
  gstin_tax_id text,
  pan_registration_no text,
  contact_person text,
  email text,
  phone text,
  address_line text,
  city text,
  state text,
  postal_code text,
  country text not null default 'India',
  payment_terms text,
  department text,
  approval_status text not null default 'Pending' check (approval_status in ('Pending','Approved','Blocked')),
  active boolean not null default true,
  created_by uuid references public.iam_profiles(id),
  updated_by uuid references public.iam_profiles(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create unique index iam_vendors_gstin_unique on public.iam_vendors(gstin_tax_id) where gstin_tax_id is not null and gstin_tax_id <> '';
create index iam_vendors_name_idx on public.iam_vendors(lower(legal_name));

create table public.iam_cost_centres (
  id bigint generated always as identity primary key,
  code text not null unique,
  name text not null,
  department text,
  owner_id uuid references public.iam_profiles(id),
  erp_external_id text,
  active boolean not null default true,
  created_at timestamptz not null default now()
);

create table public.iam_budgets (
  id bigint generated always as identity primary key,
  budget_code text not null unique,
  cost_centre_id bigint not null references public.iam_cost_centres(id),
  fiscal_year text not null,
  category text,
  allocated_amount numeric(18,2) not null check (allocated_amount >= 0),
  committed_amount numeric(18,2) not null default 0 check (committed_amount >= 0),
  consumed_amount numeric(18,2) not null default 0 check (consumed_amount >= 0),
  currency char(3) not null default 'INR',
  status text not null default 'Active',
  created_at timestamptz not null default now(),
  check (committed_amount + consumed_amount <= allocated_amount)
);
create index iam_budgets_cost_centre_idx on public.iam_budgets(cost_centre_id, fiscal_year);

create table public.iam_purchase_orders (
  id bigint generated always as identity primary key,
  po_number text not null unique,
  po_date date,
  vendor_id bigint references public.iam_vendors(id),
  department text,
  cost_centre_id bigint references public.iam_cost_centres(id),
  budget_id bigint references public.iam_budgets(id),
  currency char(3) not null default 'INR',
  total_amount numeric(18,2) not null default 0,
  status text not null default 'Open',
  source text not null default 'Manual',
  created_by uuid references public.iam_profiles(id),
  created_at timestamptz not null default now()
);
create index iam_purchase_orders_vendor_idx on public.iam_purchase_orders(vendor_id);
create index iam_purchase_orders_status_idx on public.iam_purchase_orders(status, po_date desc);

create table public.iam_purchase_order_lines (
  id bigint generated always as identity primary key,
  purchase_order_id bigint not null references public.iam_purchase_orders(id) on delete cascade,
  line_number integer not null,
  material_code text not null,
  material_description text not null,
  ordered_qty numeric(18,3) not null check (ordered_qty >= 0),
  received_qty numeric(18,3) not null default 0 check (received_qty >= 0),
  unit text not null,
  unit_price numeric(18,4) not null default 0,
  tax_rate numeric(8,4) not null default 0,
  unique (purchase_order_id,line_number)
);
create index iam_po_lines_material_idx on public.iam_purchase_order_lines(material_code);

create table public.iam_invoices (
  id bigint generated always as identity primary key,
  invoice_number text,
  invoice_date date,
  vendor_id bigint references public.iam_vendors(id),
  purchase_order_id bigint references public.iam_purchase_orders(id),
  file_name text not null,
  storage_path text not null,
  mime_type text,
  amount numeric(18,2),
  tax_amount numeric(18,2),
  file_sha256 text,
  duplicate_status text not null default 'Unique',
  duplicate_of bigint references public.iam_invoices(id),
  ocr_status text not null default 'Pending',
  ocr_provider text,
  ocr_confidence numeric(6,5),
  ocr_text text,
  extracted_json jsonb not null default '{}'::jsonb,
  created_by uuid references public.iam_profiles(id),
  created_at timestamptz not null default now()
);
create index iam_invoices_po_idx on public.iam_invoices(purchase_order_id);
create index iam_invoices_hash_idx on public.iam_invoices(file_sha256) where file_sha256 is not null;
create index iam_invoices_number_vendor_idx on public.iam_invoices(invoice_number,vendor_id);

create table public.iam_non_po_requests (
  id bigint generated always as identity primary key,
  request_no text not null unique,
  department text not null,
  requester_id uuid references public.iam_profiles(id),
  vendor_id bigint references public.iam_vendors(id),
  cost_centre_id bigint references public.iam_cost_centres(id),
  budget_id bigint references public.iam_budgets(id),
  justification text not null,
  amount numeric(18,2) not null default 0,
  invoice_id bigint references public.iam_invoices(id),
  approver_id uuid references public.iam_profiles(id),
  status text not null default 'Pending Approval',
  approval_note text,
  approved_at timestamptz,
  created_at timestamptz not null default now()
);
create index iam_non_po_status_idx on public.iam_non_po_requests(status,department);

create table public.iam_observations (
  id bigint generated always as identity primary key,
  reference_no text not null unique,
  title text not null,
  description text,
  site text,
  department text,
  category text,
  severity text not null,
  status text not null default 'Open',
  owner_id uuid references public.iam_profiles(id),
  due_date date,
  created_by uuid references public.iam_profiles(id),
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);
create index iam_observations_status_idx on public.iam_observations(status,severity,due_date);

create table public.iam_grns (
  id bigint generated always as identity primary key,
  grn_number text not null unique,
  receipt_type text not null check (receipt_type in ('PO','Non-PO')),
  purchase_order_id bigint references public.iam_purchase_orders(id),
  non_po_request_id bigint references public.iam_non_po_requests(id),
  invoice_id bigint references public.iam_invoices(id),
  vendor_id bigint references public.iam_vendors(id),
  cost_centre_id bigint references public.iam_cost_centres(id),
  receipt_date date not null,
  department text,
  warehouse text not null,
  status text not null default 'Received',
  inspection_status text not null default 'Pending',
  industry_profile_code text not null default 'MANUFACTURING',
  compliance_status text not null default 'Pending',
  gap_count integer not null default 0,
  observation_id bigint references public.iam_observations(id),
  created_by uuid references public.iam_profiles(id),
  created_at timestamptz not null default now()
);
create index iam_grns_source_idx on public.iam_grns(purchase_order_id,non_po_request_id);
create index iam_grns_receipt_idx on public.iam_grns(receipt_date desc,warehouse);

create table public.iam_grn_lines (
  id bigint generated always as identity primary key,
  grn_id bigint not null references public.iam_grns(id) on delete cascade,
  po_line_id bigint references public.iam_purchase_order_lines(id),
  material_code text not null,
  material_description text not null,
  received_qty numeric(18,3) not null,
  accepted_qty numeric(18,3) not null,
  rejected_qty numeric(18,3) not null default 0,
  unit text not null,
  batch_no text,
  expiry_date date,
  unit_cost numeric(18,4) not null default 0,
  check (accepted_qty + rejected_qty <= received_qty)
);
create index iam_grn_lines_material_idx on public.iam_grn_lines(material_code,grn_id);

create table public.iam_inventory_stock (
  id bigint generated always as identity primary key,
  warehouse text not null,
  material_code text not null,
  material_description text not null,
  unit text not null,
  quantity numeric(18,3) not null default 0,
  average_cost numeric(18,4) not null default 0,
  updated_at timestamptz not null default now(),
  unique (warehouse,material_code)
);

create table public.iam_incidents (
  id bigint generated always as identity primary key,
  incident_no text not null unique,
  observation_id bigint references public.iam_observations(id),
  title text not null,
  description text,
  severity text not null,
  status text not null default 'Open',
  owner_id uuid references public.iam_profiles(id),
  created_by uuid references public.iam_profiles(id),
  created_at timestamptz not null default now()
);

create table public.iam_capas (
  id bigint generated always as identity primary key,
  capa_no text not null unique,
  observation_id bigint references public.iam_observations(id),
  incident_id bigint references public.iam_incidents(id),
  action_type text not null,
  action text not null,
  owner_id uuid references public.iam_profiles(id),
  target_date date,
  status text not null default 'Open',
  effectiveness_review text,
  created_by uuid references public.iam_profiles(id),
  created_at timestamptz not null default now()
);

create table public.iam_gap_checks (
  id bigint generated always as identity primary key,
  grn_id bigint not null references public.iam_grns(id) on delete cascade,
  rule_code text not null,
  check_name text not null,
  expected_value text,
  actual_value text,
  variance_value numeric,
  result text not null check (result in ('Pass','Gap','Warning')),
  severity text not null,
  gap_category text not null,
  resolution_status text not null default 'Open',
  resolution_note text,
  observation_id bigint references public.iam_observations(id),
  checked_at timestamptz not null default now()
);
create index iam_gap_checks_open_idx on public.iam_gap_checks(grn_id,resolution_status) where result <> 'Pass';

create table public.iam_audit_trail (
  id bigint generated always as identity primary key,
  user_id uuid references public.iam_profiles(id),
  action text not null,
  entity_type text not null,
  entity_id bigint,
  details jsonb not null default '{}'::jsonb,
  ip_address inet,
  created_at timestamptz not null default now()
);
create index iam_audit_entity_idx on public.iam_audit_trail(entity_type,entity_id,created_at desc);
create index iam_audit_user_idx on public.iam_audit_trail(user_id,created_at desc);

insert into public.iam_roles(name) values ('Admin'),('Manager'),('Auditor'),('Viewer') on conflict do nothing;

do $$
declare t text;
begin
  foreach t in array array['iam_roles','iam_profiles','iam_vendors','iam_cost_centres','iam_budgets','iam_purchase_orders','iam_purchase_order_lines','iam_invoices','iam_non_po_requests','iam_observations','iam_grns','iam_grn_lines','iam_inventory_stock','iam_incidents','iam_capas','iam_gap_checks','iam_audit_trail']
  loop execute format('alter table public.%I enable row level security',t); end loop;
end $$;

revoke all on all tables in schema public from anon, authenticated;
grant usage on schema public to service_role;
grant all on all tables in schema public to service_role;
grant all on all sequences in schema public to service_role;

