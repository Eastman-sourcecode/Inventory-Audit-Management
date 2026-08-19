create table public.iam_sync_records (
  id bigint generated always as identity primary key,
  source_instance uuid not null,
  source_table text not null check (source_table ~ '^[a-z][a-z0-9_]{0,62}$'),
  source_id text not null,
  payload jsonb,
  payload_hash char(64) not null check (payload_hash ~ '^[0-9a-f]{64}$'),
  deleted_at timestamptz,
  synced_at timestamptz not null default now(),
  unique (source_instance, source_table, source_id)
);

create index iam_sync_records_table_idx
  on public.iam_sync_records(source_instance, source_table, synced_at desc);

create index iam_sync_records_active_idx
  on public.iam_sync_records(source_instance, synced_at desc)
  where deleted_at is null;

alter table public.iam_sync_records enable row level security;
revoke all on public.iam_sync_records from anon, authenticated;
grant all on public.iam_sync_records to service_role;
grant usage, select on sequence public.iam_sync_records_id_seq to service_role;

comment on table public.iam_sync_records is
  'Server-only mirror of local Inventory Audit Management business records. Secret/authentication tables are excluded.';
