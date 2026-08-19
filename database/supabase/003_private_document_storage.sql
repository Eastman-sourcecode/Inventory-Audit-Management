insert into storage.buckets(id,name,public)
values ('iam-private-documents','iam-private-documents',false)
on conflict(id) do update set public=false;

create table public.iam_sync_files (
  id bigint generated always as identity primary key,
  source_instance uuid not null,
  entity_type text not null,
  entity_id text not null,
  bucket_id text not null default 'iam-private-documents',
  object_path text not null,
  original_name text not null,
  mime_type text,
  size_bytes bigint not null check(size_bytes >= 0),
  sha256 char(64) not null check(sha256 ~ '^[0-9a-f]{64}$'),
  uploaded_at timestamptz not null default now(),
  verified_at timestamptz,
  status text not null default 'Uploaded' check(status in ('Uploaded','Verified','Missing','Failed')),
  last_error text,
  unique(source_instance,entity_type,entity_id),
  unique(bucket_id,object_path)
);

create index iam_sync_files_status_idx
  on public.iam_sync_files(source_instance,status,uploaded_at desc);

alter table public.iam_sync_files enable row level security;
revoke all on public.iam_sync_files from anon, authenticated;
grant all on public.iam_sync_files to service_role;
grant usage, select on sequence public.iam_sync_files_id_seq to service_role;

comment on table public.iam_sync_files is
  'Server-only integrity metadata for private Inventory Audit Management documents in Supabase Storage.';
