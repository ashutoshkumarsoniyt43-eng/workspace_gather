-- Gather workspace schema for Supabase.
-- Run this once in the Supabase SQL Editor for the project used by Vercel.

create table if not exists public.team_users (
  id text primary key,
  name text not null,
  email text not null unique,
  password_hash text not null,
  role text not null default 'member' check (role in ('admin','member')),
  active boolean not null default true,
  avatar_path text not null default '',
  created_at timestamptz not null default now()
);

create table if not exists public.sessions (
  token_hash text primary key,
  user_id text not null references public.team_users(id) on delete cascade,
  expires_at timestamptz not null
);
create index if not exists sessions_user_id_idx on public.sessions(user_id);

create table if not exists public.records (
  id text primary key,
  kind text not null check (kind in ('tasks','reminders','meetings','updates','goals')),
  owner_id text not null references public.team_users(id) on delete cascade,
  data jsonb not null default '{}'::jsonb,
  created_at timestamptz not null default now()
);
create index if not exists records_kind_created_idx on public.records(kind, created_at desc);

create table if not exists public.files (
  id text primary key,
  owner_id text not null references public.team_users(id) on delete cascade,
  filename text not null,
  stored_path text not null unique,
  size bigint not null check (size >= 0 and size <= 20971520),
  content_type text not null,
  description text not null default '',
  created_at timestamptz not null default now()
);

create table if not exists public.settings (
  key text primary key,
  value text not null
);
insert into public.settings(key,value) values ('workspace_name','Studio North') on conflict (key) do nothing;

alter table public.team_users enable row level security;
alter table public.sessions enable row level security;
alter table public.records enable row level security;
alter table public.files enable row level security;
alter table public.settings enable row level security;

-- The Vercel API uses the Supabase server-side secret key and performs access
-- checks itself. No browser-facing policies are created for these tables.
insert into storage.buckets (id, name, public, file_size_limit)
values ('gather-private', 'gather-private', false, 20971520)
on conflict (id) do update set public = false, file_size_limit = 20971520;
