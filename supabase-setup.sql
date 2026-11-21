-- Thai Docs Tracker: Supabase setup
-- Run once in Supabase > SQL Editor > New query > Run

-- 1) Tables -----------------------------------------------------------
create table public.profiles (
  id          uuid primary key references auth.users(id) on delete cascade,
  name        text,
  city        text,
  lang        text not null default 'my',
  suspended   boolean not null default false,
  created_at  timestamptz not null default now(),
  last_active timestamptz not null default now()
);

create table public.documents (
  id         uuid primary key default gen_random_uuid(),
  user_id    uuid not null references auth.users(id) on delete cascade,
  cat        text not null check (cat in ('r90','visa','passport','license','permit','other')),
  name       text,
  date       date not null,          -- last report date (r90) or expiry date
  rem        int  not null default 14, -- remind this many days before
  note       text,
  photo_path text,                   -- path inside the doc-photos bucket
  created_at timestamptz not null default now()
);
create index on public.documents (user_id);

create table public.admins (
  user_id uuid primary key references auth.users(id) on delete cascade
);

-- 2) Helper: is the current user an admin? ----------------------------
create or replace function public.is_admin()
returns boolean language sql security definer set search_path = public stable as $$
  select exists (select 1 from public.admins where user_id = auth.uid());
$$;

-- 3) Create a profile automatically when someone signs up -------------
create or replace function public.handle_new_user()
returns trigger language plpgsql security definer set search_path = public as $$
begin
  insert into public.profiles (id, name) values (new.id, new.raw_user_meta_data->>'name');
  return new;
end $$;
create trigger on_auth_user_created after insert on auth.users
  for each row execute function public.handle_new_user();

-- 4) Row-level security ----------------------------------------------
alter table public.profiles  enable row level security;
alter table public.documents enable row level security;
alter table public.admins    enable row level security;

-- clients: own rows only
create policy "own profile read"   on public.profiles  for select using (id = auth.uid());
create policy "own profile update" on public.profiles  for update using (id = auth.uid()) with check (id = auth.uid() and suspended = false);
create policy "own docs all"       on public.documents for all    using (user_id = auth.uid()) with check (user_id = auth.uid());

-- admins: read everything, suspend/restore users
create policy "admin read profiles"   on public.profiles  for select using (public.is_admin());
create policy "admin update profiles" on public.profiles  for update using (public.is_admin());
create policy "admin read docs"       on public.documents for select using (public.is_admin());
create policy "admin check self"      on public.admins    for select using (user_id = auth.uid());

-- 5) Dashboard numbers for the admin site -----------------------------
create or replace function public.admin_stats()
returns json language plpgsql security definer set search_path = public as $$
begin
  if not public.is_admin() then raise exception 'not allowed'; end if;
  return json_build_object(
    'total_users',  (select count(*) from profiles),
    'active_7d',    (select count(*) from profiles where last_active > now() - interval '7 days' and not suspended),
    'new_30d',      (select count(*) from profiles where created_at > now() - interval '30 days'),
    'documents',    (select count(*) from documents),
    'overdue_users',(select count(distinct user_id) from documents
                     where (case when cat = 'r90' then date + 90 else date end) < current_date),
    'by_type',      (select coalesce(json_object_agg(cat, n), '{}'::json) from
                     (select cat, count(*) n from documents group by cat) t)
  );
end $$;

-- 6) Private bucket for document photos -------------------------------
insert into storage.buckets (id, name, public) values ('doc-photos', 'doc-photos', false)
on conflict do nothing;

-- each user can only touch files inside a folder named with their own user id
create policy "own photos read"   on storage.objects for select
  using (bucket_id = 'doc-photos' and (storage.foldername(name))[1] = auth.uid()::text);
create policy "own photos insert" on storage.objects for insert
  with check (bucket_id = 'doc-photos' and (storage.foldername(name))[1] = auth.uid()::text);
create policy "own photos delete" on storage.objects for delete
  using (bucket_id = 'doc-photos' and (storage.foldername(name))[1] = auth.uid()::text);

-- 7) Make yourself the admin (do this AFTER you sign up once) ----------
-- insert into public.admins (user_id)
-- select id from auth.users where email = 'YOUR-EMAIL@example.com';
