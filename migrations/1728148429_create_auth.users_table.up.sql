create or replace function pgsql_fn_update_updated_at_timestamp()
    returns trigger as $$
begin
    new.updated_at = current_timestamp;
    return new;
end;
$$ language plpgsql;

create extension if not exists "uuid-ossp";

create schema if not exists auth;

create table if not exists auth.users (
    id uuid primary key default uuid_generate_v4(),
    email text unique not null,
    encrypted_password text not null,
    email_confirmed_at timestamp with time zone,
    confirmation_token text,
    confirmation_token_created_at timestamp with time zone,
    email_change text,
    email_change_token text,
    email_change_requested_at timestamp with time zone,
    password_change text,
    password_change_token text,
    password_change_requested_at timestamp with time zone,
    encrypted_otp text,
    otp_created_at timestamp with time zone,
    created_at timestamp with time zone not null default now(),
    updated_at timestamp with time zone not null default now(),
    deleted_at timestamp with time zone
);

create trigger auth_users_update_updated_at
    before update on auth.users
    for each row
execute function pgsql_fn_update_updated_at_timestamp();
