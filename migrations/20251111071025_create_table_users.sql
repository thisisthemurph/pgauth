-- +goose Up
-- +goose StatementBegin
create extension if not exists citext;

create table if not exists auth.users (
    id uuid primary key default gen_random_uuid(),
    email citext not null,
    email_confirmed_at timestamp with time zone,
    password_hash text not null,
    user_data jsonb not null,
    -- signup confirmation
    confirmation_token text, 
    confirmation_token_created_at timestamp with time zone,
    -- email change
    email_change text,
    email_change_token text,
    email_change_requested_at timestamp with time zone,
    -- password change
    password_change text,
    password_change_token text,
    password_change_requested_at timestamp with time zone,
    -- general OTP
    encrypted_otp text,
    otp_created_at timestamp with time zone,
    -- metadata
    created_at timestamp with time zone not null default now(),
    updated_at timestamp with time zone not null default now(),
    deleted_at timestamp with time zone
);

create unique index if not exists users_email_active_uniq
    on auth.users (email)
    where deleted_at is null;

create trigger auth_users_set_updated_at
    before update on auth.users
    for each row
execute function pgsql_fn_set_updated_at_timestamp();

-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
drop table if exists auth.users;
drop extension if exists citext;
-- +goose StatementEnd
