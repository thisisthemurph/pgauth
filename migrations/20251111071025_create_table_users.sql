-- +goose Up
-- +goose StatementBegin
create extension if not exists citext;

create table if not exists auth.users (
    id uuid primary key default gen_random_uuid(),
    email citext not null,
    password_hash text not null,
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

create unique index users_email_active_uniq
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
