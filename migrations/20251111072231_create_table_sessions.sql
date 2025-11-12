-- +goose Up
-- +goose StatementBegin
create table if not exists auth.sessions (
    id uuid primary key default gen_random_uuid (),
    user_id uuid references auth.users(id) on delete cascade,
    created_at timestamp not null default now (),
    expires_at timestamp not null,
    last_accessed_at timestamp,
    revoked_at timestamp,
    user_agent text,
    ip_address text
);

create index idx_sessions_user_id on auth.sessions(user_id);
create index idx_sessions_expires_at on auth.sessions(expires_at) where revoked_at is null;

-- +goose StatementEnd
-- +goose Down
-- +goose StatementBegin
drop table if exists auth.sessions;

-- +goose StatementEnd