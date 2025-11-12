-- +goose Up
-- +goose StatementBegin
create or replace function pgsql_fn_set_updated_at_timestamp()
    returns trigger as $$
begin
    new.updated_at = current_timestamp;
    return new;
end;
$$ language plpgsql;

create extension if not exists pgcrypto;

create schema if not exists auth;
-- +goose StatementEnd

-- +goose Down
-- +goose StatementBegin
drop schema if exists auth;
drop extension if exists pgcrypto;
drop function if exists pgsql_fn_set_updated_at_timestamp;
-- +goose StatementEnd
