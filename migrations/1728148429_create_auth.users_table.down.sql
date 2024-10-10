drop trigger if exists auth_users_update_updated_at on auth.users;
drop table if exists auth.users;
drop schema if exists auth;
drop function if exists pgsql_fn_update_updated_at_timestamp;
