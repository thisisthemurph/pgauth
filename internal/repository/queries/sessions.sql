-- name: CreateSession :one
insert into auth.sessions (user_id, expires_at, ip_address) 
values ($1, $2, $3)
returning *;

-- name: ValidateSession :one
select * from auth.sessions where id = $1 and revoked_at is null;

-- name: RevokeSession :exec
update auth.sessions set revoked_at = now() where id = $1;

-- name: RevokeAllUserSessions :exec
update auth.sessions set revoked_at = now() where user_id = $1;

-- name: ResetSession :one
update auth.sessions 
set expires_at = $1,
    last_accessed_at = now() 
where id = $2
returning *;

-- name: RegisterRefreshToken :exec
insert into auth.refresh_tokens (user_id, hashed_token, expires_at)
values ($1, $2, $3);

-- name: GetRefreshToken :one
select *
from auth.refresh_tokens
where hashed_token = $1
    and user_id = $2
    and revoked = false
    and expires_at > now()
limit 1;

-- name: GetRefreshTokensByUserID :many
select *
from auth.refresh_tokens
where user_id = $1
    and revoked = false
    and expires_at > now();

-- name: DeleteRefreshToken :exec
delete from auth.refresh_tokens where id = $1;

-- name: InvalidateRefreshToken :exec
update auth.refresh_tokens
set revoked = true
where id = $1;
