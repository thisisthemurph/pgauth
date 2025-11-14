-- name: UserExists :one
select exists (select 1 from auth.users where id = $1);

-- name: UserExistsWithEmail :one
select exists (select 1 from auth.users where email = $1);

-- name: GetUserByID :one
-- GetUserByID returns the non-deleted user by their id
select * from auth.users where id = $1 and deleted_at is null;

-- name: GetUserByEmail :one
-- GetUserByEmail returns the non-deleted user by their email address
select * from auth.users where email = $1 and deleted_at is null limit 1;

-- name: GetUserByPasswordChangeToken :one
select * from auth.users
where password_change_token is not null
    and password_change_token = cast($1 as text)
    and deleted_at is null
limit 1;

-- name: GetPasswordHash :one
-- GetPasswordHash returns the user's hashed password
select password_hash from auth.users where id = $1 limit 1;

-- name: CreateUser :one
insert into auth.users (email, password_hash, user_data, confirmation_token, confirmation_token_created_at) 
values ($1, $2, $3, $4, now()) 
returning *;

-- name: SetUserSignupAsConfirmed :exec
update auth.users
set confirmation_token = null,
    confirmation_token_created_at = null,
    email_confirmed_at = now()
where id = $1;

-- name: InitiateEmailUpdate :exec
update auth.users 
set email_change = $1, 
    email_change_token = $2,
    email_change_requested_at = now(),
    encrypted_otp = $3,
    otp_created_at = now()
where id = $4;

-- name: CompleteEmailUpdate :exec
update auth.users
set email = email_change,
    email_change = null,
    email_change_token = null,
    email_change_requested_at = null,
    encrypted_otp = null,
    otp_created_at = null
where id = $1;

-- name: InitiatePasswordUpdate :exec
update auth.users
set password_change = $1,
    password_change_token = $2,
    password_change_requested_at = now(),
    encrypted_otp = $3,
    otp_created_at = now()
where id = $4;

-- name: CompletePasswordUpdate :exec
update auth.users
set password_hash = password_change,
    password_change = null,
    password_change_token = null,
    password_change_requested_at = null,
    encrypted_otp = null,
    otp_created_at = null
where id = $1;

-- name: InitiatePasswordReset :exec
update auth.users
set password_change_token = $2,
    password_change_requested_at = now()
where id = $1;

-- name: CompletePasswordReset :exec
update auth.users
set password_change_token = null,
    password_hash = $2,
    password_change_requested_at = null
where id = $1;

-- name: DeleteUserById :one
delete from auth.users where id = $1 returning *;

-- name: SoftDeleteUserById :one
update auth.users set deleted_at = now() where id = $1 returning *;
