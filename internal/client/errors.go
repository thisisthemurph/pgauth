package client

import "errors"

var (
	ErrBadRequest         = errors.New("bad request")
	ErrInvalidCredentials = errors.New("email and password combination does not match")
	ErrDuplicateEmail     = errors.New("user already exists with the given email address")
	ErrEmailNotConfirmed  = errors.New("email not confimed")
	ErrInvalidEmail       = errors.New("invalid email address")
	ErrInvalidPassword    = errors.New("invalid password")
	ErrInvalidToken       = errors.New("token is invalid or has expired")
	ErrUserNotFound       = errors.New("user not found")
)
