package pgauth

import "errors"

// ErrPasswordChangeNotRequested indicates that the user has not been correctly initialized for a password change.
var ErrPasswordChangeNotRequested = errors.New("password change not requested")

// ErrInvalidCredentials indicates that the provided email and password combination does not match any user.
var ErrInvalidCredentials = errors.New("email and password combination does not match")

// ErrDuplicateEmail indicates that a user already exists with the given email address.
var ErrDuplicateEmail = errors.New("user already exists with the given email address")

// ErrEmailNotConfirmed indicates that the user's email address has not been confirmed.
var ErrEmailNotConfirmed = errors.New("email not confirmed")

// ErrInvalidEmail indicates that the provided email address is not valid.
var ErrInvalidEmail = errors.New("invalid email address")

// ErrInvalidPassword indicates that the provided password does not meet requirements or is incorrect.
var ErrInvalidPassword = errors.New("invalid password")

// ErrInvalidToken indicates that the provided token is invalid or has expired.
var ErrInvalidToken = errors.New("token is invalid or has expired")

// ErrUserNotFound indicates that no user was found with the given identifier.
var ErrUserNotFound = errors.New("user not found")

// ErrSessionNotFound indicates that the user's session could not be found in the database.
var ErrSessionNotFound = errors.New("session not found")

// var ErrRefreshTokenNotFound indicates that the provided prefresh token does not exist in the database.
var ErrRefreshTokenNotFound = errors.New("refresh token not found")
