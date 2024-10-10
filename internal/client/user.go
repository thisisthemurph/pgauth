package client

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/thisisthemurph/pgauth/internal/crypt"
	"github.com/thisisthemurph/pgauth/internal/types"
	"github.com/thisisthemurph/pgauth/internal/validation"
)

var (
	ErrBadRequest      = errors.New("bad request")
	ErrInvalidEmail    = errors.New("invalid email address")
	ErrInvalidPassword = errors.New("invalid password")
	ErrInvalidToken    = errors.New("token is invalid or has expired")
	ErrUserNotFound    = errors.New("user not found")
)

type UserClient struct {
	db               *sql.DB
	verifyPassword   func(string, string) bool
	validatePassword func(string) error
	generateToken    func() string
}

func NewUserClient(db *sql.DB, passwordMinLen int) UserClient {
	return UserClient{
		db:               db,
		verifyPassword:   crypt.VerifyHash,
		validatePassword: validation.ValidatePasswordFactory(passwordMinLen),
		generateToken:    crypt.GenerateToken,
	}
}

// Get retrieves a user from the database by their unique user ID.
// If the user is found, the function returns the details of the
// user as a User object.
//
// Parameters:
//   - ctx: the context to be used with the database query.
//   - userID: The unique identifier of the user to be retrieved.
//
// Returns:
//   - A pointer to a User object containing the details of the user.
func (c UserClient) Get(ctx context.Context, userID uuid.UUID) (*types.User, error) {
	stmt := `select * from auth.users where id = $1 and deleted_at is null;`
	u, err := types.MapRowToUser(c.db.QueryRowContext(ctx, stmt, userID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: %s", ErrUserNotFound, userID)
		}
		return nil, err
	}
	return u, nil
}

// GetByEmail retrieves a user from the database by their email address.
// The email comparison is case-insensitive. If the user is found,
// the function returns the details of the user as a User object.
//
// Parameters:
//   - ctx: the context to be used with the database query.
//   - email: The email address of the user to be retrieved.
//
// Returns:
//   - A pointer to a User object containing the details of the user.
func (c UserClient) GetByEmail(ctx context.Context, email string) (*types.User, error) {
	stmt := `select * from auth.users where lower(email) = lower($1) and deleted_at is null limit 1;`
	u, err := types.MapRowToUser(c.db.QueryRowContext(ctx, stmt, email))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: %s", ErrUserNotFound, email)
		}
		return nil, err
	}
	return u, nil
}

// Delete removes a user from the database by their unique user ID.
// If the user is found and deleted, the function returns the details
// of the deleted user. If the user does not exist, it returns an error.
//
// Parameters:
//   - ctx: the context to be used with the database query.
//   - userID: The unique identifier of the user to be deleted.
//
// Returns:
//   - A pointer to a User object containing the details of the deleted user.
func (c UserClient) Delete(ctx context.Context, userID uuid.UUID) (*types.User, error) {
	stmt := `delete from auth.users where id = $1 returning *;`
	u, err := types.MapRowToUser(c.db.QueryRowContext(ctx, stmt, userID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: %s", ErrUserNotFound, userID)
		}
		return nil, err
	}
	return u, nil
}

// SoftDelete sets the deleted_at column of the user to the current date.
// If the user is found, the function returns the details of the deleted user.
// If the user does not exist, it returns an error.
//
// Parameters:
//   - ctx: the context to be used with the database query.
//   - userID: The unique identifier of the user to be deleted.
//
// Returns:
//   - A pointer to a User object containing the details of the deleted user.
func (c UserClient) SoftDelete(ctx context.Context, userID uuid.UUID) (*types.User, error) {
	stmt := `update auth.users set deleted_at = now() where id = $1 returning *;`
	u, err := types.MapRowToUser(c.db.QueryRowContext(ctx, stmt, userID))
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: %s", ErrUserNotFound, userID)
		}
		return nil, err
	}
	return u, nil
}
