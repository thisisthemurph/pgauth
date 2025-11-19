package pgauth

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/thisisthemurph/pgauth/claims"
	"github.com/thisisthemurph/pgauth/internal/auth"
	"github.com/thisisthemurph/pgauth/internal/crypt"
	userrepo "github.com/thisisthemurph/pgauth/internal/repository/user"
	"github.com/thisisthemurph/pgauth/internal/validation"
)

// UserClient handles user management operations such as fetching, updating, and deleting users.
type UserClient struct {
	db          *sql.DB
	userQureies *userrepo.Queries
	config      Config

	verifyPassword   func(string, string) bool
	validatePassword func(string) error
	generateToken    func() string
}

// newUserClient creates a new UserClient with the provided database connection and configuration.
func newUserClient(db *sql.DB, config Config) *UserClient {
	return &UserClient{
		db:          db,
		userQureies: userrepo.New(db),
		config:      config,

		verifyPassword:   crypt.VerifyHash,
		validatePassword: validation.ValidatePasswordFactory(config.PasswordMinLen),
		generateToken:    crypt.GenerateToken,
	}
}

// UserExistsWithEmail checks if a user exists in the database with the given email address.
//
// Parameters:
//   - ctx: the context to be used with the database query.
//   - email: The email address to check for existence.
//
// Returns:
//   - A boolean indicating whether a user with the given email exists.
func (c *UserClient) UserExistsWithEmail(ctx context.Context, email string) (bool, error) {
	exists, err := c.userQureies.UserExistsWithEmail(ctx, email)
	if err != nil {
		return false, fmt.Errorf("failed to check if user exists with email: %w", err)
	}
	return exists, nil
}

// Get retrieves a user from the database by their unique user ID.
//
// Parameters:
//   - ctx: the context to be used with the database query.
//   - userID: The unique identifier of the user to be retrieved.
//
// Returns:
//   - A pointer to a User object containing the details of the user.
func (c *UserClient) Get(ctx context.Context, userID uuid.UUID) (*User, error) {
	u, err := c.userQureies.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to find user: %w", err)
	}

	return NewUser(u), nil
}

// GetByEmail retrieves a user from the database by their email address.
// The email comparison is case-insensitive.
//
// Parameters:
//   - ctx: the context to be used with the database query.
//   - email: The email address of the user to be retrieved.
//
// Returns:
//   - A pointer to a User object containing the details of the user.
func (c *UserClient) GetByEmail(ctx context.Context, email string) (*User, error) {
	u, err := c.userQureies.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to find user: %w", err)
	}

	return NewUser(u), nil
}

// GetByToken returns the user assigned with the given JWT token.
//
// Parameters:
//   - ctx: the context to be used with the database query.
//   - token: the JWT token string used to fetch the required user.
func (c *UserClient) GetByToken(ctx context.Context, token string) (*User, error) {
	claims, err := c.GetClaims(token)
	if err != nil {
		return nil, err
	}

	userID, err := claims.UserID()
	if err != nil {
		return nil, fmt.Errorf("failed to parse user ID from subject: %w", err)
	}

	return c.Get(ctx, userID)
}

// GetClaims returns the claims for the provided JWT string.
//
// Parameters:
//   - token: the token containing the claims.
func (c *UserClient) GetClaims(token string) (*claims.Claims, error) {
	return auth.ParseJWT(token, c.config.JWTSecret)
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
func (c *UserClient) Delete(ctx context.Context, userID uuid.UUID) (*User, error) {
	u, err := c.userQureies.DeleteUserById(ctx, userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: %s", ErrUserNotFound, userID)
		}
		return nil, err
	}

	return NewUser(u), nil
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
func (c *UserClient) SoftDelete(ctx context.Context, userID uuid.UUID) (*User, error) {
	u, err := c.userQureies.SoftDeleteUserById(ctx, userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: %s", ErrUserNotFound, userID)
		}
		return nil, err
	}

	return NewUser(u), nil
}
