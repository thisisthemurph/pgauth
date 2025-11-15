package client

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/thisisthemurph/pgauth/internal/auth"
	"github.com/thisisthemurph/pgauth/internal/crypt"
	userrepo "github.com/thisisthemurph/pgauth/internal/repository/user"
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

type UserClientConfig struct {
	JWTSecret      string
	PasswordMinLen int
}

type UserClient struct {
	db          *sql.DB
	userQureies *userrepo.Queries
	config      UserClientConfig

	verifyPassword   func(string, string) bool
	validatePassword func(string) error
	generateToken    func() string
}

func NewUserClient(db *sql.DB, config UserClientConfig) *UserClient {
	return &UserClient{
		db:          db,
		userQureies: userrepo.New(db),
		config:      config,

		verifyPassword:   crypt.VerifyHash,
		validatePassword: validation.ValidatePasswordFactory(config.PasswordMinLen),
		generateToken:    crypt.GenerateToken,
	}
}

// Get retrieves a user from the database by their unique user ID.
//
// Parameters:
//   - ctx: the context to be used with the database query.
//   - userID: The unique identifier of the user to be retrieved.
//
// Returns:
//   - A pointer to a User object containing the details of the user.
func (c *UserClient) Get(ctx context.Context, userID uuid.UUID) (*types.UserResponse, error) {
	u, err := c.userQureies.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to find user: %w", err)
	}

	return types.NewUserResponse(u), nil
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
func (c *UserClient) GetByEmail(ctx context.Context, email string) (*types.UserResponse, error) {
	u, err := c.userQureies.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to find user: %w", err)
	}

	return types.NewUserResponse(u), nil
}

// GetByToken returns the user assigned with the given JWT token.
//
// Parameters:
//   - ctx: the context to be used with the database query.
//   - token: the JWT token string used to fetch the required user.
func (c *UserClient) GetByToken(ctx context.Context, token string) (*types.UserResponse, error) {
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
func (c *UserClient) GetClaims(token string) (*auth.Claims, error) {
	claims, err := auth.ParseJWT(token, c.config.JWTSecret)
	if err != nil {
		return nil, err
	}

	return claims, nil
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
func (c *UserClient) Delete(ctx context.Context, userID uuid.UUID) (*types.UserResponse, error) {
	u, err := c.userQureies.DeleteUserById(ctx, userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: %s", ErrUserNotFound, userID)
		}
		return nil, err
	}

	return types.NewUserResponse(u), nil
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
func (c *UserClient) SoftDelete(ctx context.Context, userID uuid.UUID) (*types.UserResponse, error) {
	u, err := c.userQureies.SoftDeleteUserById(ctx, userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: %s", ErrUserNotFound, userID)
		}
		return nil, err
	}

	return types.NewUserResponse(u), nil
}
