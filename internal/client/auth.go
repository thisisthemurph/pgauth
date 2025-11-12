package client

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/lib/pq"

	"github.com/google/uuid"
	"github.com/thisisthemurph/pgauth/internal/crypt"
	sessionrepo "github.com/thisisthemurph/pgauth/internal/repository/session"
	userrepo "github.com/thisisthemurph/pgauth/internal/repository/user"
	"github.com/thisisthemurph/pgauth/internal/types"
	"github.com/thisisthemurph/pgauth/internal/validation"
	"github.com/thisisthemurph/pgauth/pkg/null"
)

var (
	ErrInvalidCredentials = errors.New("email and password combination does not match")
	ErrDuplicateEmail     = errors.New("user already exists with the given email address")
	ErrEmailNotConfirmed  = errors.New("email not confimed")
)

type AuthClientConfig struct {
	JWTSecret      string
	PasswordMinLen int
}

type AuthClient struct {
	db             *sql.DB
	userQueries    *userrepo.Queries
	sessionQueries *sessionrepo.Queries
	config         AuthClientConfig

	hashPassword     func(string) (string, error)
	generateToken    func() string
	validatePassword func(string) error
	verifyPassword   func(string, string) bool
}

func NewAuthClient(db *sql.DB, config AuthClientConfig) *AuthClient {
	return &AuthClient{
		db:             db,
		userQueries:    userrepo.New(db),
		sessionQueries: sessionrepo.New(db),
		config:         config,

		hashPassword:     crypt.HashValue,
		generateToken:    crypt.GenerateToken,
		validatePassword: validation.ValidatePasswordFactory(config.PasswordMinLen),
		verifyPassword:   crypt.VerifyHash,
	}
}

func (c *AuthClient) SignUpWithEmailAndPassword(ctx context.Context, email, password string) (*types.UserResponse, error) {
	if valid := validation.IsValidEmail(email); !valid {
		return nil, fmt.Errorf("%w: %s", ErrInvalidEmail, email)
	}
	if err := c.validatePassword(password); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidPassword, err)
	}

	newConfirmationToken := c.generateToken()
	hashedPassword, err := c.hashPassword(password)
	if err != nil {
		return nil, err
	}

	u, err := c.userQueries.CreateUser(ctx, userrepo.CreateUserParams{
		Email:             email,
		PasswordHash:      hashedPassword,
		ConfirmationToken: null.ValidString(newConfirmationToken),
	})

	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code.Name() == "unique_violation" {
			return nil, ErrDuplicateEmail
		}
		return nil, err
	}

	return types.NewUserResponse(u), nil
}

func (c *AuthClient) ConfirmSignUp(ctx context.Context, email, confirmationToken string) error {
	u, err := c.userQueries.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrUserNotFound
		}
		return err
	}

	if !u.ConfirmationToken.Valid || u.ConfirmationToken.String != confirmationToken {
		return ErrInvalidToken
	}
	if !u.ConfirmationTokenCreatedAt.Valid {
		return ErrInvalidToken
	}

	expirationTime := u.ConfirmationTokenCreatedAt.Time.Add(1 * time.Hour)
	if !u.ConfirmationTokenCreatedAt.Valid || expirationTime.UTC().Before(time.Now().UTC()) {
		return ErrInvalidToken
	}

	return c.userQueries.SetUserSignupAsConfirmed(ctx, u.ID)
}

func (c *AuthClient) SignInWithEmailAndPassword(ctx context.Context, email, password string) (string, error) {
	u, err := c.userQueries.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrInvalidCredentials
		}
		return "", fmt.Errorf("failed to fetch user: %w", err)
	}

	if passwordMatches := c.verifyPassword(u.PasswordHash, password); !passwordMatches {
		return "", ErrInvalidCredentials
	}

	if !u.EmailConfirmedAt.Valid {
		return "", ErrEmailNotConfirmed
	}

	session, err := c.sessionQueries.CreateSession(ctx, sessionrepo.CreateSessionParams{
		UserID:    null.ValidUUID(u.ID),
		ExpiresAt: time.Now().Add(15 * time.Minute),
	})
	if err != nil {
		return "", fmt.Errorf("failed to create session: %w", err)
	}

	claims := jwt.MapClaims{
		"sub":        u.ID,
		"session_id": session.ID,
		"iat":        time.Now().Unix(),
		"exp":        session.ExpiresAt.Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	signedToken, err := token.SignedString([]byte(c.config.JWTSecret))
	return signedToken, err
}

type UpdateEmailResponse struct {
	Token string `json:"token"`
	OTP   string `json:"otp"`
}

// UpdateEmail updates the email change request for a user by setting the
// email_change and email_change_token fields in the database. It generates
// a new token and associates it with the specified user.
//
// Parameters:
//   - ctx: the context to be used with the database query.
//   - userID: The unique identifier of the user whose email is to be updated.
//   - newEmail: The new email address that the user wants to set.
//
// Returns:
//   - A string representing the generated email change token.
//   - An error, if any occurs during the execution of the update statement.
func (c *AuthClient) UpdateEmail(ctx context.Context, userID uuid.UUID, newEmail string) (UpdateEmailResponse, error) {
	if valid := validation.IsValidEmail(newEmail); !valid {
		return UpdateEmailResponse{}, fmt.Errorf("%w: %s", ErrInvalidEmail, newEmail)
	}

	newEmailAlreadyTaken, err := c.userQueries.UserExistsWithEmail(ctx, newEmail)
	if err != nil {
		return UpdateEmailResponse{}, fmt.Errorf("faiiled to determine if the new email is already taken: %w", err)
	}
	if newEmailAlreadyTaken {
		return UpdateEmailResponse{}, ErrDuplicateEmail
	}

	emailChangeToken := c.generateToken()
	otp, err := crypt.GenerateOTP()
	if err != nil {
		return UpdateEmailResponse{}, err
	}

	hashedOTP, err := crypt.HashValue(otp)
	if err != nil {
		return UpdateEmailResponse{}, err
	}

	err = c.userQueries.InitiateEmailUpdate(ctx, userrepo.InitiateEmailUpdateParams{
		ID:               userID,
		EmailChange:      null.ValidString(newEmail),
		EmailChangeToken: null.ValidString(emailChangeToken),
		EncryptedOtp:     null.ValidString(hashedOTP),
	})
	if err != nil {
		return UpdateEmailResponse{}, err
	}

	return UpdateEmailResponse{
		Token: emailChangeToken,
		OTP:   otp,
	}, nil
}

// ConfirmEmailChange confirms the email change request for a user by
// validating the provided user ID and token, and then updating the
// user's email in the database. If the token is valid, the function
// updates the email field with the value from email_change.
//
// Parameters:
//   - ctx: the context to be used with the database query.
//   - userID: The unique identifier of the user whose email is being changed.
//   - token: The email change token used to verify the email change request.
func (c AuthClient) ConfirmEmailChange(ctx context.Context, userID uuid.UUID, token string) error {
	u, err := c.userQueries.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrUserNotFound
		}
		return fmt.Errorf("failed to find user: %w", err)
	}

	if err := c.isUserInCorrecStateForEmailChange(ctx, userID); err != nil {
		return err
	}

	expires := u.EmailChangeRequestedAt.Time.Add(15 * time.Minute)
	if time.Now().After(expires) {
		return ErrInvalidToken
	}

	if u.EmailChangeToken.String != token {
		return ErrInvalidToken
	}

	return c.updateUserEmail(ctx, userID)
}

func (c *AuthClient) ConfirmEmailChangeWithOTP(ctx context.Context, userID uuid.UUID, otp string) error {
	u, err := c.userQueries.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrUserNotFound
		}
		return fmt.Errorf("failed to find user: %w", err)
	}

	if err := c.isUserInCorrecStateForEmailChange(ctx, userID); err != nil {
		return err
	}

	expires := u.OtpCreatedAt.Time.Add(15 * time.Minute)
	if time.Now().After(expires) {
		return ErrInvalidToken
	}

	if match := crypt.VerifyHash(u.EncryptedOtp.String, otp); !match {
		return ErrInvalidToken
	}

	return c.updateUserEmail(ctx, userID)
}

func (c *AuthClient) updateUserEmail(ctx context.Context, userID uuid.UUID) error {
	u, err := c.userQueries.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrUserNotFound
		}
		return fmt.Errorf("failed to get user: %w", err)
	}

	if !u.EmailChange.Valid {
		return errors.New("incorrect state, email_change not set")
	}

	if err := c.userQueries.CompleteEmailUpdate(ctx, userID); err != nil {
		return fmt.Errorf("failed to update email: %w", err)
	}

	return nil
}

type UpdatePasswordResponse struct {
	Token string `json:"token"`
	OTP   string `json:"otp"`
}

func (c *AuthClient) RequestPasswordUpdate(
	ctx context.Context,
	userID uuid.UUID,
	currentPassword,
	newPassword string,
) (UpdatePasswordResponse, error) {
	if err := c.validatePassword(newPassword); err != nil {
		return UpdatePasswordResponse{}, fmt.Errorf("%w: %w", ErrInvalidPassword, err)
	}

	passwordHash, err := c.userQueries.GetPasswordHash(ctx, userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return UpdatePasswordResponse{}, fmt.Errorf("%w: %s", ErrUserNotFound, userID)
		}
		return UpdatePasswordResponse{}, fmt.Errorf("faiiled to fetch user password: %w", err)
	}

	if match := c.verifyPassword(passwordHash, currentPassword); !match {
		return UpdatePasswordResponse{}, ErrInvalidPassword
	}

	otp, err := crypt.GenerateOTP()
	if err != nil {
		return UpdatePasswordResponse{}, err
	}

	hashedOTP, err := crypt.HashValue(otp)
	if err != nil {
		return UpdatePasswordResponse{}, err
	}

	token := c.generateToken()
	c.userQueries.InitiatePasswordUpdate(ctx, userrepo.InitiatePasswordUpdateParams{
		ID:                  userID,
		PasswordChange:      null.ValidString(newPassword),
		PasswordChangeToken: null.ValidString(token),
		EncryptedOtp:        null.ValidString(hashedOTP),
	})

	return UpdatePasswordResponse{
		Token: token,
		OTP:   otp,
	}, nil
}

func (c *AuthClient) ConfirmPasswordUpdate(ctx context.Context, userID uuid.UUID, token string) error {
	if err := c.validatePasswordChangeRequest(ctx, userID, token); err != nil {
		return err
	}

	if err := c.userQueries.CompletePasswordUpdate(ctx, userID); err != nil {
		return fmt.Errorf("failed to complete password update: %w", err)
	}

	return nil
}

func (c *AuthClient) RequestPasswordReset(ctx context.Context, email string) (string, error) {
	u, err := c.userQueries.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", ErrUserNotFound
		}
		return "", fmt.Errorf("failed to find user: %w", err)
	}

	resetToken := c.generateToken()
	err = c.userQueries.InitiatePasswordReset(ctx, userrepo.InitiatePasswordResetParams{
		ID:                  u.ID,
		PasswordChangeToken: null.ValidString(resetToken),
	})
	if err != nil {
		return "", fmt.Errorf("failed to initiate password reset: %w", err)
	}

	return resetToken, nil
}

func (c *AuthClient) ConfirmPasswordReset(ctx context.Context, token, newPassword string) error {
	if err := c.validatePassword(newPassword); err != nil {
		return ErrInvalidPassword
	}

	u, err := c.userQueries.GetUserByPasswordChangeToken(ctx, token)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrUserNotFound
		}
		return fmt.Errorf("failed to fetch user: %w", err)
	}

	if !u.PasswordChangeToken.Valid || !u.PasswordChangeRequestedAt.Valid || u.PasswordChange.Valid {
		return ErrInvalidToken
	}

	if u.PasswordChangeToken.String != token {
		return ErrInvalidToken
	}

	passwordHash, err := c.hashPassword(newPassword)
	if err != nil {
		return fmt.Errorf("failed to hash password: %w", err)
	}

	err = c.userQueries.CompletePasswordReset(ctx, userrepo.CompletePasswordResetParams{
		ID:           u.ID,
		PasswordHash: passwordHash,
	})

	if err != nil {
		return fmt.Errorf("failed to complete password reset: %w", err)
	}

	return nil
}

func (c *AuthClient) isUserInCorrecStateForEmailChange(ctx context.Context, userID uuid.UUID) error {
	u, err := c.userQueries.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrUserNotFound
		}
		return fmt.Errorf("failed to fetch user: %w", err)
	}

	if !u.EmailChange.Valid || !u.EmailChangeToken.Valid || !u.EmailChangeRequestedAt.Valid || !u.EncryptedOtp.Valid || !u.OtpCreatedAt.Valid {
		return fmt.Errorf("user in incorrect state for email reset")
	}

	return nil
}

func (c *AuthClient) validatePasswordChangeRequest(ctx context.Context, userID uuid.UUID, token string) error {
	u, err := c.userQueries.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: %s", ErrUserNotFound, userID)
		}
		return err
	}

	if !u.PasswordChange.Valid || !u.PasswordChangeToken.Valid || !u.PasswordChangeRequestedAt.Valid {
		return fmt.Errorf("%w: no password reset was requested for user", ErrBadRequest)
	}

	if u.PasswordChangeToken.String != token {
		return ErrInvalidToken
	}

	expires := u.PasswordChangeRequestedAt.Time.Add(15 * time.Minute)
	if time.Now().After(expires) {
		return ErrInvalidToken
	}

	return nil
}
