package pgauth

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/lib/pq"

	"github.com/thisisthemurph/pgauth/internal/auth"
	"github.com/thisisthemurph/pgauth/internal/crypt"
	sessionrepo "github.com/thisisthemurph/pgauth/internal/repository/session"
	userrepo "github.com/thisisthemurph/pgauth/internal/repository/user"
	"github.com/thisisthemurph/pgauth/internal/validation"
	"github.com/thisisthemurph/pgauth/pkg/null"
)

// AuthClient handles authentication operations such as sign up, sign in, and password management.
type AuthClient struct {
	db             *sql.DB
	userQueries    *userrepo.Queries
	sessionQueries *sessionrepo.Queries
	config         Config

	hashPassword     func(string) (string, error)
	generateToken    func() string
	validatePassword func(string) error
	verifyPassword   func(string, string) bool
}

// newAuthClient creates a new AuthClient with the provided database connection and configuration.
func newAuthClient(db *sql.DB, config Config) *AuthClient {
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

// SignUpWithEmailAndPasswordResponse contains the result of a successful user registration.
type SignUpWithEmailAndPasswordResponse struct {
	// User is the newly created user account.
	User *User `json:"user"`

	// ConfirmationToken is the token that must be used to confirm the user's email address.
	ConfirmationToken string `json:"confirmation_token"`
}

// ConfirmSignUpResponse contains the result of a successful email confirmation.
type ConfirmSignUpResponse struct {
	// User is the confirmed user account with updated confirmation status.
	User *User `json:"user"`
}

// SignInWithEmailAndPasswordResponse contains the result of a successful user sign-in.
type SignInWithEmailAndPasswordResponse struct {
	// UserID is the unique identifier of the authenticated user.
	UserID uuid.UUID `json:"user_id"`

	// Token is the JWT token that can be used to authenticate subsequent requests.
	Token string `json:"token"`
}

// RequestEmailUpdateResponse contains the tokens needed to confirm an email change.
type RequestEmailUpdateResponse struct {
	// Token is the email change token that can be used with ConfirmEmailUpdate.
	Token string `json:"token"`

	// OTP is the one-time password that can be used with ConfirmEmailChangeWithOTP.
	OTP string `json:"otp"`
}

// ConfirmEmailUpdateResponse contains the result of a successful email update.
type ConfirmEmailUpdateResponse struct {
	// User is the user account with the updated email address.
	User *User `json:"user"`
}

// UpdatePasswordResponse contains the tokens needed to confirm a password change.
type UpdatePasswordResponse struct {
	// Token is the password change token that can be used with ConfirmPasswordUpdate.
	Token string `json:"token"`

	// OTP is the one-time password that can be used as an alternative confirmation method.
	OTP string `json:"otp"`
}

// RequestPasswordResetResponse contains the token needed to complete a password reset.
type RequestPasswordResetResponse struct {
	// Token is the password reset token that must be used with ConfirmPasswordReset.
	Token string `json:"token"`
}

// SignUpWithEmailAndPassword allows the user to sign up with their given email and password.
//
// Parameters:
//   - ctx: the context to be used with the database query.
//   - email: The user's email address used to identify their account.
//   - password: The plain text password the yser will use to log in.
//   - userData: Additional data for the user that will be persisted in the database and available in the JWT.
func (c *AuthClient) SignUpWithEmailAndPassword(ctx context.Context, email, password string, userData any) (*SignUpWithEmailAndPasswordResponse, error) {
	if valid := validation.IsValidEmail(email); !valid {
		return nil, fmt.Errorf("%w: %s", ErrInvalidEmail, email)
	}
	if err := c.validatePassword(password); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidPassword, err)
	}

	userDataJSON, err := userDataToJSON(userData)
	if err != nil {
		return nil, fmt.Errorf("failed to parse user data: %w", err)
	}

	newConfirmationToken := c.generateToken()
	hashedPassword, err := c.hashPassword(password)
	if err != nil {
		return nil, err
	}

	u, err := c.userQueries.CreateUser(ctx, userrepo.CreateUserParams{
		Email:             email,
		PasswordHash:      hashedPassword,
		UserData:          userDataJSON,
		ConfirmationToken: null.ValidString(newConfirmationToken),
	})

	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code.Name() == "unique_violation" {
			return nil, ErrDuplicateEmail
		}
		return nil, err
	}

	return &SignUpWithEmailAndPasswordResponse{
		User:              NewUser(u),
		ConfirmationToken: newConfirmationToken,
	}, nil
}

func userDataToJSON(data any) (json.RawMessage, error) {
	defaultUserData, _ := json.Marshal("{}")

	if data == nil || data == "" {
		return defaultUserData, nil
	}

	userDataJSON, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}

	if len(userDataJSON) == 0 {
		return defaultUserData, nil
	}

	return userDataJSON, nil
}

// ConfirmSignUp completes the sign up process using the conformation token.
//
// Parameters:
//   - ctx: the context to be used with the database query.
//   - email: the user's email address used to identify their account.
//   - confirmationToken: the confirmation token used to authenticate the confirming user.
func (c *AuthClient) ConfirmSignUp(ctx context.Context, email, confirmationToken string) (*ConfirmSignUpResponse, error) {
	u, err := c.userQueries.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to fetch user: %w", err)
	}

	if !u.ConfirmationToken.Valid || u.ConfirmationToken.String != confirmationToken {
		return nil, ErrInvalidToken
	}
	if !u.ConfirmationTokenCreatedAt.Valid {
		return nil, ErrInvalidToken
	}

	expirationTime := u.ConfirmationTokenCreatedAt.Time.Add(1 * time.Hour)
	if !u.ConfirmationTokenCreatedAt.Valid || expirationTime.UTC().Before(time.Now().UTC()) {
		return nil, ErrInvalidToken
	}

	if err := c.userQueries.SetUserSignupAsConfirmed(ctx, u.ID); err != nil {
		return nil, fmt.Errorf("failed to confirm user sign up: %w", err)
	}

	updatedUser, err := c.userQueries.GetUserByID(ctx, u.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch updated user: %w", err)
	}

	return &ConfirmSignUpResponse{
		User: NewUser(updatedUser),
	}, nil
}

// SignInWithEmailAndPassword signs in the given user.
//
// Parameters:
//   - ctx: the context to be used with the database query.
//   - email: the user's email address used to identify their account.
//   - password: the user's password.
//
// Returns:
//   - a string JWT used for authenticating the user in future requests.
func (c *AuthClient) SignInWithEmailAndPassword(ctx context.Context, email, password string) (*SignInWithEmailAndPasswordResponse, error) {
	u, err := c.userQueries.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrInvalidCredentials
		}
		return nil, fmt.Errorf("failed to fetch user: %w", err)
	}

	if passwordMatches := c.verifyPassword(u.PasswordHash, password); !passwordMatches {
		return nil, ErrInvalidCredentials
	}

	if !u.EmailConfirmedAt.Valid {
		return nil, ErrEmailNotConfirmed
	}

	session, err := c.sessionQueries.CreateSession(ctx, sessionrepo.CreateSessionParams{
		UserID:    u.ID,
		ExpiresAt: auth.GetSessionExpirationTime(),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to create session: %w", err)
	}

	signedToken, err := auth.NewSignedJWT(u, session, c.config.JWTSecret)
	return &SignInWithEmailAndPasswordResponse{
		UserID: u.ID,
		Token:  signedToken,
	}, err
}

// RequestEmailUpdate updates the email change request for a user by setting the
// email_change and email_change_token fields in the database. It generates
// a new token and associates it with the specified user.
//
// Parameters:
//   - ctx: the context to be used with the database query.
//   - userID: The unique identifier of the user whose email is to be updated.
//   - newEmail: The new email address that the user wants to set.
//
// Returns:
//   - A RequestEmailUpdateResponse containing the email_change token and OTP that can be used to confirm.
//   - An error, if any occurs during the execution of the update statement.
func (c *AuthClient) RequestEmailUpdate(ctx context.Context, userID uuid.UUID, newEmail string) (*RequestEmailUpdateResponse, error) {
	if valid := validation.IsValidEmail(newEmail); !valid {
		return nil, fmt.Errorf("%w: %s", ErrInvalidEmail, newEmail)
	}

	newEmailAlreadyTaken, err := c.userQueries.UserExistsWithEmail(ctx, newEmail)
	if err != nil {
		return nil, fmt.Errorf("faiiled to determine if the new email is already taken: %w", err)
	}
	if newEmailAlreadyTaken {
		return nil, ErrDuplicateEmail
	}

	emailChangeToken := c.generateToken()
	otp, err := crypt.GenerateOTP()
	if err != nil {
		return nil, err
	}

	hashedOTP, err := crypt.HashValue(otp)
	if err != nil {
		return nil, err
	}

	err = c.userQueries.InitiateEmailUpdate(ctx, userrepo.InitiateEmailUpdateParams{
		ID:               userID,
		EmailChange:      null.ValidString(newEmail),
		EmailChangeToken: null.ValidString(emailChangeToken),
		EncryptedOtp:     null.ValidString(hashedOTP),
	})
	if err != nil {
		return nil, err
	}

	return &RequestEmailUpdateResponse{
		Token: emailChangeToken,
		OTP:   otp,
	}, nil
}

// ConfirmEmailUpdate confirms the email change request for a user by
// validating the provided user ID and token, and then updating the
// user's email in the database. If the token is valid, the function
// updates the email field with the value from email_change.
//
// Parameters:
//   - ctx: the context to be used with the database query.
//   - userID: The unique identifier of the user whose email is being changed.
//   - token: The email change token used to verify the email change request.
func (c AuthClient) ConfirmEmailUpdate(ctx context.Context, userID uuid.UUID, token string) (*ConfirmEmailUpdateResponse, error) {
	u, err := c.userQueries.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to find user: %w", err)
	}

	if err := c.isUserInCorrecStateForEmailChange(ctx, userID); err != nil {
		return nil, err
	}

	expires := u.EmailChangeRequestedAt.Time.Add(15 * time.Minute)
	if time.Now().After(expires) {
		return nil, ErrInvalidToken
	}

	if u.EmailChangeToken.String != token {
		return nil, ErrInvalidToken
	}

	if err := c.updateUserEmail(ctx, u); err != nil {
		return nil, err
	}

	updatedUser, err := c.userQueries.GetUserByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch updated user: %w", err)
	}

	return &ConfirmEmailUpdateResponse{
		User: NewUser(updatedUser),
	}, nil
}

// ConfirmEmailChangeWithOTP confirms the email change request for a user by
// validating the provided user ID and OTP, and then updating the
// user's email in the database. If the token is valid, the function
// updates the email field with the value from email_change.
//
// Parameters:
//   - ctx: the context to be used with the database query.
//   - userID: The unique identifier of the user whose email is being changed.
//   - otp: The one time password used to verify the email change request.
func (c *AuthClient) ConfirmEmailChangeWithOTP(ctx context.Context, userID uuid.UUID, otp string) (*ConfirmEmailUpdateResponse, error) {
	u, err := c.userQueries.GetUserByID(ctx, userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to find user: %w", err)
	}

	if err := c.isUserInCorrecStateForEmailChange(ctx, userID); err != nil {
		return nil, err
	}

	expires := u.OtpCreatedAt.Time.Add(15 * time.Minute)
	if time.Now().After(expires) {
		return nil, ErrInvalidToken
	}

	if match := crypt.VerifyHash(u.EncryptedOtp.String, otp); !match {
		return nil, ErrInvalidToken
	}

	if err := c.updateUserEmail(ctx, u); err != nil {
		return nil, err
	}

	updatedUser, err := c.userQueries.GetUserByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch updated user: %w", err)
	}

	return &ConfirmEmailUpdateResponse{
		User: NewUser(updatedUser),
	}, nil
}

func (c *AuthClient) updateUserEmail(ctx context.Context, user userrepo.AuthUser) error {
	if !user.EmailChange.Valid {
		return errors.New("incorrect state, email_change not set")
	}

	if err := c.userQueries.CompleteEmailUpdate(ctx, user.ID); err != nil {
		return fmt.Errorf("failed to update email: %w", err)
	}

	return nil
}

// RequestPasswordUpdate initiates a password update request for the specified user.
// It verifies the current password, validates the new password, generates an OTP and a token,
//
// Parameters:
//   - ctx: the context to be used with the database query.
//   - userID: The unique identifier of the user requesting the password update.
//   - currentPassword: The user's current password for verification.
//   - newPassword: The new password that the user wants to set.
//
// Returns:
//   - An UpdatePasswordResponse containing the password change token and OTP that can be used to confirm.
//   - An error, if any occurs.
func (c *AuthClient) RequestPasswordUpdate(
	ctx context.Context,
	userID uuid.UUID,
	currentPassword,
	newPassword string,
) (*UpdatePasswordResponse, error) {
	if err := c.validatePassword(newPassword); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidPassword, err)
	}

	passwordHash, err := c.userQueries.GetPasswordHash(ctx, userID)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, fmt.Errorf("%w: %s", ErrUserNotFound, userID)
		}
		return nil, fmt.Errorf("faiiled to fetch user password: %w", err)
	}

	if match := c.verifyPassword(passwordHash, currentPassword); !match {
		return nil, ErrInvalidPassword
	}

	otp, err := crypt.GenerateOTP()
	if err != nil {
		return nil, err
	}

	hashedOTP, err := crypt.HashValue(otp)
	if err != nil {
		return nil, err
	}

	token := c.generateToken()
	c.userQueries.InitiatePasswordUpdate(ctx, userrepo.InitiatePasswordUpdateParams{
		ID:                  userID,
		PasswordChange:      null.ValidString(newPassword),
		PasswordChangeToken: null.ValidString(token),
		EncryptedOtp:        null.ValidString(hashedOTP),
	})

	return &UpdatePasswordResponse{
		Token: token,
		OTP:   otp,
	}, nil
}

// ConfirmPasswordUpdate confirms the password update request for a user by
// validating the provided user ID and token, and then updating the
// user's password in the database.
//
// Parameters:
//   - ctx: the context to be used with the database query.
//   - userID: The unique identifier of the user whose password is being changed.
//   - token: The password change token used to verify the password change request.
func (c *AuthClient) ConfirmPasswordUpdate(ctx context.Context, userID uuid.UUID, token string) error {
	if err := c.validatePasswordChangeRequest(ctx, userID, token); err != nil {
		return err
	}

	if err := c.userQueries.CompletePasswordUpdate(ctx, userID); err != nil {
		return fmt.Errorf("failed to complete password update: %w", err)
	}

	return nil
}

// RequestPasswordReset initiates a password reset request for the specified email.
// It generates a reset token and associates it with the user.
//
// Parameters:
//   - ctx: the context to be used with the database query.
//   - email: The email address of the user requesting the password reset.
//
// Returns:
//   - A RequestPasswordResetResponse containing the password reset token that can be used to confirm.
//   - An error, if any occurs.
func (c *AuthClient) RequestPasswordReset(ctx context.Context, email string) (*RequestPasswordResetResponse, error) {
	u, err := c.userQueries.GetUserByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return nil, ErrUserNotFound
		}
		return nil, fmt.Errorf("failed to find user: %w", err)
	}

	resetToken := c.generateToken()
	err = c.userQueries.InitiatePasswordReset(ctx, userrepo.InitiatePasswordResetParams{
		ID:                  u.ID,
		PasswordChangeToken: null.ValidString(resetToken),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to initiate password reset: %w", err)
	}

	return &RequestPasswordResetResponse{
		Token: resetToken,
	}, nil
}

// ConfirmPasswordReset confirms the password reset request for a user by
// validating the provided token, and then updating the user's password in the database.
//
// Parameters:
//   - ctx: the context to be used with the database query.
//   - token: The password reset token used to verify the password reset request.
//   - newPassword: The new password that the user wants to set.
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

	if err = c.userQueries.CompletePasswordReset(ctx, userrepo.CompletePasswordResetParams{
		ID:           u.ID,
		PasswordHash: passwordHash,
	}); err != nil {
		return fmt.Errorf("failed to complete password reset: %w", err)
	}

	if err := c.sessionQueries.RevokeAllUserSessions(ctx, u.ID); err != nil {
		return fmt.Errorf("failed to revoke all user sessions: %w", err)
	}

	return nil
}

type TokenResponse struct {
	AccessToken  string
	RefreshToken string
}

func (c *AuthClient) RefreshAccessToken(ctx context.Context, userID, sessionID uuid.UUID, refreshToken string) (*TokenResponse, error) {
	rt, err := c.sessionQueries.GetRefreshToken(ctx, sessionrepo.GetRefreshTokenParams{
		HashedToken: refreshToken,
		UserID:      userID,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get refresh token for user: %w", err)
	}

	user, err := c.userQueries.GetUserByID(ctx, userID)
	if err != nil {
		return nil, ErrUserNotFound
	}

	_, err = c.sessionQueries.ValidateSession(ctx, sessionID)
	if err != nil {
		return nil, ErrSessionNotFound
	}

	newSessionExpiration := auth.GetSessionExpirationTime()
	session, err := c.sessionQueries.ResetSession(ctx, sessionrepo.ResetSessionParams{
		ExpiresAt: newSessionExpiration,
		ID:        sessionID,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to reset session: %w", err)
	}

	newAccessToken, err := auth.NewSignedJWT(user, session, c.config.JWTSecret)
	if err != nil {
		return nil, fmt.Errorf("failed to create new access token: %w", err)
	}

	newRefreshToken, err := auth.GenerateRefreshToken()
	if err != nil {
		return nil, fmt.Errorf("failed to create new refresh token: %w", err)
	}

	err = c.sessionQueries.RegisterRefreshToken(ctx, sessionrepo.RegisterRefreshTokenParams{
		UserID:      userID,
		HashedToken: newRefreshToken,
		ExpiresAt:   time.Now().Add(c.config.RefreshTokenTTL),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to register new refresh token: %w", err)
	}

	_ = c.sessionQueries.DeleteRefreshToken(ctx, rt.ID)

	return &TokenResponse{
		AccessToken:  newAccessToken,
		RefreshToken: newRefreshToken,
	}, nil
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
		return fmt.Errorf("%w: no password reset was requested for user", ErrPasswordChangeNotRequested)
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
