package client

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"github.com/lib/pq"
	"time"

	"github.com/google/uuid"
	"github.com/thisisthemurph/pgauth/internal/crypt"
	"github.com/thisisthemurph/pgauth/internal/types"
	"github.com/thisisthemurph/pgauth/internal/validation"
)

var ErrDuplicateEmail = errors.New("user already exists with the given email address")

type AuthClient struct {
	db               *sql.DB
	hashPassword     func(string) (string, error)
	generateToken    func() string
	validatePassword func(string) error
	verifyPassword   func(string, string) bool
}

func NewAuthClient(db *sql.DB, passwordMinLen int) AuthClient {
	return AuthClient{
		db:               db,
		hashPassword:     crypt.HashValue,
		generateToken:    crypt.GenerateToken,
		validatePassword: validation.ValidatePasswordFactory(passwordMinLen),
		verifyPassword:   crypt.VerifyHash,
	}
}

func (c AuthClient) SignUpWithEmailAndPassword(ctx context.Context, email, password string) (*types.User, error) {
	if valid := validation.IsValidEmail(email); !valid {
		return nil, fmt.Errorf("%w: %s", ErrInvalidEmail, email)
	}
	if err := c.validatePassword(password); err != nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidPassword, err)
	}

	stmt := `
		insert into auth.users (email, encrypted_password, confirmation_token, confirmation_token_created_at) 
		values ($1, $2, $3, now()) returning *;`

	newConfirmationToken := c.generateToken()
	hashedPassword, err := c.hashPassword(password)
	if err != nil {
		return nil, err
	}

	row := c.db.QueryRowContext(ctx, stmt, email, hashedPassword, newConfirmationToken)
	u, err := types.MapRowToUser(row)
	if err != nil {
		var pqErr *pq.Error
		if errors.As(err, &pqErr) && pqErr.Code.Name() == "unique_violation" {
			return nil, ErrDuplicateEmail
		}
		return nil, err
	}

	return u, nil
}

func (c AuthClient) ConfirmSignUp(ctx context.Context, email, confirmationToken string) error {
	stmt := `
		select id, confirmation_token, confirmation_token_created_at 
		from auth.users
		where email = $1;`

	var userID uuid.UUID
	var dbConfirmationToken *string
	var dbConfirmationTokenCreatedAt *time.Time
	err := c.db.QueryRowContext(ctx, stmt, email).Scan(&userID, &dbConfirmationToken, &dbConfirmationTokenCreatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return ErrUserNotFound
		}
		return err
	}

	if dbConfirmationToken == nil || *dbConfirmationToken != confirmationToken {
		return ErrInvalidToken
	}

	expirationTime := dbConfirmationTokenCreatedAt.Add(1 * time.Hour)
	if dbConfirmationTokenCreatedAt == nil || expirationTime.UTC().Before(time.Now().UTC()) {
		return ErrInvalidToken
	}

	stmt = `
		update auth.users
		set confirmation_token = null,
		    confirmation_token_created_at = null,
			email_confirmed_at = now()
		where id = $1;`

	_, err = c.db.Exec(stmt, userID)
	return err
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
func (c AuthClient) UpdateEmail(ctx context.Context, userID uuid.UUID, newEmail string) (UpdateEmailResponse, error) {
	if valid := validation.IsValidEmail(newEmail); !valid {
		return UpdateEmailResponse{}, fmt.Errorf("%w: %s", ErrInvalidEmail, newEmail)
	}

	if exists, err := c.userExists(newEmail); err != nil {
		return UpdateEmailResponse{}, err
	} else if exists {
		return UpdateEmailResponse{}, ErrDuplicateEmail
	}

	stmt := `
		update auth.users 
		set email_change = $1, 
			email_change_token = $2,
			email_change_requested_at = now(),
			encrypted_otp = $3,
			otp_created_at = now()
		where id = $4;`

	emailChangeToken := c.generateToken()
	otp, err := crypt.GenerateOTP()
	if err != nil {
		return UpdateEmailResponse{}, err
	}

	hashedOTP, err := crypt.HashValue(otp)
	if err != nil {
		return UpdateEmailResponse{}, err
	}

	if _, err = c.db.ExecContext(ctx, stmt, newEmail, emailChangeToken, hashedOTP, userID); err != nil {
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
	storedToken, err := c.validateEmailChangeRequest(ctx, userID, true)
	if err != nil {
		return err
	}
	if token != storedToken {
		return ErrInvalidToken
	}

	return c.updateUserEmail(ctx, userID)
}

func (c AuthClient) ConfirmEmailChangeWithOTP(ctx context.Context, userID uuid.UUID, otp string) error {
	hashedOTP, err := c.validateEmailChangeRequest(ctx, userID, false)
	if err != nil {
		return err
	}
	if match := crypt.VerifyHash(hashedOTP, otp); !match {
		return ErrInvalidToken
	}

	return c.updateUserEmail(ctx, userID)
}

func (c AuthClient) updateUserEmail(ctx context.Context, userID uuid.UUID) error {
	stmt := `
		update auth.users
		set email = email_change,
		    email_change = null,
		    email_change_token = null,
		    encrypted_otp = null,
		    otp_created_at = null
		where id = $1;`

	res, err := c.db.ExecContext(ctx, stmt, userID)
	if err != nil {
		return err
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrInvalidToken
	}
	return nil
}

type UpdatePasswordResponse struct {
	Token string `json:"token"`
	OTP   string `json:"otp"`
}

func (c AuthClient) UpdatePassword(
	ctx context.Context,
	userID uuid.UUID,
	currentPassword,
	newPassword string,
) (UpdatePasswordResponse, error) {
	if err := c.validatePassword(newPassword); err != nil {
		return UpdatePasswordResponse{}, fmt.Errorf("%w: %w", ErrInvalidPassword, err)
	}

	var dbHashedPassword string
	stmt := `select encrypted_password from auth.users where id = $1;`
	if err := c.db.QueryRowContext(ctx, stmt, userID).Scan(&dbHashedPassword); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return UpdatePasswordResponse{}, fmt.Errorf("%w: %s", ErrUserNotFound, userID)
		}
		return UpdatePasswordResponse{}, err
	}

	if match := c.verifyPassword(dbHashedPassword, currentPassword); !match {
		return UpdatePasswordResponse{}, ErrInvalidPassword
	}

	stmt = `
		update auth.users
		set password_change = $1,
		    password_change_token = $2,
		    password_change_requested_at = now(),
			encrypted_otp = $3,
			otp_created_at = now()
		where id = $4;`

	otp, err := crypt.GenerateOTP()
	if err != nil {
		return UpdatePasswordResponse{}, err
	}

	hashedOTP, err := crypt.HashValue(otp)
	if err != nil {
		return UpdatePasswordResponse{}, err
	}

	token := c.generateToken()
	if _, err := c.db.ExecContext(ctx, stmt, newPassword, token, hashedOTP, userID); err != nil {
		return UpdatePasswordResponse{}, err
	}

	return UpdatePasswordResponse{
		Token: token,
		OTP:   otp,
	}, nil
}

func (c AuthClient) ConfirmPasswordChange(ctx context.Context, userID uuid.UUID, token string) error {
	if err := c.validatePasswordChangeRequest(ctx, userID, token); err != nil {
		return err
	}

	stmt := `
		update auth.users
		set encrypted_password = password_change,
		    password_change = null,
		    password_change_token = null,
		    password_change_requested_at = null
		where id = $1;`

	res, err := c.db.ExecContext(ctx, stmt, userID)
	if err != nil {
		return err
	}

	affected, err := res.RowsAffected()
	if err != nil {
		return err
	}
	if affected == 0 {
		return ErrInvalidToken
	}

	return nil
}

func (c AuthClient) validateEmailChangeRequest(ctx context.Context, userID uuid.UUID, wantToken bool) (string, error) {
	stmt := `
		select 
		    email_change,
		    email_change_token,
		    email_change_requested_at,
		    encrypted_otp,
		    otp_created_at
		from auth.users
		where id = $1;`

	var emailChange *string
	var emailChangeToken *string
	var emailChangeTimestamp *time.Time
	var encryptedOTP *string
	var otpCreatedAt *time.Time
	err := c.db.QueryRowContext(ctx, stmt, userID).Scan(&emailChange, &emailChangeToken, &emailChangeTimestamp, &encryptedOTP, &otpCreatedAt)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return "", fmt.Errorf("%w: %s", ErrUserNotFound, userID)
		}
		return "", err
	}

	if emailChange == nil || emailChangeToken == nil || emailChangeTimestamp == nil || encryptedOTP == nil || otpCreatedAt == nil {
		return "", fmt.Errorf("%w: no email reset was requested for user", ErrBadRequest)
	}

	// Ensure the token in the database has not expired

	if wantToken {
		expires := emailChangeTimestamp.Add(15 * time.Minute)
		if time.Now().After(expires) {
			return "", ErrInvalidToken
		}
		return *emailChangeToken, nil
	}

	expires := otpCreatedAt.Add(15 * time.Minute)
	if time.Now().After(expires) {
		return "", ErrInvalidToken
	}
	return *encryptedOTP, nil
}

func (c AuthClient) validatePasswordChangeRequest(ctx context.Context, userID uuid.UUID, token string) error {
	stmt := `
		select password_change, password_change_token, password_change_requested_at
		from auth.users
		where id = $1;`

	var passwordChange *string
	var passwordChangeToken *string
	var passwordChangeTimestamp *time.Time
	err := c.db.QueryRowContext(ctx, stmt, userID).Scan(&passwordChange, &passwordChangeToken, &passwordChangeTimestamp)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: %s", ErrUserNotFound, userID)
		}
		return err
	}

	if passwordChange == nil || passwordChangeToken == nil || passwordChangeTimestamp == nil {
		return fmt.Errorf("%w: no password reset was requested for user", ErrBadRequest)
	}

	if token != *passwordChangeToken {
		return ErrInvalidToken
	}

	expires := passwordChangeTimestamp.Add(15 * time.Minute)
	if time.Now().After(expires) {
		return ErrInvalidToken
	}

	return nil
}

func (c AuthClient) userExists(email string) (bool, error) {
	stmt := `select exists(select 1 from auth.users where email = $1);`
	var exists bool
	if err := c.db.QueryRow(stmt, email).Scan(&exists); err != nil {
		return false, err
	}
	return exists, nil
}
