package client_test

import (
	"context"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/thisisthemurph/pgauth"
	"github.com/thisisthemurph/pgauth/internal/client"
	"testing"
)

var (
	AliceID = uuid.MustParse("f968d0ab-858c-4cab-b8fb-575a814ea738")
	BobID   = uuid.MustParse("d1f44dba-9cab-43d2-aecf-ed0b1cd9b406")
	EnochID = uuid.MustParse("2ce46a7c-a0cc-407a-8e1d-75c6317d1cfe")

	ctx = context.Background()
)

func TestAuthClient_SignUpWithEmailAndPassword(t *testing.T) {
	db, err := connect()
	assert.NoError(t, err)

	c := pgauth.NewClient(db, nil)
	user, err := c.Auth.SignUpWithEmailAndPassword(ctx, "newuser@example.com", "654321")

	assert.NoError(t, err)
	assert.Equal(t, "newuser@example.com", user.Email)
	assert.NotEmpty(t, user.EncryptedPassword)
	assert.Nil(t, user.EmailConfirmedAt)
	assert.NotEmpty(t, user.ConfirmationToken)
	assert.NotNil(t, user.ConfirmationTokenCreatedAt)
	assert.Empty(t, user.EmailChange)
	assert.Empty(t, user.EmailChangeToken)
	assert.Nil(t, user.EmailChangeRequestedAt)
	assert.Empty(t, user.PasswordChange)
	assert.Empty(t, user.PasswordChangeToken)
	assert.Nil(t, user.PasswordChangeRequestedAt)
}

func TestAuthClient_SignUpWithEmailAndPassword_UserAlreadyExists(t *testing.T) {
	db, err := connect()
	assert.NoError(t, err)
	assert.NotNil(t, db)

	c := pgauth.NewClient(db, nil)
	user, err := c.Auth.SignUpWithEmailAndPassword(ctx, "alice@example.com", "password")

	assert.Error(t, err)
	assert.ErrorIs(t, client.ErrDuplicateEmail, err)
	assert.Nil(t, user)
}

func TestAuthClient_ConfirmSignUp(t *testing.T) {
	db, err := connect()
	assert.NoError(t, err)

	c := pgauth.NewClient(db, nil)
	err = c.Auth.ConfirmSignUp(ctx, "bob@example.com", "confirmation-token")

	assert.NoError(t, err)

	user, err := c.User.Get(ctx, BobID)
	assert.NoError(t, err)
	assert.Equal(t, "bob@example.com", user.Email)
	assert.NotNil(t, user.EmailConfirmedAt)
	assert.Empty(t, user.ConfirmationToken)
	assert.Nil(t, user.ConfirmationTokenCreatedAt)
	assert.Greater(t, user.UpdatedAt, user.CreatedAt)
}

func TestAuthClient_ConfirmSignUp_WithExpiredConfirmationToken(t *testing.T) {
	db, err := connect()
	assert.NoError(t, err)

	c := pgauth.NewClient(db, nil)
	err = c.Auth.ConfirmSignUp(ctx, "teddy@example.com", "confirmation-token")

	assert.Error(t, err)
	assert.ErrorIs(t, client.ErrInvalidToken, err)
}

func TestAuthClient_UpdateEmail(t *testing.T) {
	db, err := connect()
	assert.NoError(t, err)

	c := pgauth.NewClient(db, nil)

	resp, err := c.Auth.UpdateEmail(ctx, AliceID, "alice.new@example.com")

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotEmpty(t, resp.Token)
	assert.NotEmpty(t, resp.OTP)
	assert.Len(t, resp.OTP, 6)

	user, err := c.User.Get(ctx, AliceID)
	assert.NoError(t, err)
	assert.Equal(t, "alice@example.com", user.Email)
	assert.Equal(t, "alice.new@example.com", user.EmailChange)
	assert.NotEmpty(t, user.EmailChangeToken)
	assert.NotNil(t, user.EmailChangeRequestedAt)
}

func TestAuthClient_UpdateEmail_WithExistingEmail(t *testing.T) {
	db, err := connect()
	assert.NoError(t, err)

	c := pgauth.NewClient(db, nil)

	// Change Alice's email to Bob's email
	_, err = c.Auth.UpdateEmail(ctx, AliceID, "bob@example.com")

	assert.Error(t, err)
	assert.ErrorIs(t, client.ErrDuplicateEmail, err)
}

func TestAuthClient_ConfirmEmailChange(t *testing.T) {
	db, err := connect()
	assert.NoError(t, err)

	c := pgauth.NewClient(db, nil)
	resp, err := c.Auth.UpdateEmail(ctx, AliceID, "alice.new@example.com")
	assert.NoError(t, err)

	err = c.Auth.ConfirmEmailChange(ctx, AliceID, resp.Token)
	assert.NoError(t, err)

	user, err := c.User.Get(ctx, AliceID)
	assert.NoError(t, err)
	assert.Equal(t, "alice.new@example.com", user.Email)
	assert.Empty(t, user.EmailChange)
}

func TestAuthClient_ConfirmEmailChange_WithIncorrectToken(t *testing.T) {
	db, err := connect()
	assert.NoError(t, err)

	c := pgauth.NewClient(db, nil)
	_, err = c.Auth.UpdateEmail(ctx, AliceID, "alice.new@example.com")
	assert.NoError(t, err)

	err = c.Auth.ConfirmEmailChange(ctx, AliceID, uuid.NewString())
	assert.ErrorIs(t, err, client.ErrInvalidToken)
}

func TestAuthClient_ConfirmEmailChange_WithExpiredToken(t *testing.T) {
	db, err := connect()
	assert.NoError(t, err)

	c := pgauth.NewClient(db, nil)
	err = c.Auth.ConfirmEmailChange(ctx, EnochID, "eed9550b-978a-4ddc-922e-7be5bd8e4d24")
	assert.ErrorIs(t, err, client.ErrInvalidToken)
}

func TestAuthClient_ConfirmEmailChangeWithOTP(t *testing.T) {
	db, err := connect()
	assert.NoError(t, err)

	c := pgauth.NewClient(db, nil)
	resp, err := c.Auth.UpdateEmail(ctx, AliceID, "alice.new@example.com")
	assert.NoError(t, err)

	err = c.Auth.ConfirmEmailChangeWithOTP(ctx, AliceID, resp.OTP)
	assert.NoError(t, err)

	user, err := c.User.Get(ctx, AliceID)
	assert.NoError(t, err)
	assert.Equal(t, "alice.new@example.com", user.Email)
	assert.Empty(t, user.EmailChange)
}

func TestAuthClient_ConfirmEmailChangeWithOTP_WithIncorrectOTP(t *testing.T) {
	db, err := connect()
	assert.NoError(t, err)

	c := pgauth.NewClient(db, nil)
	_, err = c.Auth.UpdateEmail(ctx, AliceID, "alice.new@example.com")
	assert.NoError(t, err)

	err = c.Auth.ConfirmEmailChangeWithOTP(ctx, AliceID, "123456")
	assert.ErrorIs(t, err, client.ErrInvalidToken)
}

func TestAuthClient_ConfirmEmailChangeWithOTP_WithExpiredOTP(t *testing.T) {
	db, err := connect()
	assert.NoError(t, err)

	c := pgauth.NewClient(db, nil)
	err = c.Auth.ConfirmEmailChangeWithOTP(ctx, EnochID, "654321")
	assert.ErrorIs(t, err, client.ErrInvalidToken)
}

func TestAuthClient_UpdatePassword(t *testing.T) {
	db, err := connect()
	assert.NoError(t, err)

	c := pgauth.NewClient(db, nil)
	resp, err := c.Auth.UpdatePassword(ctx, AliceID, "password", "secret-password")

	assert.NoError(t, err)
	assert.NotEmpty(t, resp.Token)
	assert.NotEmpty(t, resp.OTP)

	user, err := c.User.Get(ctx, AliceID)
	assert.NoError(t, err)
	assert.NotEmpty(t, user.PasswordChange)
	assert.NotEmpty(t, user.PasswordChangeToken)
	assert.NotNil(t, user.PasswordChangeRequestedAt)
}

func TestAuthClient_UpdatePassword_WithIncorrectCurrentPassword(t *testing.T) {
	db, err := connect()
	assert.NoError(t, err)

	c := pgauth.NewClient(db, nil)
	resp, err := c.Auth.UpdatePassword(ctx, AliceID, "wrong", "new-password")

	assert.ErrorIs(t, err, client.ErrInvalidPassword)
	assert.Empty(t, resp.Token)
	assert.Empty(t, resp.OTP)
}

func TestAuthClient_UpdatePassword_WithInvalidNewPassword(t *testing.T) {
	db, err := connect()
	assert.NoError(t, err)

	c := pgauth.NewClient(db, &pgauth.ClientConfig{
		ValidatePassword: true,
		PasswordMinLen:   12,
	})
	resp, err := c.Auth.UpdatePassword(ctx, AliceID, "password", "short")

	assert.Error(t, err)
	assert.Equal(t, "invalid password: password must be at least 12 characters long", err.Error())
	assert.Empty(t, resp.Token)
	assert.Empty(t, resp.OTP)
}

func TestAuthClient_ConfirmPasswordChange(t *testing.T) {
	db, err := connect()
	assert.NoError(t, err)

	c := pgauth.NewClient(db, nil)
	resp, err := c.Auth.UpdatePassword(ctx, AliceID, "password", "new-password")
	assert.NoError(t, err)

	err = c.Auth.ConfirmPasswordChange(ctx, AliceID, resp.Token)
	assert.NoError(t, err)

	user, err := c.User.Get(ctx, AliceID)
	assert.NoError(t, err)
	assert.NotEqual(t, user.EncryptedPassword, "$2a$10$OuCVNjUHXJRAdOpc4b/1bOiCHRSE3XsMTVTFVIM.EEdh8h7U9RK.G")
	assert.Empty(t, user.PasswordChange)
	assert.Empty(t, user.PasswordChangeToken)
	assert.Nil(t, user.PasswordChangeRequestedAt)
}
