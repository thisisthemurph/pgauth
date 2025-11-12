package client_test

import (
	"context"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thisisthemurph/pgauth"
	"github.com/thisisthemurph/pgauth/internal/client"
	userrepo "github.com/thisisthemurph/pgauth/internal/repository/user"
	"github.com/thisisthemurph/pgauth/tests/testhelpers"
)

var (
	AliceID = uuid.MustParse("f968d0ab-858c-4cab-b8fb-575a814ea738")
	BobID   = uuid.MustParse("d1f44dba-9cab-43d2-aecf-ed0b1cd9b406")
	EnochID = uuid.MustParse("2ce46a7c-a0cc-407a-8e1d-75c6317d1cfe")

	ctx = context.Background()
)

var basicClientConfig = pgauth.ClientConfig{
	ValidatePassword:     true,
	PasswordMinLen:       12,
	JWTSecret:            "jwt-secret",
	JWTExpirationMinutes: 1,
	UseRefreshToken:      true,
}

func TestAuthClient_SignUpWithEmailAndPassword(t *testing.T) {
	db, err := connect()
	require.NoError(t, err)

	c, err := pgauth.NewClient(db, basicClientConfig)
	assert.NoError(t, err)

	user, err := c.Auth.SignUpWithEmailAndPassword(ctx, "newuser@example.com", "123456789000")

	assert.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, user.ID)
	assert.Equal(t, "newuser@example.com", user.Email)
}

func TestAuthClient_SignUpWithEmailAndPassword_UserAlreadyExists(t *testing.T) {
	db, err := connect()
	assert.NoError(t, err)
	assert.NotNil(t, db)

	c, err := pgauth.NewClient(db, basicClientConfig)
	assert.NoError(t, err)

	user, err := c.Auth.SignUpWithEmailAndPassword(ctx, "alice@example.com", "123456789000")

	assert.Error(t, err)
	assert.ErrorIs(t, err, client.ErrDuplicateEmail)
	assert.Nil(t, user)
}

func TestAuthClient_ConfirmSignUp(t *testing.T) {
	db, err := connect()
	assert.NoError(t, err)

	c, err := pgauth.NewClient(db, basicClientConfig)
	assert.NoError(t, err)

	err = c.Auth.ConfirmSignUp(ctx, "bob@example.com", "confirmation-token")

	assert.NoError(t, err)

	user, err := c.User.Get(ctx, BobID)
	assert.NoError(t, err)
	assert.Equal(t, "bob@example.com", user.Email)
	assert.Greater(t, user.UpdatedAt, user.CreatedAt)
}

func TestAuthClient_ConfirmSignUp_WithExpiredConfirmationToken(t *testing.T) {
	db, err := connect()
	assert.NoError(t, err)

	c, err := pgauth.NewClient(db, basicClientConfig)
	assert.NoError(t, err)

	err = c.Auth.ConfirmSignUp(ctx, "teddy@example.com", "confirmation-token")

	assert.Error(t, err)
	assert.ErrorIs(t, client.ErrInvalidToken, err)
}

func TestAuthClient_UpdateEmail(t *testing.T) {
	db, err := connect()
	assert.NoError(t, err)

	c, err := pgauth.NewClient(db, basicClientConfig)
	assert.NoError(t, err)

	resp, err := c.Auth.UpdateEmail(ctx, AliceID, "alice.new@example.com")

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotEmpty(t, resp.Token)
	assert.NotEmpty(t, resp.OTP)
	assert.Len(t, resp.OTP, 6)

	user, err := c.User.Get(ctx, AliceID)
	assert.NoError(t, err)
	assert.Equal(t, "alice@example.com", user.Email)
}

func TestAuthClient_UpdateEmail_WithExistingEmail(t *testing.T) {
	db, err := connect()
	assert.NoError(t, err)

	c, err := pgauth.NewClient(db, basicClientConfig)
	assert.NoError(t, err)

	// Change Alice's email to Bob's email
	_, err = c.Auth.UpdateEmail(ctx, AliceID, "bob@example.com")

	assert.Error(t, err)
	assert.ErrorIs(t, client.ErrDuplicateEmail, err)
}

func TestAuthClient_ConfirmEmailChange(t *testing.T) {
	db, err := connect()
	assert.NoError(t, err)

	c, err := pgauth.NewClient(db, basicClientConfig)
	assert.NoError(t, err)

	resp, err := c.Auth.UpdateEmail(ctx, AliceID, "alice.new@example.com")
	assert.NoError(t, err)

	err = c.Auth.ConfirmEmailChange(ctx, AliceID, resp.Token)
	assert.NoError(t, err)

	user, err := c.User.Get(ctx, AliceID)
	assert.NoError(t, err)
	assert.Equal(t, "alice.new@example.com", user.Email)
	// assert.Empty(t, user.EmailChange)
}

func TestAuthClient_ConfirmEmailChange_WithIncorrectToken(t *testing.T) {
	db, err := connect()
	assert.NoError(t, err)

	c, err := pgauth.NewClient(db, basicClientConfig)
	assert.NoError(t, err)

	_, err = c.Auth.UpdateEmail(ctx, AliceID, "alice.new@example.com")
	assert.NoError(t, err)

	err = c.Auth.ConfirmEmailChange(ctx, AliceID, uuid.NewString())
	assert.ErrorIs(t, err, client.ErrInvalidToken)
}

func TestAuthClient_ConfirmEmailChange_WithExpiredToken(t *testing.T) {
	db, err := connect()
	assert.NoError(t, err)

	c, err := pgauth.NewClient(db, basicClientConfig)
	assert.NoError(t, err)

	err = c.Auth.ConfirmEmailChange(ctx, EnochID, "eed9550b-978a-4ddc-922e-7be5bd8e4d24")
	assert.ErrorIs(t, err, client.ErrInvalidToken)
}

func TestAuthClient_ConfirmEmailChangeWithOTP(t *testing.T) {
	db, err := connect()
	assert.NoError(t, err)

	c, err := pgauth.NewClient(db, basicClientConfig)
	assert.NoError(t, err)

	resp, err := c.Auth.UpdateEmail(ctx, AliceID, "alice.new@example.com")
	assert.NoError(t, err)

	err = c.Auth.ConfirmEmailChangeWithOTP(ctx, AliceID, resp.OTP)
	assert.NoError(t, err)

	user, err := c.User.Get(ctx, AliceID)
	assert.NoError(t, err)
	assert.Equal(t, "alice.new@example.com", user.Email)
}

func TestAuthClient_ConfirmEmailChangeWithOTP_WithIncorrectOTP(t *testing.T) {
	db, err := connect()
	assert.NoError(t, err)

	c, err := pgauth.NewClient(db, basicClientConfig)
	assert.NoError(t, err)

	_, err = c.Auth.UpdateEmail(ctx, AliceID, "alice.new@example.com")
	assert.NoError(t, err)

	err = c.Auth.ConfirmEmailChangeWithOTP(ctx, AliceID, "123456")
	assert.ErrorIs(t, err, client.ErrInvalidToken)
}

func TestAuthClient_ConfirmEmailChangeWithOTP_WithExpiredOTP(t *testing.T) {
	db, err := connect()
	assert.NoError(t, err)

	c, err := pgauth.NewClient(db, basicClientConfig)
	assert.NoError(t, err)

	err = c.Auth.ConfirmEmailChangeWithOTP(ctx, EnochID, "654321")
	assert.ErrorIs(t, err, client.ErrInvalidToken)
}

func TestAuthClient_UpdatePassword(t *testing.T) {
	db, err := connect()
	assert.NoError(t, err)

	c, err := pgauth.NewClient(db, basicClientConfig)
	assert.NoError(t, err)

	resp, err := c.Auth.RequestPasswordUpdate(ctx, AliceID, "password", "secret-password")

	assert.NoError(t, err)
	assert.NotEmpty(t, resp.Token)
	assert.NotEmpty(t, resp.OTP)
}

func TestAuthClient_UpdatePassword_WithIncorrectCurrentPassword(t *testing.T) {
	db, err := connect()
	assert.NoError(t, err)

	c, err := pgauth.NewClient(db, basicClientConfig)
	assert.NoError(t, err)

	resp, err := c.Auth.RequestPasswordUpdate(ctx, AliceID, "wrong", "new-password")

	assert.ErrorIs(t, err, client.ErrInvalidPassword)
	assert.Empty(t, resp.Token)
	assert.Empty(t, resp.OTP)
}

func TestAuthClient_UpdatePassword_WithInvalidNewPassword(t *testing.T) {
	db, err := connect()
	assert.NoError(t, err)

	c, err := pgauth.NewClient(db, basicClientConfig)
	assert.NoError(t, err)

	resp, err := c.Auth.RequestPasswordUpdate(ctx, AliceID, "password", "short")

	assert.Error(t, err)
	assert.Equal(t, "invalid password: password must be at least 12 characters long", err.Error())
	assert.Empty(t, resp.Token)
	assert.Empty(t, resp.OTP)
}

func TestAuthClient_ConfirmPasswordChange(t *testing.T) {
	db, err := connect()
	assert.NoError(t, err)

	c, err := pgauth.NewClient(db, basicClientConfig)
	assert.NoError(t, err)

	resp, err := c.Auth.RequestPasswordUpdate(ctx, AliceID, "password", "new-password")
	assert.NoError(t, err)

	err = c.Auth.ConfirmPasswordUpdate(ctx, AliceID, resp.Token)
	assert.NoError(t, err)
}

func TestAuthClient_RequestPasswordReset_SetsTheAppropriateFields(t *testing.T) {
	db := testhelpers.ConnectToDatabase(t)
	userQueries := userrepo.New(db)
	c, err := pgauth.NewClient(db, basicClientConfig)
	require.NoError(t, err)

	resp, err := c.Auth.RequestPasswordReset(ctx, "alice@example.com")
	assert.NoError(t, err)
	assert.NotEmpty(t, resp)

	u, err := userQueries.GetUserByEmail(ctx, "alice@example.com")
	require.NoError(t, err)

	assert.NotNil(t, u.PasswordChangeToken)
	assert.NotNil(t, u.PasswordChangeRequestedAt)
}

func setup(t *testing.T) (*pgauth.Client, *userrepo.Queries) {
	db := testhelpers.ConnectToDatabase(t)
	queries := userrepo.New(db)
	client, err := pgauth.NewClient(db, basicClientConfig)
	require.NoError(t, err)

	return client, queries
}

func TestAuthClient_CompletePasswordReset_UpdatesThePassword(t *testing.T) {
	c, userQueries := setup(t)

	// Get then original user data
	originalUser, err := userQueries.GetUserByEmail(ctx, "alice@example.com")
	require.NoError(t, err)

	// Do the initial password reset
	token, err := c.Auth.RequestPasswordReset(ctx, "alice@example.com")
	require.NoError(t, err)

	err = c.Auth.ConfirmPasswordReset(ctx, token, "my-new-secret-password")
	assert.NoError(t, err)

	u, err := userQueries.GetUserByEmail(ctx, "alice@example.com")
	require.NoError(t, err)

	assert.False(t, u.PasswordChangeToken.Valid)
	assert.False(t, u.PasswordChangeRequestedAt.Valid)
	assert.NotEqual(t, u.PasswordHash, originalUser.PasswordHash)
}

func TestAuthClient_SignInWithEmailAndPassword(t *testing.T) {
	c, q := setup(t)
	usr, err := q.GetUserByEmail(ctx, "alice@example.com")
	require.NoError(t, err)

	tokenString, err := c.Auth.SignInWithEmailAndPassword(ctx, "alice@example.com", "password")
	assert.NoError(t, err)
	assert.NotEmpty(t, tokenString)

	claims := jwt.MapClaims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (any, error) {
		return []byte(basicClientConfig.JWTSecret), nil
	})

	assert.NoError(t, err)
	assert.NotNil(t, token)
	assert.True(t, token.Valid)
	assert.Equal(t, usr.ID.String(), claims["sub"])
}
