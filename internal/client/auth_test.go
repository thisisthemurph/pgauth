package client_test

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thisisthemurph/pgauth/internal/auth"
	"github.com/thisisthemurph/pgauth/internal/client"
	th "github.com/thisisthemurph/pgauth/tests/testhelpers"
)

var (
	AliceID = uuid.MustParse("f968d0ab-858c-4cab-b8fb-575a814ea738")
	BobID   = uuid.MustParse("d1f44dba-9cab-43d2-aecf-ed0b1cd9b406")
	EnochID = uuid.MustParse("2ce46a7c-a0cc-407a-8e1d-75c6317d1cfe")

	ctx = context.Background()
)

func TestAuthClient_SignUpWithEmailAndPassword_CreatesNewUser(t *testing.T) {
	c, _ := th.Setup(t)

	resp, err := c.Auth.SignUpWithEmailAndPassword(ctx, "newuser@example.com", "123456789000", nil)

	assert.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, resp.User.ID)
	assert.Equal(t, "newuser@example.com", resp.User.Email)

	expectedUserData, _ := json.Marshal("{}")
	var actualUserData []byte = resp.User.Data
	assert.Equal(t, expectedUserData, actualUserData)
}

func TestAuthClient_SignUpWithEmailAndPassword_WithUserData_CreatesNewUserWithUserData(t *testing.T) {
	c, _ := th.Setup(t)

	type myUserData struct {
		FirstName     string `json:"first_name"`
		LastName      string `json:"last_name"`
		QueuePosition int    `json:"qp"`
	}

	data := myUserData{
		FirstName:     "New",
		LastName:      "User",
		QueuePosition: 1459,
	}

	resp, err := c.Auth.SignUpWithEmailAndPassword(ctx, "newuser@example.com", "123456789000", data)

	assert.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, resp.User.ID)
	assert.Equal(t, "newuser@example.com", resp.User.Email)
	assert.NotNil(t, resp.User.Data)

	var userData myUserData
	err = json.Unmarshal(resp.User.Data, &userData)
	require.NoError(t, err)
	assert.Equal(t, data.FirstName, userData.FirstName)
	assert.Equal(t, data.LastName, userData.LastName)
	assert.Equal(t, data.QueuePosition, userData.QueuePosition)
}

func TestAuthClient_SignUpWithEmailAndPassword_WithEmptyUserData_CreatesNewUserWithoutUserData(t *testing.T) {
	c, _ := th.Setup(t)

	resp, err := c.Auth.SignUpWithEmailAndPassword(ctx, "newuser@example.com", "123456789000", "")

	assert.NoError(t, err)
	assert.NotEqual(t, uuid.Nil, resp.User.ID)
	assert.Equal(t, "newuser@example.com", resp.User.Email)

	expectedUserData, _ := json.Marshal("{}")
	var actualUserData []byte = resp.User.Data
	assert.Equal(t, expectedUserData, actualUserData)
}

func TestAuthClient_SignUpWithEmailAndPassword_UserAlreadyExists(t *testing.T) {
	c, _ := th.Setup(t)

	user, err := c.Auth.SignUpWithEmailAndPassword(ctx, "alice@example.com", "123456789000", nil)

	assert.Error(t, err)
	assert.ErrorIs(t, err, client.ErrDuplicateEmail)
	assert.Nil(t, user)
}

func TestAuthClient_ConfirmSignUp(t *testing.T) {
	c, _ := th.Setup(t)

	resp, err := c.Auth.ConfirmSignUp(ctx, "bob@example.com", "confirmation-token")
	assert.NoError(t, err)

	require.NotNil(t, resp)
	assert.Equal(t, "bob@example.com", resp.User.Email)
	assert.Greater(t, resp.User.UpdatedAt, resp.User.CreatedAt)
}

func TestAuthClient_ConfirmSignUp_WithExpiredConfirmationToken(t *testing.T) {
	c, _ := th.Setup(t)

	resp, err := c.Auth.ConfirmSignUp(ctx, "teddy@example.com", "confirmation-token")

	assert.Error(t, err)
	assert.ErrorIs(t, client.ErrInvalidToken, err)
	assert.Nil(t, resp)
}

func TestAuthClient_UpdateEmail(t *testing.T) {
	c, q := th.Setup(t)

	resp, err := c.Auth.RequestEmailUpdate(ctx, AliceID, "alice.new@example.com")

	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotEmpty(t, resp.Token)
	assert.NotEmpty(t, resp.OTP)
	assert.Len(t, resp.OTP, 6)

	user, err := q.UserQueries.GetUserByID(ctx, AliceID)
	assert.NoError(t, err)
	assert.Equal(t, "alice@example.com", user.Email)
}

func TestAuthClient_UpdateEmail_WithExistingEmail(t *testing.T) {
	c, _ := th.Setup(t)

	// Attempt to change Alice's email to Bob's email
	_, err := c.Auth.RequestEmailUpdate(ctx, AliceID, "bob@example.com")

	assert.Error(t, err)
	assert.ErrorIs(t, client.ErrDuplicateEmail, err)
}

func TestAuthClient_ConfirmEmailChange(t *testing.T) {
	c, q := th.Setup(t)
	newEmail := "alice.new@example.com"

	r, err := c.Auth.RequestEmailUpdate(ctx, AliceID, newEmail)
	assert.NoError(t, err)

	resp, err := c.Auth.ConfirmEmailUpdate(ctx, AliceID, r.Token)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, AliceID, resp.User.ID)
	assert.Equal(t, newEmail, resp.User.Email)

	user, err := q.UserQueries.GetUserByID(ctx, AliceID)
	assert.NoError(t, err)
	assert.Equal(t, newEmail, user.Email)
	assert.Empty(t, user.EmailChange)
}

func TestAuthClient_ConfirmEmailChange_WithIncorrectToken(t *testing.T) {
	c, _ := th.Setup(t)

	_, err := c.Auth.RequestEmailUpdate(ctx, AliceID, "alice.new@example.com")
	assert.NoError(t, err)

	resp, err := c.Auth.ConfirmEmailUpdate(ctx, AliceID, uuid.NewString())
	assert.ErrorIs(t, err, client.ErrInvalidToken)
	assert.Nil(t, resp)
}

func TestAuthClient_ConfirmEmailChange_WithExpiredToken(t *testing.T) {
	c, _ := th.Setup(t)

	resp, err := c.Auth.ConfirmEmailUpdate(ctx, EnochID, "eed9550b-978a-4ddc-922e-7be5bd8e4d24")
	assert.ErrorIs(t, err, client.ErrInvalidToken)
	assert.Nil(t, resp)
}

func TestAuthClient_ConfirmEmailChangeWithOTP(t *testing.T) {
	c, q := th.Setup(t)
	newEmail := "alice.new@example.com"

	r, err := c.Auth.RequestEmailUpdate(ctx, AliceID, newEmail)
	assert.NoError(t, err)

	resp, err := c.Auth.ConfirmEmailChangeWithOTP(ctx, AliceID, r.OTP)
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.Equal(t, AliceID, resp.User.ID)
	assert.Equal(t, newEmail, resp.User.Email)

	user, err := q.UserQueries.GetUserByID(ctx, AliceID)
	assert.NoError(t, err)
	assert.Equal(t, newEmail, user.Email)
	assert.False(t, user.EmailChangeToken.Valid)
	assert.False(t, user.EmailChangeRequestedAt.Valid)
}

func TestAuthClient_ConfirmEmailChangeWithOTP_WithIncorrectOTP(t *testing.T) {
	c, _ := th.Setup(t)
	newEmail := "alice.new@example.com"

	_, err := c.Auth.RequestEmailUpdate(ctx, AliceID, newEmail)
	assert.NoError(t, err)

	resp, err := c.Auth.ConfirmEmailChangeWithOTP(ctx, AliceID, "123456")
	assert.ErrorIs(t, err, client.ErrInvalidToken)
	assert.Nil(t, resp)
}

func TestAuthClient_ConfirmEmailChangeWithOTP_WithExpiredOTP(t *testing.T) {
	c, _ := th.Setup(t)

	resp, err := c.Auth.ConfirmEmailChangeWithOTP(ctx, EnochID, "654321")
	assert.ErrorIs(t, err, client.ErrInvalidToken)
	assert.Nil(t, resp)
}

func TestAuthClient_RequestPasswordUpdate(t *testing.T) {
	c, q := th.Setup(t)

	resp, err := c.Auth.RequestPasswordUpdate(ctx, AliceID, "password", "secret-password")

	assert.NoError(t, err)
	assert.NotEmpty(t, resp.Token)
	assert.NotEmpty(t, resp.OTP)

	u, err := q.UserQueries.GetUserByID(ctx, AliceID)
	require.NoError(t, err)
	assert.True(t, u.PasswordChange.Valid)
	assert.True(t, u.PasswordChangeToken.Valid)
	assert.True(t, u.PasswordChangeRequestedAt.Valid)
}

func TestAuthClient_UpdatePassword_WithIncorrectCurrentPassword(t *testing.T) {
	c, _ := th.Setup(t)

	resp, err := c.Auth.RequestPasswordUpdate(ctx, AliceID, "wrong", "new-password")

	assert.ErrorIs(t, err, client.ErrInvalidPassword)
	assert.Empty(t, resp.Token)
	assert.Empty(t, resp.OTP)
}

func TestAuthClient_UpdatePassword_WithInvalidNewPassword(t *testing.T) {
	c, _ := th.Setup(t)

	resp, err := c.Auth.RequestPasswordUpdate(ctx, AliceID, "password", "short")

	assert.Error(t, err)
	assert.Equal(t, "invalid password: password must be at least 12 characters long", err.Error())
	assert.Empty(t, resp.Token)
	assert.Empty(t, resp.OTP)
}

func TestAuthClient_ConfirmPasswordChange(t *testing.T) {
	c, q := th.Setup(t)

	resp, err := c.Auth.RequestPasswordUpdate(ctx, AliceID, "password", "new-password")
	assert.NoError(t, err)

	originalUser, err := q.UserQueries.GetUserByID(ctx, AliceID)
	require.NoError(t, err)

	err = c.Auth.ConfirmPasswordUpdate(ctx, AliceID, resp.Token)
	assert.NoError(t, err)

	user, err := q.UserQueries.GetUserByID(ctx, AliceID)
	require.NoError(t, err)
	assert.NotEqual(t, originalUser.PasswordHash, user.PasswordHash)
	assert.False(t, user.PasswordChange.Valid)
	assert.False(t, user.PasswordChangeRequestedAt.Valid)
	assert.False(t, user.PasswordChangeToken.Valid)
	assert.False(t, user.OtpCreatedAt.Valid)
	assert.False(t, user.EncryptedOtp.Valid)
}

func TestAuthClient_RequestPasswordReset_SetsTheAppropriateFields(t *testing.T) {
	c, q := th.Setup(t)

	resp, err := c.Auth.RequestPasswordReset(ctx, "alice@example.com")
	assert.NoError(t, err)
	assert.NotEmpty(t, resp)

	u, err := q.UserQueries.GetUserByEmail(ctx, "alice@example.com")
	require.NoError(t, err)
	assert.True(t, u.PasswordChangeToken.Valid)
	assert.True(t, u.PasswordChangeRequestedAt.Valid)
}

func TestAuthClient_CompletePasswordReset_UpdatesThePassword(t *testing.T) {
	c, q := th.Setup(t)

	// Get then original user data
	originalUser, err := q.UserQueries.GetUserByEmail(ctx, "alice@example.com")
	require.NoError(t, err)

	// Do the initial password reset
	resp, err := c.Auth.RequestPasswordReset(ctx, "alice@example.com")
	require.NoError(t, err)

	err = c.Auth.ConfirmPasswordReset(ctx, resp.Token, "my-new-secret-password")
	assert.NoError(t, err)

	u, err := q.UserQueries.GetUserByEmail(ctx, "alice@example.com")
	require.NoError(t, err)

	assert.False(t, u.PasswordChangeToken.Valid)
	assert.False(t, u.PasswordChangeRequestedAt.Valid)
	assert.NotEqual(t, u.PasswordHash, originalUser.PasswordHash)
}

func TestAuthClient_SignInWithEmailAndPassword(t *testing.T) {
	c, q := th.Setup(t)

	dbUser, err := q.UserQueries.GetUserByEmail(ctx, "alice@example.com")
	require.NoError(t, err)

	resp, err := c.Auth.SignInWithEmailAndPassword(ctx, "alice@example.com", "password")
	assert.NoError(t, err)
	assert.NotNil(t, resp)
	assert.NotEmpty(t, resp.Token)

	claims := &auth.Claims{}
	token, err := jwt.ParseWithClaims(resp.Token, claims, func(t *jwt.Token) (any, error) {
		return []byte(th.JWTSecret), nil
	})

	require.NoError(t, err)
	assert.NotNil(t, token)
	assert.True(t, token.Valid)
	assert.Equal(t, dbUser.ID.String(), claims.Subject)

	// Verify the user data in the claims

	type DOB struct {
		Day   int `json:"d"`
		Month int `json:"m"`
		Year  int `json:"y"`
	}

	type aliceUserData struct {
		Name       string `json:"name"`
		ExternalId string `json:"external_id"`
		DOB        DOB    `json:"dob"`
	}

	userDataBytes, err := json.Marshal(claims.UserData)
	require.NoError(t, err)

	var userData aliceUserData
	err = json.Unmarshal(userDataBytes, &userData)
	require.NoError(t, err)
	assert.Equal(t, "Alice", userData.Name)
	assert.Equal(t, "ext_1234", userData.ExternalId)
	assert.Equal(t, 25, userData.DOB.Day)
	assert.Equal(t, 8, userData.DOB.Month)
	assert.Equal(t, 1990, userData.DOB.Year)
}
