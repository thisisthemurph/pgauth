package pgauth_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	th "github.com/thisisthemurph/pgauth/tests/testhelpers"
)

func TestUserClient_UserExistsWithEmail(t *testing.T) {
	testCases := []struct {
		email        string
		expectExists bool
	}{
		{
			email:        "alice@example.com",
			expectExists: true,
		},
		{
			email:        "carol@example.com",
			expectExists: true,
		},
		{
			email:        "eve@example.com",
			expectExists: true,
		},
		{
			email:        "bob@example.com",
			expectExists: true,
		},
		{
			email:        "teddy@example.com",
			expectExists: true,
		},
		{
			email:        "enoch@example.com",
			expectExists: true,
		},
		{
			email:        "no-exist@example.com",
			expectExists: false,
		},
	}

	c, _ := th.SetupAndSeed(t)

	for _, tc := range testCases {
		exists, err := c.User.UserExistsWithEmail(context.Background(), tc.email)
		assert.NoError(t, err)
		assert.Equal(t, tc.expectExists, exists)
	}
}

func TestUserClient_Get(t *testing.T) {
	c, _ := th.SetupAndSeed(t)

	userID := uuid.MustParse("f968d0ab-858c-4cab-b8fb-575a814ea738")
	user, err := c.User.Get(context.Background(), userID)
	assert.NoError(t, err)
	assert.NotNil(t, user)

	assert.Equal(t, userID, user.ID)
	assert.Equal(t, "alice@example.com", user.Email)
	th.AssertTimeMatchesString(t, "2024-01-01 09:00:00", user.CreatedAt)
	th.AssertTimeMatchesString(t, "2024-01-01 09:00:00", user.UpdatedAt)
}

func TestUserClient_GetByEmail(t *testing.T) {
	c, _ := th.SetupAndSeed(t)

	user, err := c.User.GetByEmail(context.Background(), "alice@example.com")
	assert.NoError(t, err)
	assert.NotNil(t, user)

	assert.Equal(t, uuid.MustParse("f968d0ab-858c-4cab-b8fb-575a814ea738"), user.ID)
	assert.Equal(t, "alice@example.com", user.Email)
	th.AssertTimeMatchesString(t, "2024-01-01 09:00:00", user.CreatedAt)
	th.AssertTimeMatchesString(t, "2024-01-01 09:00:00", user.UpdatedAt)
}
