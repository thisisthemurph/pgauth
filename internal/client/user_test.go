package client_test

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	th "github.com/thisisthemurph/pgauth/tests/testhelpers"
)

func TestUserClient_Get(t *testing.T) {
	c, _ := th.Setup(t)

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
	c, _ := th.Setup(t)

	user, err := c.User.GetByEmail(context.Background(), "alice@example.com")
	assert.NoError(t, err)
	assert.NotNil(t, user)

	assert.Equal(t, uuid.MustParse("f968d0ab-858c-4cab-b8fb-575a814ea738"), user.ID)
	assert.Equal(t, "alice@example.com", user.Email)
	th.AssertTimeMatchesString(t, "2024-01-01 09:00:00", user.CreatedAt)
	th.AssertTimeMatchesString(t, "2024-01-01 09:00:00", user.UpdatedAt)
}
