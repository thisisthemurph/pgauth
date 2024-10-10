package client_test

import (
	"context"
	"database/sql"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/thisisthemurph/pgauth/internal/client"
	"github.com/thisisthemurph/pgauth/tests/seed"
)

func connect() (*sql.DB, error) {
	uri := "postgres://testuser:mysecretpassword@localhost:5432/testdb?sslmode=disable"
	db, err := sql.Open("postgres", uri)
	if err != nil {
		return nil, fmt.Errorf("could not connect to database: %w", err)
	}
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("could not ping database: %w", err)
	}

	if err := seed.SeedDatabase(context.Background(), db); err != nil {
		return nil, fmt.Errorf("could not seed database: %w", err)
	}

	return db, nil
}

func mustParseTime(s string) time.Time {
	layout := "2006-01-02 15:04:05"
	parsedTime, err := time.Parse(layout, s)
	if err != nil {
		panic(err)
	}
	return parsedTime.UTC()
}

func assertTimeEqual(t *testing.T, s string, dt time.Time) {
	expected := mustParseTime(s).UTC()
	assert.Equal(t, expected, dt.UTC())
}

func TestUserClient_Get(t *testing.T) {
	db, err := connect()
	assert.NoError(t, err)

	c := client.NewUserClient(db, 6)

	userID := uuid.MustParse("f968d0ab-858c-4cab-b8fb-575a814ea738")
	user, err := c.Get(context.Background(), userID)
	assert.NoError(t, err)
	assert.NotNil(t, user)

	assert.Equal(t, userID, user.ID)
	assert.Equal(t, "alice@example.com", user.Email)
	assert.Equal(t, "$2a$10$OuCVNjUHXJRAdOpc4b/1bOiCHRSE3XsMTVTFVIM.EEdh8h7U9RK.G", user.EncryptedPassword)
	assertTimeEqual(t, "2024-01-01 10:00:00", *user.EmailConfirmedAt)
	assert.Equal(t, "", user.ConfirmationToken)
	assert.Equal(t, "", user.EmailChange)
	assert.Equal(t, "", user.EmailChangeToken)
	assertTimeEqual(t, "2024-01-01 09:00:00", user.CreatedAt)
	assertTimeEqual(t, "2024-01-01 09:00:00", user.UpdatedAt)
}

func TestUserClient_GetByEmail(t *testing.T) {
	db, err := connect()
	assert.NoError(t, err)

	c := client.NewUserClient(db, 6)

	user, err := c.GetByEmail(context.Background(), "alice@example.com")
	assert.NoError(t, err)
	assert.NotNil(t, user)

	assert.Equal(t, uuid.MustParse("f968d0ab-858c-4cab-b8fb-575a814ea738"), user.ID)
	assert.Equal(t, "alice@example.com", user.Email)
	assert.Equal(t, "$2a$10$OuCVNjUHXJRAdOpc4b/1bOiCHRSE3XsMTVTFVIM.EEdh8h7U9RK.G", user.EncryptedPassword)
	assertTimeEqual(t, "2024-01-01 10:00:00", *user.EmailConfirmedAt)
	assert.Equal(t, "", user.ConfirmationToken)
	assert.Equal(t, "", user.EmailChange)
	assert.Equal(t, "", user.EmailChangeToken)
	assertTimeEqual(t, "2024-01-01 09:00:00", user.CreatedAt)
	assertTimeEqual(t, "2024-01-01 09:00:00", user.UpdatedAt)
}
