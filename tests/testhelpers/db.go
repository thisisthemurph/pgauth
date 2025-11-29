package testhelpers

import (
	"context"
	"database/sql"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/thisisthemurph/pgauth/tests/seed"
)

func ConnectToDatabaseAndSeed(t *testing.T) *sql.DB {
	db := ConnectToDatabase(t)
	err := seed.SeedDatabase(context.Background(), db, "tests/seed/seed.sql")
	require.NoError(t, err)

	return db
}

func ConnectToDatabase(t *testing.T) *sql.DB {
	uri := "postgres://testuser:mysecretpassword@localhost:5433/pgauth-testdb?sslmode=disable"
	db, err := sql.Open("postgres", uri)
	require.NoError(t, err)

	err = db.Ping()
	require.NoError(t, err)

	return db
}
