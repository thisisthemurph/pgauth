package testhelpers

import (
	"context"
	"database/sql"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/thisisthemurph/pgauth/tests/seed"
)

func ConnectToDatabaseAndSeed(t *testing.T) *sql.DB {
	uri := "postgres://testuser:mysecretpassword@localhost:5432/testdb?sslmode=disable"
	db, err := sql.Open("postgres", uri)
	require.NoError(t, err)

	err = db.Ping()
	require.NoError(t, err)

	err = seed.SeedDatabase(context.Background(), db)
	require.NoError(t, err)

	return db
}
