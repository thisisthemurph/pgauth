package testhelpers

import (
	"database/sql"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/thisisthemurph/pgauth"
	sessionrepo "github.com/thisisthemurph/pgauth/internal/repository/session"
	userrepo "github.com/thisisthemurph/pgauth/internal/repository/user"
)

const JWTSecret string = "jwt-secret"

var basicClientConfig = pgauth.ClientConfig{
	PasswordMinLen: 12,
	JWTSecret:      JWTSecret,
}

type QueryContainer struct {
	UserQueries    *userrepo.Queries
	SessionQueries *sessionrepo.Queries
}

func newQueryContainer(db *sql.DB) *QueryContainer {
	return &QueryContainer{
		UserQueries:    userrepo.New(db),
		SessionQueries: sessionrepo.New(db),
	}
}

func Setup(t *testing.T) (*pgauth.Client, *QueryContainer) {
	db := ConnectToDatabaseAndSeed(t)
	client, err := pgauth.NewClient(db, basicClientConfig)
	require.NoError(t, err)
	return client, newQueryContainer(db)
}
