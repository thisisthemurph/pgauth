package testhelpers

import (
	"database/sql"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/thisisthemurph/pgauth"
	sessionrepo "github.com/thisisthemurph/pgauth/internal/repository/session"
	userrepo "github.com/thisisthemurph/pgauth/internal/repository/user"
)

const JWTSecret string = "jwt-secret"

var basicClientConfig = pgauth.Config{
	PasswordMinLen:  12,
	JWTSecret:       JWTSecret,
	RefreshTokenTTL: 15 * time.Minute,
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

func SetupAndSeed(t *testing.T) (*pgauth.Client, *QueryContainer) {
	db := ConnectToDatabaseAndSeed(t)
	client, err := pgauth.NewClient(db, basicClientConfig)
	require.NoError(t, err)
	return client, newQueryContainer(db)
}

func Setup(t *testing.T) (*pgauth.Client, *QueryContainer) {
	db := ConnectToDatabase(t)
	client, err := pgauth.NewClient(db, basicClientConfig)
	require.NoError(t, err)
	return client, newQueryContainer(db)
}
