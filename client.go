package pgauth

import (
	"database/sql"
	"github.com/thisisthemurph/pgauth/internal/client"
)

type ClientConfig struct {
	ValidatePassword bool
	PasswordMinLen   int
}

type Client struct {
	Auth client.AuthClient
	User client.UserClient
}

func NewClient(db *sql.DB, config *ClientConfig) Client {
	clientConfig := ClientConfig{}
	if config != nil {
		clientConfig = *config
	}

	return Client{
		Auth: client.NewAuthClient(db, clientConfig.PasswordMinLen),
		User: client.NewUserClient(db, clientConfig.PasswordMinLen),
	}
}
