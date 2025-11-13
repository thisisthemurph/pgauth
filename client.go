package pgauth

import (
	"database/sql"
	"errors"

	"github.com/thisisthemurph/pgauth/internal/client"
)

type ClientConfig struct {
	ValidatePassword     bool
	PasswordMinLen       int
	JWTSecret            string
	JWTExpirationMinutes int
	UseRefreshToken      bool
}

type Client struct {
	Auth *client.AuthClient
	User *client.UserClient
}

func NewClient(db *sql.DB, config ClientConfig) (*Client, error) {
	if config.JWTSecret == "" {
		return nil, errors.New("JWTSecret field must be set in ClientConfig")
	}

	return &Client{
		Auth: client.NewAuthClient(db, client.AuthClientConfig{
			JWTSecret:      config.JWTSecret,
			PasswordMinLen: config.PasswordMinLen,
		}),
		User: client.NewUserClient(db, client.UserClientConfig{
			JWTSecret:      config.JWTSecret,
			PasswordMinLen: config.PasswordMinLen,
		}),
	}, nil
}
