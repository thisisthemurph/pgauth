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

func NewClient(db *sql.DB, c ClientConfig) (*Client, error) {
	if c.JWTSecret == "" {
		return nil, errors.New("JWTSecret field must be set in ClientConfig")
	}

	config := client.Config{
		JWTSecret:      c.JWTSecret,
		PasswordMinLen: c.PasswordMinLen,
	}

	return &Client{
		Auth: client.NewAuthClient(db, config),
		User: client.NewUserClient(db, config),
	}, nil
}
