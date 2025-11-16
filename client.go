package pgauth

import (
	"database/sql"
	"embed"
	"errors"
	"fmt"

	"github.com/pressly/goose/v3"
	"github.com/thisisthemurph/pgauth/internal/client"
)

//go:embed migrations/*.sql
var embedMigrations embed.FS

type ClientConfig struct {
	PasswordMinLen int
	JWTSecret      string
}

type Client struct {
	Auth *client.AuthClient
	User *client.UserClient
}

// NewClient creates a new pgauth Client with the provided database connection and configuration.
// The Auth and User clients can be accessed via the returned Client struct.
//
// Database migrations will be run automatically when this function is called.
func NewClient(db *sql.DB, c ClientConfig) (*Client, error) {
	if c.JWTSecret == "" {
		return nil, errors.New("JWTSecret field must be set in ClientConfig")
	}

	// Run migrations automatically
	if err := runMigrations(db); err != nil {
		return nil, fmt.Errorf("failed to run migrations: %w", err)
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

// runMigrations applies any pending database migrations.
func runMigrations(db *sql.DB) error {
	goose.SetBaseFS(embedMigrations)

	if err := goose.SetDialect("postgres"); err != nil {
		return err
	}

	if err := goose.Up(db, "migrations"); err != nil {
		if errors.Is(err, goose.ErrNoNextVersion) {
			return nil
		}
		return err
	}

	return nil
}
