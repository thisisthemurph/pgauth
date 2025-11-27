package pgauth

import (
	"database/sql"
	"embed"
	"errors"
	"fmt"

	"github.com/pressly/goose/v3"
)

//go:embed migrations/*.sql
var embedMigrations embed.FS

type Client struct {
	Auth *AuthClient
	User *UserClient
}

// Config holds the configuration for the Auth and User clients.
type Config struct {
	// JWTSecret is the secret key used to sign JWT tokens.
	JWTSecret string

	// PasswordMinLen is the minimum length required for passwords.
	PasswordMinLen int
}

// NewClient creates a new pgauth Client with the provided database connection and configuration.
// The Auth and User clients can be accessed via the returned Client struct.
//
// Database migrations will be run automatically when this function is called.
func NewClient(db *sql.DB, config Config) (*Client, error) {
	if config.JWTSecret == "" {
		return nil, errors.New("JWTSecret field must be set in the config")
	}

	// Run migrations automatically
	if err := runMigrations(db); err != nil {
		return nil, fmt.Errorf("failed to run migrations: %w", err)
	}

	return &Client{
		Auth: newAuthClient(db, config),
		User: newUserClient(db, config),
	}, nil
}

// runMigrations applies any pending database migrations.
func runMigrations(db *sql.DB) error {
	goose.SetBaseFS(embedMigrations)

	if err := goose.SetDialect("postgres"); err != nil {
		return err
	}

	goose.SetTableName("auth_goose_migrations")

	if err := goose.Up(db, "migrations"); err != nil {
		if errors.Is(err, goose.ErrNoNextVersion) {
			return nil
		}
		return err
	}

	return nil
}
