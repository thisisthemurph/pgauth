package migrator

import (
	"database/sql"
	"errors"
	"fmt"
	"log/slog"
	"os"

	"github.com/golang-migrate/migrate/v4"
	"github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

var ErrUnknownDirection = errors.New("unknown direction expected up or down")

type MigrationDirection string

const (
	MigrationDirectionUp      MigrationDirection = "up"
	MigrationDirectionDown    MigrationDirection = "down"
	MigrationDirectionUnknown MigrationDirection = "unknown"
)

func NewMigrationDirection(direction string) MigrationDirection {
	switch direction {
	case "up":
		return MigrationDirectionUp
	case "down":
		return MigrationDirectionDown
	default:
		return MigrationDirectionUnknown
	}
}

type Migrator interface {
	Migrate(direction MigrationDirection) error
}

func NewPostgresMigrator(db *sql.DB, dbName, migrationPath string) *PostgresMigrator {
	return &PostgresMigrator{
		DB:            db,
		DBName:        dbName,
		MigrationPath: migrationPath,
		Logger:        slog.New(slog.NewTextHandler(os.Stdout, nil)),
	}
}

type PostgresMigrator struct {
	DB            *sql.DB
	DBName        string
	MigrationPath string
	Logger        *slog.Logger
}

func (m *PostgresMigrator) WithLogger(logger *slog.Logger) *PostgresMigrator {
	m.Logger = logger
	return m
}

func (m *PostgresMigrator) Migrate(direction MigrationDirection) error {
	driver, err := postgres.WithInstance(m.DB, &postgres.Config{})
	if err != nil {
		return fmt.Errorf("could not create database driver: %w", err)
	}

	mig, err := migrate.NewWithDatabaseInstance(m.MigrationPath, m.DBName, driver)
	if err != nil {
		return fmt.Errorf("could not create migration instance: %w", err)
	}

	m.Logger.Info("starting database migration", "direction", direction)

	switch direction {
	case MigrationDirectionUp:
		if err := mig.Up(); err != nil {
			if errors.Is(err, migrate.ErrNoChange) {
				m.Logger.Info("nothing to migrate")
				return nil
			}
			return fmt.Errorf("could not run migration: %w", err)
		}
	case MigrationDirectionDown:
		if err := mig.Down(); err != nil {
			if errors.Is(err, migrate.ErrNoChange) {
				m.Logger.Info("nothing to migrate")
				return nil
			}
			return fmt.Errorf("could not run migration: %w", err)
		}
	default:
		return fmt.Errorf("%w got %s", ErrUnknownDirection, direction)
	}

	m.Logger.Info("database migration complete")
	return nil
}
