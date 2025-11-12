package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"strings"

	_ "github.com/lib/pq"
	"github.com/pressly/goose/v3"
)

const (
	migrationsDir = "migrations"
	seedFilePath  = "tests/seed/seed.sql"
)

type DatabaseConfig struct {
	DatabaseName string
	DatabaseURI  string
}

func NewDatabaseConfig(dbName, dbURI string) DatabaseConfig {
	return DatabaseConfig{
		DatabaseName: dbName,
		DatabaseURI:  dbURI,
	}
}

func connect(config DatabaseConfig) (*sql.DB, error) {
	db, err := sql.Open("postgres", config.DatabaseURI)
	if err != nil {
		return nil, fmt.Errorf("could not connect to database: %w", err)
	}

	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("could not ping database: %w", err)
	}

	return db, nil
}

func migrateWithGoose(direction string, config DatabaseConfig) error {
	db, err := connect(config)
	if err != nil {
		return err
	}
	defer db.Close()

	if err := goose.SetDialect("postgres"); err != nil {
		return fmt.Errorf("could not set goose dialect: %w", err)
	}

	fmt.Printf("starting goose migration: direction=%s\n", direction)

	var migrateErr error
	switch direction {
	case "up":
		migrateErr = goose.Up(db, migrationsDir)
	case "down":
		migrateErr = goose.Down(db, migrationsDir)
	default:
		return fmt.Errorf("unknown direction %s", direction)
	}

	if migrateErr != nil {
		if isNoopMigrationError(migrateErr) {
			fmt.Println("nothing to migrate")
			return nil
		}
		return fmt.Errorf("goose migration failed: %w", migrateErr)
	}

	fmt.Println("database migration complete")
	return nil
}

func isNoopMigrationError(err error) bool {
	return errors.Is(err, goose.ErrNoNextVersion) ||
		errors.Is(err, goose.ErrNoMigrationFiles) ||
		errors.Is(err, goose.ErrNoCurrentVersion)
}

func seed(ctx context.Context, config DatabaseConfig) error {
	db, err := connect(config)
	if err != nil {
		return err
	}
	defer db.Close()

	sqlFile, err := os.ReadFile(seedFilePath)
	if err != nil {
		return fmt.Errorf("could not read seed.sql: %w", err)
	}

	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("failed to begin transaction: %w", err)
	}

	sqlStatements := strings.Split(string(sqlFile), ";")
	for _, statement := range sqlStatements {
		stmt := strings.TrimSpace(statement)
		if stmt == "" {
			continue
		}

		if _, err := tx.ExecContext(ctx, stmt); err != nil {
			if rollbackErr := tx.Rollback(); rollbackErr != nil {
				return fmt.Errorf("could not rollback transaction: %w", rollbackErr)
			}
			return fmt.Errorf("failed to execute statement: %w", err)
		}

		fmt.Printf("Executed statement:\n%s\n\n", stmt)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}

	return nil
}
