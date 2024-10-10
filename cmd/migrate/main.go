package main

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"

	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/thisisthemurph/pgauth/pkg/migrator"
)

const DefaultMigrationPath = "file://migrations"

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

func migrate(direction migrator.MigrationDirection, config DatabaseConfig) error {
	db, err := connect(config)
	if err != nil {
		return err
	}
	defer db.Close()

	m := migrator.NewPostgresMigrator(db, config.DatabaseName, DefaultMigrationPath)
	return m.Migrate(direction)
}

func seed(ctx context.Context, config DatabaseConfig) error {
	db, err := connect(config)
	if err != nil {
		return err
	}
	defer db.Close()

	seedFilePath := "tests/seed/seed.sql"
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
		} else {
			fmt.Printf("Executed statement:\n%s\n\n", stmt)
		}
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	return nil
}

func printUsage() {
	usage := `Usage: migrate [command] [database_name] [database_uri]

Commands:
  up       - Apply migrations to the database
  down     - Rollback migrations from the database
  seed     - Seed the database with initial data

Arguments:
  database_name - The name of the database to operate on
  database_uri  - The URI connection string for the database`

	_, _ = fmt.Fprintln(os.Stdout, usage)
}

func main() {
	if len(os.Args) != 4 {
		printUsage()
		os.Exit(1)
	}

	commandArg := os.Args[1]
	dbNameArg := os.Args[2]
	dbURIArg := os.Args[3]
	config := NewDatabaseConfig(dbNameArg, dbURIArg)

	if commandArg == "seed" {
		if err := seed(context.Background(), config); err != nil {
			_, _ = fmt.Fprintf(os.Stderr, "%s\n", err.Error())
			os.Exit(1)
		}
		os.Exit(0)
	}

	direction := migrator.NewMigrationDirection(commandArg)
	if err := migrate(direction, config); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%s\n", err.Error())
		os.Exit(1)
	}
}
