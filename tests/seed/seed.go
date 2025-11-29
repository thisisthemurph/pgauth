package seed

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"
)

func SeedDatabase(ctx context.Context, db *sql.DB, seedFilePath string) error {
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
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("failed to commit transaction: %w", err)
	}
	return nil
}
