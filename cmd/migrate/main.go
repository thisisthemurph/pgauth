package main

import (
	"context"
	"fmt"
	"os"
)

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

	if err := migrateWithGoose(commandArg, config); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "%s\n", err.Error())
		os.Exit(1)
	}
}
