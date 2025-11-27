# pgauth

A simple, PostgreSQL-backed authentication library for Go applications.

For the user guide, read [USERGUIDE.md](./USERGUIDE.md).

# Local setup

## Install the following tools

**SQLc CLI**
```
go install github.com/sqlc-dev/sqlc/cmd/sqlc@latest
```

**Goose CLI**
```
go install github.com/pressly/goose/v3/cmd/goose@latest
```

## .env

Create a .env file in the root of the project:

- `GOOSE_%` props are required for the Goose CLI commands to work.

```
GOOSE_DRIVER=postgres
GOOSE_DBSTRING=postgres://testuser:mysecretpassword@localhost:5433/pgauth-testdb
GOOSE_MIGRATION_DIR=./migrations
GOOSE_TABLE=auth_goose_migrations
```
