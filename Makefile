test-db-up:
	docker compose up -d
	go run ./cmd/migrate/. up testdb "postgres://testuser:mysecretpassword@localhost:5432/testdb?sslmode=disable"
