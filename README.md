# pgauth

A simple, PostgreSQL-backed authentication library for Go applications.

## Features

- Email/password authentication with email confirmation
- Sign in with JWT session tokens
- Password reset flow (forgot password)
- Password and email update with OTP verification
- User management (CRUD operations)
- HTTP middleware for JWT authentication

## Installation

```bash
go get github.com/thisisthemurph/pgauth
```

## Database Setup

Run the migrations in the `migrations/` directory against your PostgreSQL database:

```bash
# Using the included migration tool
go run ./cmd/migrate/. up <database-name> <connection-string>

# Example
go run ./cmd/migrate/. up mydb "postgres://user:pass@localhost:5432/mydb?sslmode=disable"
```

Or use your preferred migration tool (goose, migrate, etc.) with the SQL files in `migrations/`.

## Configuration

```go
import (
    "database/sql"
    "github.com/thisisthemurph/pgauth"
    _ "github.com/lib/pq"
)

db, err := sql.Open("postgres", "your-connection-string")
if err != nil {
    panic(err)
}

client, err := pgauth.NewClient(db, pgauth.ClientConfig{
    JWTSecret:      "your-secret-key-keep-this-safe",
    PasswordMinLen: 8,
})
if err != nil {
    panic(err)
}
```

## Usage

### Sign Up

```go
user, err := client.Auth.SignUpWithEmailAndPassword(ctx, "user@example.com", "password123")
if err != nil {
    // Handle error (duplicate email, weak password, etc.)
}

// user.ConfirmationToken is generated - send this via email
// Your app sends: https://yourapp.com/confirm?token={user.ConfirmationToken}
```

### Confirm Email

```go
err := client.Auth.ConfirmSignUp(ctx, "user@example.com", confirmationToken)
if err != nil {
    // Invalid or expired token
}
// User email is now confirmed, they can sign in
```

### Sign In

```go
token, err := client.Auth.SignInWithEmailAndPassword(ctx, "user@example.com", "password123")
if err != nil {
    // Invalid credentials or email not confirmed
}

// Return token to client - they send it in Authorization header
// Authorization: Bearer {token}
```

### Forgot Password

```go
// Step 1: User requests password reset
resetToken, err := client.Auth.RequestPasswordReset(ctx, "user@example.com")
if err != nil {
    // Handle error
}
// Send resetToken via email: https://yourapp.com/reset?token={resetToken}

// Step 2: User submits new password with token
err = client.Auth.ConfirmPasswordReset(ctx, resetToken, "newPassword123")
if err != nil {
    // Invalid or expired token
}
// Password is now reset
```

### Update Password (Authenticated User)

```go
// User knows current password and wants to change it
response, err := client.Auth.RequestPasswordUpdate(ctx, userID, "currentPassword", "newPassword123")
if err != nil {
    // Wrong current password or weak new password
}

// Confirm with token
err = client.Auth.ConfirmPasswordUpdate(ctx, userID, response.Token)
// Or confirm with OTP (if sent via email/SMS)
// err = client.Auth.ConfirmPasswordUpdateWithOTP(ctx, userID, response.OTP)
```

### Update Email

```go
response, err := client.Auth.RequestEmailUpdate(ctx, userID, "newemail@example.com")
if err != nil {
    // Email already taken or invalid
}

// Confirm with token
err = client.Auth.ConfirmEmailUpdate(ctx, userID, response.Token)
// Or confirm with OTP
// err = client.Auth.ConfirmEmailChangeWithOTP(ctx, userID, response.OTP)
```

### Get User

```go
// By ID
user, err := client.User.Get(ctx, userID)

// By email
user, err := client.User.GetByEmail(ctx, "user@example.com")
```

### Delete User

```go
// Soft delete (sets deleted_at timestamp)
user, err := client.User.SoftDelete(ctx, userID)

// Hard delete (removes from database)
user, err := client.User.Delete(ctx, userID)
```

## HTTP Middleware

pgauth includes middleware for extracting JWT claims from HTTP requests:

```go
import (
    "net/http"
    "github.com/thisisthemurph/pgauth/middleware"
)

mux := http.NewServeMux()

// Wrap your handlers with the middleware
handler := middleware.WithClaimsInContext(mux, "your-jwt-secret")

http.ListenAndServe(":8080", handler)
```

Access claims in your handlers:

```go
func protectedHandler(w http.ResponseWriter, r *http.Request) {
    claims, authenticated := middleware.ClaimsFromContext(r.Context())
    if !authenticated {
        http.Error(w, "Unauthorized", http.StatusUnauthorized)
        return
    }
    
    userID := claims.Subject // UUID of authenticated user
    sessionID := claims.SessionID
    // ... your handler logic
}
```

The middleware checks both `Authorization: Bearer <token>` header and `jwt` cookie.

## Error Handling

Common errors to handle:

```go
import "github.com/thisisthemurph/pgauth/internal/client"

switch {
case errors.Is(err, client.ErrInvalidCredentials):
    // Wrong email/password
case errors.Is(err, client.ErrEmailNotConfirmed):
    // User hasn't confirmed their email yet
case errors.Is(err, client.ErrDuplicateEmail):
    // Email already registered
case errors.Is(err, client.ErrInvalidPassword):
    // Password doesn't meet requirements
case errors.Is(err, client.ErrInvalidToken):
    // Token expired or invalid
case errors.Is(err, client.ErrUserNotFound):
    // User doesn't exist
}
```
