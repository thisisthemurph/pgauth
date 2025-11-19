package claims

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Claims represents JWT claims for authenticated users.
// It extends the standard JWT registered claims with additional user-specific data.
type Claims struct {
	jwt.RegisteredClaims

	// SessionID is the unique identifier for the user's session.
	SessionID string `json:"sid"`

	// UserData contains custom user data that should be available in the JWT.
	UserData map[string]any `json:"user_data,omitempty"`
}

// UserID extracts and parses the user ID from the JWT subject claim.
// It returns an error if the subject is not a valid UUID.
func (c *Claims) UserID() (uuid.UUID, error) {
	return uuid.Parse(c.Subject)
}
