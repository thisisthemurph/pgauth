package types

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// Claims represents JWT claims for authenticated users.
type Claims struct {
	jwt.RegisteredClaims
	SessionID string         `json:"sid"`
	UserData  map[string]any `json:"user_data,omitempty"`
}

// UserID extracts and parses the user ID from the JWT subject claim.
func (c *Claims) UserID() (uuid.UUID, error) {
	return uuid.Parse(c.Subject)
}
