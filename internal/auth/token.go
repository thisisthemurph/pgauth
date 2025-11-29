package auth

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
)

// GenerateRefreshToken returns a URL-safe, cryptographically secure refresh token.
//
// Uses 32 bytes (256 bits) is a good defaul length.
// The length is the number of random bytes BEFORE encoding.
func GenerateRefreshToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", fmt.Errorf("failed to generate random bytes: %w", err)
	}

	// Use RawURLEncoding (no padding, URL-safe).
	token := base64.RawURLEncoding.EncodeToString(buf)
	return token, nil
}
