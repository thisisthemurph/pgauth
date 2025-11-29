package auth

import "time"

// GetSessionExpirationTime calculates the new expiration time of a session from now.
func GetSessionExpirationTime() time.Time {
	return time.Now().Add(15 * time.Minute)
}
