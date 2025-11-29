package auth

import (
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/thisisthemurph/pgauth/claims"
	sessionrepo "github.com/thisisthemurph/pgauth/internal/repository/session"
	userrepo "github.com/thisisthemurph/pgauth/internal/repository/user"
)

var (
	ErrInvalidToken = errors.New("invalid token")
)

func NewSignedJWT(u userrepo.AuthUser, session sessionrepo.AuthSession, secret string) (string, error) {
	c := &claims.Claims{
		SessionID: session.ID.String(),
		UserData:  parseUserData(u.UserData),
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   u.ID.String(),
			Issuer:    "github.com/thisisthemurph/pgauth",
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(session.ExpiresAt),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, c)
	return token.SignedString([]byte(secret))
}

func parseUserData(data json.RawMessage) map[string]any {
	if data == nil {
		return nil
	}

	var result map[string]any
	if err := json.Unmarshal(data, &result); err != nil {
		return nil
	}

	return result
}

func ParseJWT(jwtToken string, secret string) (*claims.Claims, error) {
	c := &claims.Claims{}

	token, err := jwt.ParseWithClaims(jwtToken, c, func(t *jwt.Token) (any, error) {
		if t.Method.Alg() != jwt.SigningMethodHS256.Alg() {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(secret), nil
	})
	if err != nil {
		return c, err
	}
	if !token.Valid {
		return c, ErrInvalidToken
	}

	return c, nil
}
