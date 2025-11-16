package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/thisisthemurph/pgauth/internal/auth"
)

type contextKey string

const claimsKey contextKey = "pgauth:claims"

// parseJWT is a variable holding a function to allow for easier testing.
var parseJWT = auth.ParseJWT

// WithClaimsInContext is middleware that parses the JWT and adds the claim to the context.
// If no JWT is available, the middleware continues as normal.
func WithClaimsInContext(next http.Handler, secret string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := getTokenFromRequest(r)
		if token == "" {
			next.ServeHTTP(w, r)
			return
		}

		claims, err := parseJWT(token, secret)
		if err == nil {
			ctx := context.WithValue(r.Context(), claimsKey, claims)
			r = r.WithContext(ctx)
		}

		next.ServeHTTP(w, r)
	})
}

// ClaimsFromContext returns any claims added to the HTTP context by the WithClaimsInContext middleware.
// A bool is also returned indicating if that context was present.
// If true, the user associated with the claims is authenticated, otherwise not.
func ClaimsFromContext(ctx context.Context) (*auth.Claims, bool) {
	if v := ctx.Value(claimsKey); v != nil {
		if c, ok := v.(*auth.Claims); ok {
			return c, true
		}
	}
	return nil, false
}

func getTokenFromRequest(r *http.Request) string {
	auth := r.Header.Get("Authorization")
	if strings.HasPrefix(strings.ToLower(auth), "bearer ") {
		return strings.TrimSpace(auth[7:])
	}

	if c, err := r.Cookie("jwt"); err == nil {
		return c.Value
	}

	return ""
}
