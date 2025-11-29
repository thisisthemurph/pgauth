package middleware

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/thisisthemurph/pgauth"
	"github.com/thisisthemurph/pgauth/claims"
	"github.com/thisisthemurph/pgauth/internal/auth"
)

type contextKey string

const claimsKey contextKey = "pgauth:claims"

type Config struct {
	Secret                 string
	AccessTokenCookieName  string
	RefreshTokenCookieName string
}

type Middleware struct {
	Config Config
	Client *pgauth.Client
}

// New creates a new Middleware struct for instantiating auth middleware
// that has access to the client and configuration values.
func New(c Config, client *pgauth.Client) *Middleware {
	return &Middleware{
		Config: c,
		Client: client,
	}
}

// WithClaimsInContext is middleware that parses the JWT and adds the claim to the context.
// If no JWT is available, the middleware continues as normal.
func (mw *Middleware) WithClaimsInContextMw(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodOptions {
			next.ServeHTTP(w, r)
			return
		}

		at, err := r.Cookie(mw.Config.AccessTokenCookieName)
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}

		rt, err := r.Cookie(mw.Config.RefreshTokenCookieName)
		if err != nil {
			next.ServeHTTP(w, r)
			return
		}

		accessToken := at.Value
		refreshToken := rt.Value

		claims, err := auth.ParseJWT(accessToken, mw.Config.Secret)
		if err != nil && errors.Is(err, jwt.ErrTokenExpired) {
			// Attempt to refresh the access token if it has expired.
			userID, sessionID, err := parseUserAndSessionID(claims)
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}

			tokens, err := mw.Client.Auth.RefreshAccessToken(r.Context(), userID, sessionID, refreshToken)
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}

			// Reparse the claims from the access token
			claims, err = auth.ParseJWT(tokens.AccessToken, mw.Config.Secret)
			if err != nil {
				next.ServeHTTP(w, r)
				return
			}

			mw.refreshCookies(w, r, tokens)
		} else if err != nil {
			// There has been an error parsing the JWT, but something other than expiration.
			next.ServeHTTP(w, r)
			return
		}

		ctx := context.WithValue(r.Context(), claimsKey, claims)
		r = r.WithContext(ctx)
		next.ServeHTTP(w, r)
	})
}

// refreshCookies reuses the access and refresh cookies on the request
// to override them with new values and expiration times.
func (mw *Middleware) refreshCookies(w http.ResponseWriter, r *http.Request, tokens *pgauth.TokenResponse) error {
	at, err := r.Cookie(mw.Config.AccessTokenCookieName)
	if err != nil {
		return fmt.Errorf("failed to get access token cookie: %w", err)
	}

	rt, err := r.Cookie(mw.Config.RefreshTokenCookieName)
	if err != nil {
		return fmt.Errorf("failed to get refresh token cookie: %w", err)
	}

	at.Value = tokens.AccessToken
	at.Expires = time.Now().Add(24 * time.Hour)
	rt.Value = tokens.RefreshToken
	rt.Expires = time.Now().Add(24 * time.Hour * 7)

	http.SetCookie(w, at)
	http.SetCookie(w, rt)
	return nil
}

// parseUserAndSessionID returns the user and sessio ID from the provided claims.
func parseUserAndSessionID(c *claims.Claims) (uuid.UUID, uuid.UUID, error) {
	if c == nil {
		return uuid.Nil, uuid.Nil, errors.New("claims is nil")
	}

	userID, err := c.UserID()
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}

	sessionID, err := uuid.Parse(c.SessionID)
	if err != nil {
		return uuid.Nil, uuid.Nil, err
	}

	return userID, sessionID, nil
}

// ClaimsFromContext returns any claims added to the HTTP context by the WithClaimsInContext middleware.
// A bool is also returned indicating if that context was present.
// If true, the user associated with the claims is authenticated, otherwise not.
func ClaimsFromContext(ctx context.Context) (*claims.Claims, bool) {
	if v := ctx.Value(claimsKey); v != nil {
		if c, ok := v.(*claims.Claims); ok {
			return c, true
		}
	}
	return nil, false
}
