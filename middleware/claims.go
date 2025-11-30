package middleware

import (
	"context"
	"errors"
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

type CookieSettings struct {
	Name     string
	Path     string
	TTL      time.Duration
	Secure   bool
	SameSite http.SameSite
}

type Config struct {
	Secret                 string
	AccessTokenCookieName  string
	AccessTokenCookieFn    func(string) *http.Cookie
	RefreshTokenCookieName string
	RefreshTokenCookieFn   func(string) *http.Cookie
}

func (c Config) Validate() error {
	if c.Secret == "" {
		return errors.New("secret configuration is required")
	}

	if c.AccessTokenCookieName == "" {
		return errors.New("the access token cookie must have a name")
	}

	if c.RefreshTokenCookieName == "" {
		return errors.New("the refresh token cookie must have a name")
	}

	if c.AccessTokenCookieFn == nil {
		return errors.New("the access token function must be configured")
	}

	if c.RefreshTokenCookieFn == nil {
		return errors.New("the refresh token function must be configured")
	}

	return nil
}

type Middleware struct {
	Config Config
	Client *pgauth.Client
}

// New creates a new Middleware struct for instantiating auth middleware
// that has access to the client and configuration values.
func New(c Config, client *pgauth.Client) (*Middleware, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}

	return &Middleware{
		Config: c,
		Client: client,
	}, nil
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

			http.SetCookie(w, mw.Config.AccessTokenCookieFn(tokens.AccessToken))
			http.SetCookie(w, mw.Config.RefreshTokenCookieFn(tokens.RefreshToken))
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
