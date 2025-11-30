package middleware

import (
	"context"
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/thisisthemurph/pgauth"
	"github.com/thisisthemurph/pgauth/claims"
	"github.com/thisisthemurph/pgauth/internal/auth"
	sessionrepo "github.com/thisisthemurph/pgauth/internal/repository/session"
	userrepo "github.com/thisisthemurph/pgauth/internal/repository/user"
	"github.com/thisisthemurph/pgauth/tests/seed"
	th "github.com/thisisthemurph/pgauth/tests/testhelpers"
)

var mwConfig = Config{
	Secret:                "this is only a secret",
	AccessTokenCookieName: "access_token",
	AccessTokenCookieFn: func(value string) *http.Cookie {
		return &http.Cookie{
			Name:     "access_token",
			Value:    value,
			Path:     "/",
			Expires:  time.Now().Add(24 * time.Hour),
			HttpOnly: true,
			Secure:   false,
			SameSite: http.SameSiteLaxMode,
		}
	},
	RefreshTokenCookieName: "refresh_token",
	RefreshTokenCookieFn: func(value string) *http.Cookie {
		return &http.Cookie{
			Name:     "refresh_token",
			Value:    value,
			Path:     "/",
			Expires:  time.Now().Add(24 * 7 * time.Hour),
			HttpOnly: true,
			Secure:   false,
			SameSite: http.SameSiteLaxMode,
		}
	},
}

func TestWithClaimsInContext_WithNoAccessToken_ContinuesWithoutClaims(t *testing.T) {
	client, _ := setupAndSeed(t)

	var seenClaims bool
	var claimsOnContext *claims.Claims
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claimsOnContext, seenClaims = ClaimsFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	mw, _ := New(mwConfig, client)
	handler := mw.WithClaimsInContextMw(next)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	// Asset that the claims can be derrived from the token on the HTTP context
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.False(t, seenClaims, "claims should be attached when jwt cookie is present")
	assert.Nil(t, claimsOnContext)
}

func TestWithClaimsInContext_WithValidAccessToken_RefreshesAccessToken(t *testing.T) {
	client, q := setupAndSeed(t)

	var seenClaims bool
	var claimsOnContext *claims.Claims
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claimsOnContext, seenClaims = ClaimsFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	mw, _ := New(mwConfig, client)
	handler := mw.WithClaimsInContextMw(next)

	user, err := q.UserQueries.GetUserByEmail(context.Background(), "alice@example.com")
	require.NoError(t, err)

	expiredAccessToken, refreshTokenValue := createJWT(t, user, q)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: mwConfig.AccessTokenCookieName, Value: expiredAccessToken})
	req.AddCookie(&http.Cookie{Name: mwConfig.RefreshTokenCookieName, Value: refreshTokenValue})
	rec := httptest.NewRecorder()

	// Asset that the claims can be derrived from the token on the HTTP context
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, seenClaims, "claims should be attached when jwt cookie is present")
	assert.NotNil(t, claimsOnContext)

	// Assert that the original refresh token is deleted
	allRefreshTokens, err := q.SessionQueries.GetRefreshTokensByUserID(context.Background(), user.ID)
	require.NoError(t, err)
	assert.Equal(t, 1, len(allRefreshTokens))
}

func TestWithClaimsInContext_WithExpiredAccessToken_RefreshesAccessToken(t *testing.T) {
	client, q := setupAndSeed(t)

	var seenClaims bool
	var claimsFromContext *claims.Claims
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claimsFromContext, seenClaims = ClaimsFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	mw, _ := New(mwConfig, client)
	handler := mw.WithClaimsInContextMw(next)

	user, err := q.UserQueries.GetUserByEmail(context.Background(), "alice@example.com")
	require.NoError(t, err)

	expiredAccessToken, refreshTokenValue := createExpiredJWT(t, user, q)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: mwConfig.AccessTokenCookieName, Value: expiredAccessToken})
	req.AddCookie(&http.Cookie{Name: mwConfig.RefreshTokenCookieName, Value: refreshTokenValue})
	rec := httptest.NewRecorder()

	// Asset that the claims can be derrived from the token on the HTTP context
	handler.ServeHTTP(rec, req)
	assert.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, seenClaims, "claims should be attached when jwt cookie is present")
	assert.NotNil(t, claimsFromContext)

	// Assert that the original refresh token is deleted
	allRefreshTokens, err := q.SessionQueries.GetRefreshTokensByUserID(context.Background(), user.ID)
	require.NoError(t, err)
	assert.Equal(t, 1, len(allRefreshTokens))
}

func createJWT(t *testing.T, user userrepo.AuthUser, q *th.QueryContainer) (string, string) {
	// Create session for the user - JWT takes time from session
	session, err := q.SessionQueries.CreateSession(context.Background(), sessionrepo.CreateSessionParams{
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(time.Hour * 24),
	})
	require.NoError(t, err)

	// Create refresh token for the user
	refreshToken, err := auth.GenerateRefreshToken()
	require.NoError(t, err)
	err = q.SessionQueries.RegisterRefreshToken(context.Background(), sessionrepo.RegisterRefreshTokenParams{
		UserID:      user.ID,
		HashedToken: refreshToken,
		ExpiresAt:   time.Now().Add(15 * time.Minute),
	})
	require.NoError(t, err)

	// Create JWT from the session
	expiredAccessToken, err := auth.NewSignedJWT(user, session, mwConfig.Secret)
	require.NoError(t, err)

	return expiredAccessToken, refreshToken
}

func createExpiredJWT(t *testing.T, user userrepo.AuthUser, q *th.QueryContainer) (string, string) {
	// Create a session that has expired.
	// This is required as the JWT takes it'expiredSession expiration time from the session.
	expiredSession, err := q.SessionQueries.CreateSession(context.Background(), sessionrepo.CreateSessionParams{
		UserID:    user.ID,
		ExpiresAt: time.Now().Add(time.Hour * -23),
	})
	require.NoError(t, err)

	// Create a refresh token that has not expired.
	refreshToken, err := auth.GenerateRefreshToken()
	require.NoError(t, err)
	err = q.SessionQueries.RegisterRefreshToken(context.Background(), sessionrepo.RegisterRefreshTokenParams{
		UserID:      user.ID,
		HashedToken: refreshToken,
		ExpiresAt:   time.Now().Add(15 * time.Minute),
	})
	require.NoError(t, err)

	// Create the expired JWT from the expired session
	expiredAccessToken, err := auth.NewSignedJWT(user, expiredSession, mwConfig.Secret)
	require.NoError(t, err)

	return expiredAccessToken, refreshToken
}

func connectToDatabaseAndSeed(t *testing.T) *sql.DB {
	db := th.ConnectToDatabase(t)
	err := seed.SeedDatabase(context.Background(), db, "../tests/seed/seed.sql")
	require.NoError(t, err)

	return db
}

func setupAndSeed(t *testing.T) (*pgauth.Client, *th.QueryContainer) {
	db := connectToDatabaseAndSeed(t)
	client, err := pgauth.NewClient(db, pgauth.Config{
		JWTSecret:       mwConfig.Secret,
		RefreshTokenTTL: 15 * time.Minute,
	})
	require.NoError(t, err)

	return client, &th.QueryContainer{
		UserQueries:    userrepo.New(db),
		SessionQueries: sessionrepo.New(db),
	}
}
