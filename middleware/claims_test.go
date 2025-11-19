package middleware

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/thisisthemurph/pgauth/internal/types"
)

func TestWithClaimsInContext_NoToken_ContinuesWithoutClaims(t *testing.T) {
	restore := hijackParser(t, nil, errors.New("no token"))
	defer restore()

	seenClaims := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, ok := ClaimsFromContext(r.Context())
		seenClaims = ok
		w.WriteHeader(http.StatusTeapot)
	})

	handler := WithClaimsInContext(next, "secret")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusTeapot, rec.Code, "should continue to next handler")
	assert.False(t, seenClaims, "no claims expected when no token present")
}

func TestWithClaimsInContext_BearerToken_AttachesClaims(t *testing.T) {
	fake := &types.Claims{}
	restore := hijackParser(t, fake, nil)
	defer restore()

	var got *types.Claims
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got, _ = ClaimsFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	handler := WithClaimsInContext(next, "secret")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer abc.def.ghi")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.NotNil(t, got, "claims should be attached")
	assert.Equal(t, fake, got, "should pass through the same claims pointer")
}

func TestWithClaimsInContext_BearerCaseInsensitive_AttachesClaims(t *testing.T) {
	fake := &types.Claims{}
	restore := hijackParser(t, fake, nil)
	defer restore()

	var ok bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, ok = ClaimsFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	handler := WithClaimsInContext(next, "secret")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "bEaReR token123")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, ok, "claims should be attached for mixed-case Bearer")
}

func TestWithClaimsInContext_CookieToken_AttachesClaims(t *testing.T) {
	fake := &types.Claims{}
	restore := hijackParser(t, fake, nil)
	defer restore()

	var ok bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, ok = ClaimsFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	handler := WithClaimsInContext(next, "secret")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: "jwt", Value: "cookie.token"})
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.True(t, ok, "claims should be attached when jwt cookie is present")
}

func TestWithClaimsInContext_InvalidToken_DoesNotAttachClaims(t *testing.T) {
	restore := hijackParser(t, nil, errors.New("bad token"))
	defer restore()

	var ok bool
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, ok = ClaimsFromContext(r.Context())
		w.WriteHeader(http.StatusOK)
	})
	handler := WithClaimsInContext(next, "secret")

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("Authorization", "Bearer invalid.token")
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	assert.Equal(t, http.StatusOK, rec.Code, "chain should continue on invalid token")
	assert.False(t, ok, "claims should NOT be attached on parse error")
}

// hijackParser replaces the package-level parseJWT with a stub and returns a restore func.
func hijackParser(t *testing.T, ret *types.Claims, err error) (restore func()) {
	t.Helper()
	orig := parseJWT
	parseJWT = func(token, secret string) (*types.Claims, error) {
		return ret, err
	}
	return func() { parseJWT = orig }
}
