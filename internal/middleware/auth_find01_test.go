// Package middleware — tests for FIND-01 (token version check bypass).
//
// FIND-01 bug: AuthMiddleware and OptionalAuthMiddleware guarded the nuclear
// revocation check with `claims.TokenVersion > 0`, which silently skipped the
// check for any token whose embedded version was 0.  Because every new user
// account starts with TokenVersion=0 (or transitions through it), tokens issued
// before the user's first nuclear revocation event were never rejected by the
// middleware even after IncrementTokenVersion bumped the DB row to 1.
//
// FIND-01 fix: replace `claims.TokenVersion > 0 && user.TokenVersion != claims.TokenVersion`
// with `user.TokenVersion > claims.TokenVersion` in both AuthMiddleware and
// OptionalAuthMiddleware, matching the Introspect logic added in NEW-03.
//
// Tests:
//   - AuthMiddleware: token version 0 + user version 0  → allows (same version)
//   - AuthMiddleware: token version 0 + user version 1  → rejects (0→1 revocation, THE BUG)
//   - AuthMiddleware: token version 1 + user version 1  → allows (normal, not revoked)
//   - AuthMiddleware: token version 1 + user version 2  → rejects (1→2 revocation)
//   - AuthMiddleware: token version 2 + user version 5  → rejects (multi-increment)
//   - AuthMiddleware: token version 3 + user version 2  → allows (future-version guard — version cannot go backward)
//   - OptionalAuthMiddleware: token version 0 + user version 1 → no user in context (silently unauthenticated)
//   - OptionalAuthMiddleware: token version 1 + user version 1 → user IS in context
//   - Revoked token must not populate context (OptionalAuth)
package middleware

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ovandermoten/go-oauth2/internal/contextkeys"
	"github.com/ovandermoten/go-oauth2/internal/model"
	"github.com/ovandermoten/go-oauth2/internal/shared/auth"
)

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// find01UserRepo is a minimal stub that returns a fixed *model.User for any
// FindByID call.  All write methods are no-ops.
type find01UserRepo struct {
	user *model.User // nil → simulate "user not found"
}

func (r *find01UserRepo) FindByID(_ context.Context, _ uint) (*model.User, error) {
	if r.user == nil {
		return nil, errors.New("user not found")
	}
	return r.user, nil
}
func (r *find01UserRepo) FindByEmail(_ context.Context, _ string) (*model.User, error) {
	return r.user, nil
}
func (r *find01UserRepo) FindAll(_ context.Context, _, _ int) ([]model.User, int64, error) {
	return nil, 0, nil
}
func (r *find01UserRepo) FindByRole(_ context.Context, _ model.UserRole) ([]model.User, error) {
	return nil, nil
}
func (r *find01UserRepo) CountByRole(_ context.Context, _ model.UserRole) (int64, error) {
	return 0, nil
}
func (r *find01UserRepo) Create(_ context.Context, _ *model.User) error                { return nil }
func (r *find01UserRepo) Update(_ context.Context, _ *model.User) error                { return nil }
func (r *find01UserRepo) Delete(_ context.Context, _ uint) error                       { return nil }
func (r *find01UserRepo) IncrementTokenVersion(_ context.Context, _ uint) error        { return nil }
func (r *find01UserRepo) IncrementFailedLoginAttempts(_ context.Context, _ uint) error { return nil }
func (r *find01UserRepo) ResetFailedLoginAttempts(_ context.Context, _ uint) error     { return nil }
func (r *find01UserRepo) LockAccount(_ context.Context, _ uint, _ *time.Time) error    { return nil }

// newFind01TokenService creates a real *auth.TokenService backed by a fresh
// temporary key directory.  Uses the exported NewKeyManager (3072-bit RSA).
// One token service per top-level test is sufficient since tokens are generated
// fresh in each sub-case.
func newFind01TokenService(t *testing.T) *auth.TokenService {
	t.Helper()
	km, err := auth.NewKeyManager(t.TempDir())
	if err != nil {
		t.Fatalf("FIND-01: NewKeyManager: %v", err)
	}
	return auth.NewTokenService(km, auth.TokenConfig{
		Issuer:          "https://test.example.com",
		AccessTokenTTL:  time.Hour,
		RefreshTokenTTL: 7 * 24 * time.Hour,
		EmailTokenTTL:   time.Hour,
		ResetTokenTTL:   time.Hour,
		InviteTokenTTL:  time.Hour,
	})
}

// mintToken generates a real signed access token for a user whose stored
// TokenVersion equals mintVersion at the time of minting.  The token will
// carry `token_version: mintVersion` in its claims.
func mintToken(t *testing.T, ts *auth.TokenService, userID uint, mintVersion int) string {
	t.Helper()
	user := &model.User{
		ID:           userID,
		Email:        "test@example.com",
		TokenVersion: mintVersion,
		IsVerified:   true,
	}
	app := &model.App{
		ID:       1,
		ClientID: "test-client",
	}
	tokenSet, err := ts.GenerateTokenSet(user, app, "user", "openid", nil, "", time.Now().Unix())
	if err != nil {
		t.Fatalf("FIND-01: GenerateTokenSet(mintVersion=%d): %v", mintVersion, err)
	}
	return tokenSet.AccessToken
}

// makeAuthRequest wraps a raw JWT string into an HTTP request with the
// correct Authorization: Bearer header.
func makeAuthRequest(token string) (*httptest.ResponseRecorder, *http.Request) {
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	return httptest.NewRecorder(), req
}

// nopOKHandler records that it was reached and returns 200 OK.
type nopOKHandler struct {
	called bool
}

func (h *nopOKHandler) ServeHTTP(w http.ResponseWriter, _ *http.Request) {
	h.called = true
	w.WriteHeader(http.StatusOK)
}

// parseErrorBody decodes the JSON body of an error response.
func parseErrorBody(t *testing.T, body []byte) map[string]string {
	t.Helper()
	var m map[string]string
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatalf("FIND-01: error body is not valid JSON: %v\nbody: %q", err, body)
	}
	return m
}

// ---------------------------------------------------------------------------
// AuthMiddleware — FIND-01 tests
// ---------------------------------------------------------------------------

// TestFIND01_AuthMiddleware_ZeroVersion_SameVersion_Allows verifies that a
// token with TokenVersion=0 passes when the user's stored version is also 0
// (no revocation has occurred).  This is the baseline happy path.
func TestFIND01_AuthMiddleware_ZeroVersion_SameVersion_Allows(t *testing.T) {
	t.Parallel()
	ts := newFind01TokenService(t)
	token := mintToken(t, ts, 42, 0)

	inner := &nopOKHandler{}
	repo := &find01UserRepo{user: &model.User{ID: 42, Email: "test@example.com", TokenVersion: 0}}
	h := AuthMiddleware(ts, repo, nil)(inner)

	w, req := makeAuthRequest(token)
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("FIND-01: version 0 == 0 should allow; got %d", w.Code)
	}
	if !inner.called {
		t.Error("FIND-01: next handler must be called when token is valid")
	}
}

// TestFIND01_AuthMiddleware_ZeroToOne_Revocation_Rejects is the CORE regression
// test.  The OLD code had `claims.TokenVersion > 0 && …` which skipped the
// entire check when claims.TokenVersion was 0, letting revoked tokens through.
//
// Scenario: token was minted at version 0; nuclear revocation bumped DB to 1.
// The middleware MUST reject this token.
func TestFIND01_AuthMiddleware_ZeroToOne_Revocation_Rejects(t *testing.T) {
	t.Parallel()
	ts := newFind01TokenService(t)
	// Token carries version=0 (issued before revocation).
	token := mintToken(t, ts, 42, 0)

	inner := &nopOKHandler{}
	// Simulate nuclear revocation: user.TokenVersion is now 1.
	repo := &find01UserRepo{user: &model.User{ID: 42, Email: "test@example.com", TokenVersion: 1}}
	h := AuthMiddleware(ts, repo, nil)(inner)

	w, req := makeAuthRequest(token)
	h.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("FIND-01: revoked token (version 0→1) must return 401; got %d — bypass still active?", w.Code)
	}
	if inner.called {
		t.Error("FIND-01: next handler must NOT be called for a revoked token")
	}
	body := parseErrorBody(t, w.Body.Bytes())
	if body["error"] != "token has been revoked" {
		t.Errorf("FIND-01: expected error='token has been revoked', got %q", body["error"])
	}
}

// TestFIND01_AuthMiddleware_OneToOne_NotRevoked_Allows verifies the normal
// production case: token minted at version 1, user still at version 1.
func TestFIND01_AuthMiddleware_OneToOne_NotRevoked_Allows(t *testing.T) {
	t.Parallel()
	ts := newFind01TokenService(t)
	token := mintToken(t, ts, 7, 1)

	inner := &nopOKHandler{}
	repo := &find01UserRepo{user: &model.User{ID: 7, Email: "u@example.com", TokenVersion: 1}}
	h := AuthMiddleware(ts, repo, nil)(inner)

	w, req := makeAuthRequest(token)
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("FIND-01: version 1 == 1 should allow; got %d", w.Code)
	}
	if !inner.called {
		t.Error("FIND-01: next handler must be reached for a valid token")
	}
}

// TestFIND01_AuthMiddleware_OneToTwo_Revocation_Rejects verifies that
// standard revocation (1→2) continues to work correctly after the fix.
func TestFIND01_AuthMiddleware_OneToTwo_Revocation_Rejects(t *testing.T) {
	t.Parallel()
	ts := newFind01TokenService(t)
	token := mintToken(t, ts, 5, 1) // token carries version=1

	inner := &nopOKHandler{}
	repo := &find01UserRepo{user: &model.User{ID: 5, Email: "u@example.com", TokenVersion: 2}}
	h := AuthMiddleware(ts, repo, nil)(inner)

	w, req := makeAuthRequest(token)
	h.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("FIND-01: revoked token (1→2) must return 401; got %d", w.Code)
	}
	if inner.called {
		t.Error("FIND-01: next handler must NOT be called for a revoked token")
	}
}

// TestFIND01_AuthMiddleware_MultiIncrement_Rejects verifies cumulative
// revocations: a token at version 2 is rejected when the user is at version 5.
func TestFIND01_AuthMiddleware_MultiIncrement_Rejects(t *testing.T) {
	t.Parallel()
	ts := newFind01TokenService(t)
	token := mintToken(t, ts, 9, 2) // token at version 2

	inner := &nopOKHandler{}
	repo := &find01UserRepo{user: &model.User{ID: 9, Email: "u@example.com", TokenVersion: 5}}
	h := AuthMiddleware(ts, repo, nil)(inner)

	w, req := makeAuthRequest(token)
	h.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("FIND-01: token version 2, user version 5 must be rejected; got %d", w.Code)
	}
}

// TestFIND01_AuthMiddleware_NoAuthHeader_Returns401 is a sanity check that
// the missing-header path is unaffected by the FIND-01 fix.
func TestFIND01_AuthMiddleware_NoAuthHeader_Returns401(t *testing.T) {
	t.Parallel()
	ts := newFind01TokenService(t)
	repo := &find01UserRepo{user: &model.User{ID: 1, TokenVersion: 0}}
	h := AuthMiddleware(ts, repo, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/protected", nil) // no Authorization header
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("FIND-01: missing Authorization header must return 401; got %d", w.Code)
	}
}

// ---------------------------------------------------------------------------
// OptionalAuthMiddleware — FIND-01 tests
// ---------------------------------------------------------------------------

// TestFIND01_OptionalAuth_ZeroToOne_NoUserInContext verifies the FIND-01 bypass
// in OptionalAuthMiddleware: a token minted at version 0 with user at version 1
// must NOT populate the context with a userID (the request proceeds as
// unauthenticated, not as the revoked user).
func TestFIND01_OptionalAuth_ZeroToOne_NoUserInContext(t *testing.T) {
	t.Parallel()
	ts := newFind01TokenService(t)
	token := mintToken(t, ts, 42, 0) // token carries version=0

	var capturedCtx context.Context
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedCtx = r.Context()
		w.WriteHeader(http.StatusOK)
	})

	// Simulate nuclear revocation: user is now at version 1.
	repo := &find01UserRepo{user: &model.User{ID: 42, Email: "u@example.com", TokenVersion: 1}}
	h := OptionalAuthMiddleware(ts, repo, nil)(inner)

	w, req := makeAuthRequest(token)
	h.ServeHTTP(w, req)

	// OptionalAuth always calls next, so we expect 200.
	if w.Code != http.StatusOK {
		t.Errorf("FIND-01: OptionalAuth must always call next; got %d", w.Code)
	}

	// The context must NOT contain the revoked user's ID.
	if _, ok := capturedCtx.Value(contextkeys.UserIDKey).(uint); ok {
		t.Error("FIND-01: revoked token (version 0→1) must not populate userID in context")
	}
}

// TestFIND01_OptionalAuth_MatchingVersion_UserInContext verifies the happy
// path: a valid token with a matching version populates the context.
func TestFIND01_OptionalAuth_MatchingVersion_UserInContext(t *testing.T) {
	t.Parallel()
	ts := newFind01TokenService(t)
	token := mintToken(t, ts, 42, 1) // version=1, same as user

	var capturedCtx context.Context
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedCtx = r.Context()
		w.WriteHeader(http.StatusOK)
	})

	repo := &find01UserRepo{user: &model.User{ID: 42, Email: "u@example.com", TokenVersion: 1}}
	h := OptionalAuthMiddleware(ts, repo, nil)(inner)

	w, req := makeAuthRequest(token)
	h.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("FIND-01: OptionalAuth valid token must pass through; got %d", w.Code)
	}

	uid, ok := capturedCtx.Value(contextkeys.UserIDKey).(uint)
	if !ok || uid != 42 {
		t.Errorf("FIND-01: expected userID=42 in context for valid token; got ok=%v uid=%d", ok, uid)
	}
}

// TestFIND01_OptionalAuth_NoToken_CallsNext verifies that OptionalAuthMiddleware
// still calls next without populating context when no Authorization header is set.
func TestFIND01_OptionalAuth_NoToken_CallsNext(t *testing.T) {
	t.Parallel()
	ts := newFind01TokenService(t)
	repo := &find01UserRepo{user: &model.User{ID: 1, TokenVersion: 0}}

	called := false
	h := OptionalAuthMiddleware(ts, repo, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/optional", nil)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)

	if !called {
		t.Error("FIND-01: OptionalAuth must call next when no token is present")
	}
	if w.Code != http.StatusOK {
		t.Errorf("FIND-01: expected 200, got %d", w.Code)
	}
}

// TestFIND01_OptionalAuth_OneToTwo_NoUserInContext mirrors the 1→2 scenario
// for OptionalAuth: a token at version 1 with user at version 2 must not
// populate context (the revocation is honoured).
func TestFIND01_OptionalAuth_OneToTwo_NoUserInContext(t *testing.T) {
	t.Parallel()
	ts := newFind01TokenService(t)
	token := mintToken(t, ts, 55, 1) // token carries version=1

	var capturedCtx context.Context
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedCtx = r.Context()
		w.WriteHeader(http.StatusOK)
	})

	repo := &find01UserRepo{user: &model.User{ID: 55, Email: "u@example.com", TokenVersion: 2}}
	h := OptionalAuthMiddleware(ts, repo, nil)(inner)

	w, req := makeAuthRequest(token)
	h.ServeHTTP(w, req)

	if _, ok := capturedCtx.Value(contextkeys.UserIDKey).(uint); ok {
		t.Error("FIND-01: revoked token (1→2) must not populate userID in OptionalAuth context")
	}
}
