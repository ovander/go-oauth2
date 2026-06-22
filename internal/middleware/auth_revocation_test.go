// Package middleware — tests for EPIC-14 per-token revocation propagation.
//
// A token individually revoked via /oauth/revoke is blacklisted by its JTI in
// used_tokens. Previously only Introspect honored that list, so a revoked
// access token still passed the auth middleware on the direct-API hot path.
// These tests verify the middleware now rejects (AuthMiddleware) or ignores
// (OptionalAuthMiddleware) a JTI-revoked token, and that a nil repo or an
// unrevoked token is unaffected.
package middleware

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/ovandermoten/go-oauth2/internal/contextkeys"
	"github.com/ovandermoten/go-oauth2/internal/model"
)

// revokeStubRepo reports a fixed set of JTIs as revoked (used).
type revokeStubRepo struct {
	revoked map[string]bool
	err     error
}

func (r *revokeStubRepo) MarkAsUsed(_ context.Context, _, _ string, _ uint, _ time.Time) error {
	return nil
}
func (r *revokeStubRepo) IsUsed(_ context.Context, jti string) (bool, error) {
	if r.err != nil {
		return false, r.err
	}
	return r.revoked[jti], nil
}
func (r *revokeStubRepo) DeleteExpired(_ context.Context) (int64, error) { return 0, nil }

// AuthMiddleware rejects a token whose JTI has been individually revoked.
func TestRevocation_AuthMiddleware_RejectsRevokedJTI(t *testing.T) {
	t.Parallel()
	ts := newFind01TokenService(t)
	token := mintToken(t, ts, 42, 1)
	claims, err := ts.VerifyAccessToken(token)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}

	repo := &find01UserRepo{user: &model.User{ID: 42, Email: "u@example.com", TokenVersion: 1}}
	used := &revokeStubRepo{revoked: map[string]bool{claims.ID: true}}
	inner := &nopOKHandler{}
	h := AuthMiddleware(ts, repo, used)(inner)

	w, req := makeAuthRequest(token)
	h.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("revoked JTI must return 401; got %d", w.Code)
	}
	if inner.called {
		t.Error("next handler must NOT run for a revoked token")
	}
	if body := parseErrorBody(t, w.Body.Bytes()); body["error"] != "token has been revoked" {
		t.Errorf("error = %q, want 'token has been revoked'", body["error"])
	}
}

// A non-revoked token still passes (and a nil repo disables the check).
func TestRevocation_AuthMiddleware_AllowsUnrevokedAndNilRepo(t *testing.T) {
	t.Parallel()
	ts := newFind01TokenService(t)
	token := mintToken(t, ts, 7, 1)
	user := &model.User{ID: 7, Email: "u@example.com", TokenVersion: 1}

	// Repo present but JTI not revoked -> allow.
	h := AuthMiddleware(ts, &find01UserRepo{user: user}, &revokeStubRepo{revoked: map[string]bool{}})(&nopOKHandler{})
	w, req := makeAuthRequest(token)
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Errorf("unrevoked token must pass; got %d", w.Code)
	}

	// Nil repo -> check disabled, allow.
	inner := &nopOKHandler{}
	h = AuthMiddleware(ts, &find01UserRepo{user: user}, nil)(inner)
	w, req = makeAuthRequest(token)
	h.ServeHTTP(w, req)
	if w.Code != http.StatusOK || !inner.called {
		t.Errorf("nil repo must disable the revocation check; got %d called=%v", w.Code, inner.called)
	}
}

// OptionalAuthMiddleware treats a JTI-revoked token as unauthenticated (no user
// in context) rather than erroring.
func TestRevocation_OptionalAuthMiddleware_RevokedIsAnonymous(t *testing.T) {
	t.Parallel()
	ts := newFind01TokenService(t)
	token := mintToken(t, ts, 9, 1)
	claims, _ := ts.VerifyAccessToken(token)

	repo := &find01UserRepo{user: &model.User{ID: 9, Email: "u@example.com", TokenVersion: 1}}
	used := &revokeStubRepo{revoked: map[string]bool{claims.ID: true}}

	var sawUser bool
	inner := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		_, sawUser = r.Context().Value(contextkeys.CurrentUserKey).(*model.User)
	})
	h := OptionalAuthMiddleware(ts, repo, used)(inner)

	w, req := makeAuthRequest(token)
	h.ServeHTTP(w, req)
	if sawUser {
		t.Error("a revoked token must not populate the user context on the optional path")
	}
}
