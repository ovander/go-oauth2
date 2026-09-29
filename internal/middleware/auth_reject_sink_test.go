// Package middleware — tests for the AuthMiddleware token-abuse reject sink (#203).
//
// When a *present* bearer token is rejected at a protected endpoint, the
// optional onReject hook must fire with a classification (invalid / expired /
// revoked) so the caller can emit a token-abuse security event. A request with
// no Authorization header, and a valid token, must NOT fire the hook.
package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/repository"
	"github.com/ovander/go-oauth2/internal/shared/auth"
)

type capturedReject struct {
	reason AuthRejectReason
	detail string
}

// newExpiredTokenService mints tokens that are already past their exp (negative
// AccessTokenTTL), so VerifyAccessToken returns auth.ErrTokenExpired.
func newExpiredTokenService(t *testing.T) *auth.TokenService {
	t.Helper()
	km, err := auth.NewKeyManager(t.TempDir())
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}
	return auth.NewTokenService(km, auth.TokenConfig{
		Issuer:          "https://test.example.com",
		AccessTokenTTL:  -time.Hour, // already expired at issuance
		RefreshTokenTTL: 7 * 24 * time.Hour,
		EmailTokenTTL:   time.Hour,
		ResetTokenTTL:   time.Hour,
		InviteTokenTTL:  time.Hour,
	})
}

// runWithSink drives a single request through AuthMiddleware wired with a
// capturing reject sink, and returns the recorder plus any captured rejections.
func runWithSink(ts *auth.TokenService, repo *find01UserRepo, used repository.UsedTokenRepository, req *http.Request) (*httptest.ResponseRecorder, []capturedReject) {
	var got []capturedReject
	sink := func(_ *http.Request, reason AuthRejectReason, detail string) {
		got = append(got, capturedReject{reason, detail})
	}
	h := AuthMiddleware(ts, repo, used, sink)(&nopOKHandler{})
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	return w, got
}

func TestAuthRejectSink_InvalidForGarbageToken(t *testing.T) {
	t.Parallel()
	ts := newFind01TokenService(t)
	repo := &find01UserRepo{user: &model.User{ID: 1, TokenVersion: 0}}

	w, got := runWithSink(ts, repo, nil, mustBearer("garbage.not.a.jwt"))

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", w.Code)
	}
	if len(got) != 1 || got[0].reason != AuthRejectInvalid {
		t.Fatalf("want one invalid rejection, got %+v", got)
	}
}

func TestAuthRejectSink_InvalidForMalformedHeader(t *testing.T) {
	t.Parallel()
	ts := newFind01TokenService(t)
	repo := &find01UserRepo{user: &model.User{ID: 1, TokenVersion: 0}}

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Token abc") // not "Bearer …"
	w, got := runWithSink(ts, repo, nil, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", w.Code)
	}
	if len(got) != 1 || got[0].reason != AuthRejectInvalid || got[0].detail != "malformed_authorization_header" {
		t.Fatalf("want one invalid/malformed_authorization_header rejection, got %+v", got)
	}
}

func TestAuthRejectSink_ExpiredForExpiredToken(t *testing.T) {
	t.Parallel()
	ts := newExpiredTokenService(t)
	token := mintToken(t, ts, 7, 0) // signed by ts but already past exp
	repo := &find01UserRepo{user: &model.User{ID: 7, TokenVersion: 0}}

	w, got := runWithSink(ts, repo, nil, mustBearer(token))

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", w.Code)
	}
	if len(got) != 1 || got[0].reason != AuthRejectExpired {
		t.Fatalf("want one expired rejection, got %+v", got)
	}
}

func TestAuthRejectSink_RevokedForVersionBump(t *testing.T) {
	t.Parallel()
	ts := newFind01TokenService(t)
	token := mintToken(t, ts, 5, 1)                                    // token at version 1
	repo := &find01UserRepo{user: &model.User{ID: 5, TokenVersion: 2}} // user bumped to 2
	w, got := runWithSink(ts, repo, nil, mustBearer(token))

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", w.Code)
	}
	if len(got) != 1 || got[0].reason != AuthRejectRevoked || got[0].detail != "token_version_superseded" {
		t.Fatalf("want one revoked/token_version_superseded rejection, got %+v", got)
	}
}

func TestAuthRejectSink_RevokedForRevokedJTI(t *testing.T) {
	t.Parallel()
	ts := newFind01TokenService(t)
	token := mintToken(t, ts, 9, 1)
	claims, err := ts.VerifyAccessToken(token)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	repo := &find01UserRepo{user: &model.User{ID: 9, TokenVersion: 1}}
	used := &revokeStubRepo{revoked: map[string]bool{claims.ID: true}}

	w, got := runWithSink(ts, repo, used, mustBearer(token))

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", w.Code)
	}
	if len(got) != 1 || got[0].reason != AuthRejectRevoked || got[0].detail != "jti_revoked" {
		t.Fatalf("want one revoked/jti_revoked rejection, got %+v", got)
	}
}

func TestAuthRejectSink_NotCalledForMissingHeader(t *testing.T) {
	t.Parallel()
	ts := newFind01TokenService(t)
	repo := &find01UserRepo{user: &model.User{ID: 1, TokenVersion: 0}}

	req := httptest.NewRequest(http.MethodGet, "/protected", nil) // no Authorization
	w, got := runWithSink(ts, repo, nil, req)

	if w.Code != http.StatusUnauthorized {
		t.Fatalf("want 401, got %d", w.Code)
	}
	if len(got) != 0 {
		t.Fatalf("missing header must not fire the sink, got %+v", got)
	}
}

func TestAuthRejectSink_NotCalledForValidToken(t *testing.T) {
	t.Parallel()
	ts := newFind01TokenService(t)
	token := mintToken(t, ts, 3, 1)
	repo := &find01UserRepo{user: &model.User{ID: 3, TokenVersion: 1}}

	w, got := runWithSink(ts, repo, nil, mustBearer(token))

	if w.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", w.Code)
	}
	if len(got) != 0 {
		t.Fatalf("a valid token must not fire the sink, got %+v", got)
	}
}

func mustBearer(token string) *http.Request {
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	return req
}
