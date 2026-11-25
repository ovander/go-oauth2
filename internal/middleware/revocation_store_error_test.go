package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ovander/go-oauth2/internal/contextkeys"
	"github.com/ovander/go-oauth2/internal/model"
)

// #366: a token whose revocation status cannot be read is refused (fail
// closed), with 503 and no invalid_token challenge, so a client retries
// instead of discarding a token that may well be valid.

var errStoreDown = errors.New("used_tokens unavailable")

func TestRevocationStoreError_AuthMiddlewareRefuses(t *testing.T) {
	t.Parallel()
	ts := newFind01TokenService(t)
	token := mintToken(t, ts, 42, 1)
	repo := &find01UserRepo{user: &model.User{ID: 42, Email: "u@example.com", TokenVersion: 1}}
	var fired []AuthRejectReason
	inner := &nopOKHandler{}
	h := AuthMiddleware(ts, repo, &revokeStubRepo{err: errStoreDown}, func(_ *http.Request, reason AuthRejectReason, _ string) {
		fired = append(fired, reason)
	})(inner)

	w, req := makeAuthRequest(token)
	h.ServeHTTP(w, req)

	if w.Code != http.StatusServiceUnavailable || inner.called {
		t.Fatalf("store error: status %d (next called %v), want 503 and refused", w.Code, inner.called)
	}
	if got := w.Header().Get("WWW-Authenticate"); got != "" {
		t.Errorf("a 503 must not challenge the token: WWW-Authenticate %q", got)
	}
	if w.Header().Get("Retry-After") == "" {
		t.Error("a 503 should carry Retry-After")
	}
	if len(fired) != 0 {
		t.Errorf("an outage is not a token-abuse signal, got %v", fired)
	}
}

func TestRevocationStoreError_OptionalAuthIsAnonymous(t *testing.T) {
	t.Parallel()
	ts := newFind01TokenService(t)
	token := mintToken(t, ts, 9, 1)
	repo := &find01UserRepo{user: &model.User{ID: 9, Email: "u@example.com", TokenVersion: 1}}
	var ran, sawUser bool
	inner := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		ran = true
		_, sawUser = r.Context().Value(contextkeys.CurrentUserKey).(*model.User)
	})
	w, req := makeAuthRequest(token)
	OptionalAuthMiddleware(ts, repo, &revokeStubRepo{err: errStoreDown})(inner).ServeHTTP(w, req)
	if !ran || w.Code != http.StatusOK {
		t.Fatalf("the optional route must still be served: ran %v, status %d", ran, w.Code)
	}
	if sawUser {
		t.Error("a token whose revocation cannot be read must not identify the user")
	}
}

func TestRevocationStoreError_ServiceAccountRefuses(t *testing.T) {
	b := newTestBundle(t)
	app := &model.App{ID: 1, ClientID: "client-1", Active: true}
	repo := &stubAppRepo{findByID: func(_ context.Context, _ uint) (*model.App, error) { return app, nil }}
	token := makeServiceToken(t, b, app)

	called := false
	rr := httptest.NewRecorder()
	ServiceAccountMiddleware(repo, b.ts, &revokeStubRepo{err: errStoreDown})(okHandler(&called)).ServeHTTP(rr, saRequest("1", token))
	if rr.Code != http.StatusServiceUnavailable || called {
		t.Fatalf("store error: status %d (next called %v), want 503 and refused", rr.Code, called)
	}
	if got := rr.Header().Get("WWW-Authenticate"); got != "" {
		t.Errorf("a 503 must not challenge the token: WWW-Authenticate %q", got)
	}
	if rr.Header().Get("Retry-After") == "" {
		t.Error("a 503 should carry Retry-After")
	}
}
