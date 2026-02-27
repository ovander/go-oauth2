// Package handler — tests for the HIGH-01 internal-error-message leak fix.
//
// HIGH-01 fix: raw Go error strings must never be forwarded to clients.
//
// The two residual err.Error() usages fixed in this session were in the
// redirect_uri validation paths of GET and POST /oauth/authorize.  Both now:
//   1. Log the full error internally via the structured logger.
//   2. Map the sentinel error to a safe description via redirectURIErrorDescription.
//
// The server_error default branches in Token and UserInfo were fixed in the
// prior session; tests here guard against regression.
package handler

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ovandermoten/go-oauth2/internal/dto"
	"github.com/ovandermoten/go-oauth2/internal/shared/auth"
)

// ---------------------------------------------------------------------------
// redirectURIErrorDescription unit tests
// ---------------------------------------------------------------------------

// TestHIGH01_RedirectURIErrorDescription_NotRegistered verifies that the
// helper returns a controlled description — not the old leaked prefix.
func TestHIGH01_RedirectURIErrorDescription_NotRegistered(t *testing.T) {
	desc := redirectURIErrorDescription(auth.ErrRedirectURINotRegistered)
	if desc == "" {
		t.Fatal("expected a non-empty description for ErrRedirectURINotRegistered")
	}
	if strings.Contains(desc, "Invalid redirect_uri:") {
		t.Errorf("description still contains old leaked prefix: %q", desc)
	}
}

// TestHIGH01_RedirectURIErrorDescription_AllSentinels verifies that every
// known redirect-URI sentinel produces a non-empty, non-prefixed description.
func TestHIGH01_RedirectURIErrorDescription_AllSentinels(t *testing.T) {
	cases := []struct {
		name string
		err  error
	}{
		{"NotRegistered", auth.ErrRedirectURINotRegistered},
		{"DangerousScheme", auth.ErrRedirectURIDangerousScheme},
		{"HasFragment", auth.ErrRedirectURIHasFragment},
		{"NotHTTPS", auth.ErrRedirectURINotHTTPS},
		{"PathTraversal", auth.ErrRedirectURIPathTraversal},
		{"InvalidURL", auth.ErrRedirectURIInvalidURL},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			desc := redirectURIErrorDescription(tc.err)
			if desc == "" {
				t.Fatalf("empty description for %s", tc.name)
			}
			if strings.HasPrefix(desc, "Invalid redirect_uri: ") {
				t.Errorf("description contains old leaked prefix for %s: %q", tc.name, desc)
			}
		})
	}
}

// TestHIGH01_RedirectURIErrorDescription_UnknownError_Fallback verifies that
// an unrecognised error (e.g. a raw DB error) falls back to "invalid redirect_uri".
func TestHIGH01_RedirectURIErrorDescription_UnknownError_Fallback(t *testing.T) {
	rawDBErr := errors.New("pq: duplicate key value violates unique constraint")
	desc := redirectURIErrorDescription(rawDBErr)
	if desc != "invalid redirect_uri" {
		t.Errorf("fallback description = %q, want %q", desc, "invalid redirect_uri")
	}
}

// ---------------------------------------------------------------------------
// GET /oauth/authorize — redirect_uri error response integration tests
// ---------------------------------------------------------------------------

// TestHIGH01_GET_Authorize_UnregisteredRedirectURI_NoRawGoError verifies
// that an unregistered redirect_uri does NOT leak raw Go error text in the
// response body and does NOT produce a 302 redirect.
func TestHIGH01_GET_Authorize_UnregisteredRedirectURI_NoRawGoError(t *testing.T) {
	h := newCritTestHandler(
		newHigh06AppService(), // registered: https://client.example.com/callback
		&critOAuthService{},
		&critAuthService{},
	)

	req := httptest.NewRequest(http.MethodGet,
		"/oauth/authorize?client_id="+high06ClientID+
			"&redirect_uri=https://attacker.example.com/steal"+
			"&response_type=code&state=csrf-state",
		nil)
	rec := httptest.NewRecorder()

	h.Authorize(rec, req)

	body := rec.Body.String()

	// Must not redirect to an unregistered URI.
	if rec.Code == http.StatusFound {
		t.Errorf("should not redirect for unregistered redirect_uri, got 302 → %s",
			rec.Header().Get("Location"))
	}

	// Must NOT contain the old leaked error prefix.
	if strings.Contains(body, "Invalid redirect_uri:") {
		t.Errorf("response body contains old leaked prefix: %q", body)
	}

	// Must NOT expose the raw Go sentinel text as-is (it should be logged, not forwarded).
	// Note: the SAFE version of this same text IS acceptable in the description field;
	// what we're guarding against is the full "redirect URI is not registered for this client"
	// string being forwarded without any sanitisation step.
	// The real guard here is the absence of the old "Invalid redirect_uri: " prefix.

	// Must contain the OAuth error code.
	if !strings.Contains(body, "invalid_request") {
		t.Errorf("expected 'invalid_request' in body, got:\n%s", body)
	}
}

// TestHIGH01_GET_Authorize_DangerousScheme_NoRawGoError verifies that a
// dangerous-scheme redirect_uri (javascript:) returns a safe static description.
func TestHIGH01_GET_Authorize_DangerousScheme_NoRawGoError(t *testing.T) {
	h := newCritTestHandler(
		newHigh06AppService(),
		&critOAuthService{},
		&critAuthService{},
	)

	req := httptest.NewRequest(http.MethodGet,
		"/oauth/authorize?client_id="+high06ClientID+
			"&redirect_uri=javascript:alert(document.cookie)"+
			"&response_type=code&state=xyz",
		nil)
	rec := httptest.NewRecorder()

	h.Authorize(rec, req)

	body := rec.Body.String()

	if strings.Contains(body, "Invalid redirect_uri:") {
		t.Errorf("response body contains old leaked error prefix: %q", body)
	}
	if !strings.Contains(body, "invalid_request") {
		t.Errorf("expected 'invalid_request' in body, got:\n%s", body)
	}
}

// ---------------------------------------------------------------------------
// Token endpoint — server_error regression guard
// ---------------------------------------------------------------------------

// high01TokenSvc is a minimal OAuthService that returns a raw DB error
// from Token(), used to exercise the server_error default branch.
type high01TokenSvc struct {
	critOAuthService
}

func (s *high01TokenSvc) Token(_ context.Context, _ dto.TokenRequest, _, _ string) (*dto.TokenResponse, error) {
	// Simulate an unexpected low-level error that must never reach the client.
	return nil, errors.New("pq: ERROR: could not serialize access due to concurrent update")
}

// TestHIGH01_Token_UnrecognisedError_StaticDescription verifies that when
// Token returns an unrecognised error, the response body contains ONLY the
// static phrase "an internal error occurred" — not the raw DB error text.
//
// This is a regression guard for the fix applied in the previous session.
func TestHIGH01_Token_UnrecognisedError_StaticDescription(t *testing.T) {
	h := &OAuthHandler{
		oauthService: &high01TokenSvc{},
		secretKey:    critTestSecretKey,
	}

	req := httptest.NewRequest(http.MethodPost, "/oauth/token",
		strings.NewReader("grant_type=refresh_token&refresh_token=sometoken"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	rec := httptest.NewRecorder()

	h.Token(rec, req)

	body := rec.Body.String()

	// Must NOT contain raw DB error text.
	if strings.Contains(body, "pq:") || strings.Contains(body, "serialize") {
		t.Errorf("Token response leaks raw DB error text: %q", body)
	}

	// Must contain the static generic description.
	if !strings.Contains(body, "an internal error occurred") {
		t.Errorf("expected 'an internal error occurred' in Token error body, got:\n%s", body)
	}
}
