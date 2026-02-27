// Package auth — tests for CRIT-03: CSRF double-submit cookie protection.
//
// CRIT-03 fix: GET /oauth/authorize now sets a SameSite=Strict HttpOnly
// _csrf cookie and embeds the same value as a hidden form field.  The POST
// handler rejects requests where the form field does not match the cookie.
package auth

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// GenerateCSRFToken
// ---------------------------------------------------------------------------

func TestGenerateCSRFToken_SetsCSRFCookie(t *testing.T) {
	t.Parallel()
	w := httptest.NewRecorder()
	token, err := GenerateCSRFToken(w, false)
	if err != nil {
		t.Fatalf("GenerateCSRFToken() error = %v", err)
	}
	if token == "" {
		t.Fatal("GenerateCSRFToken() returned empty token")
	}

	var csrfCookie *http.Cookie
	for _, c := range w.Result().Cookies() {
		if c.Name == CSRFCookieName {
			csrfCookie = c
			break
		}
	}
	if csrfCookie == nil {
		t.Fatalf("expected %q cookie to be set, but it was not", CSRFCookieName)
	}
	if csrfCookie.Value != token {
		t.Errorf("cookie value = %q, want %q", csrfCookie.Value, token)
	}
}

func TestGenerateCSRFToken_CookieIsHttpOnly(t *testing.T) {
	t.Parallel()
	w := httptest.NewRecorder()
	_, _ = GenerateCSRFToken(w, false)

	for _, c := range w.Result().Cookies() {
		if c.Name == CSRFCookieName {
			if !c.HttpOnly {
				t.Error("_csrf cookie must be HttpOnly to prevent XSS exfiltration")
			}
			return
		}
	}
	t.Fatalf("%q cookie not found", CSRFCookieName)
}

func TestGenerateCSRFToken_CookieIsSameSiteStrict(t *testing.T) {
	t.Parallel()
	w := httptest.NewRecorder()
	_, _ = GenerateCSRFToken(w, false)

	for _, c := range w.Result().Cookies() {
		if c.Name == CSRFCookieName {
			if c.SameSite != http.SameSiteStrictMode {
				t.Errorf("_csrf cookie SameSite = %v, want Strict", c.SameSite)
			}
			return
		}
	}
	t.Fatalf("%q cookie not found", CSRFCookieName)
}

func TestGenerateCSRFToken_SecureFlagSetWhenHTTPS(t *testing.T) {
	t.Parallel()
	w := httptest.NewRecorder()
	_, _ = GenerateCSRFToken(w, true /* secure */)

	for _, c := range w.Result().Cookies() {
		if c.Name == CSRFCookieName {
			if !c.Secure {
				t.Error("_csrf cookie must have Secure flag when httpsRequired=true")
			}
			return
		}
	}
	t.Fatalf("%q cookie not found", CSRFCookieName)
}

func TestGenerateCSRFToken_SecureFlagAbsentWhenHTTP(t *testing.T) {
	t.Parallel()
	w := httptest.NewRecorder()
	_, _ = GenerateCSRFToken(w, false /* not secure */)

	for _, c := range w.Result().Cookies() {
		if c.Name == CSRFCookieName {
			if c.Secure {
				t.Error("_csrf cookie must NOT have Secure flag when httpsRequired=false")
			}
			return
		}
	}
	t.Fatalf("%q cookie not found", CSRFCookieName)
}

func TestGenerateCSRFToken_TokenHasAdequateEntropy(t *testing.T) {
	t.Parallel()
	w := httptest.NewRecorder()
	token, _ := GenerateCSRFToken(w, false)
	// 32 bytes base64url-encoded = 43 chars (no padding)
	if len(token) < 40 {
		t.Errorf("CSRF token length = %d, want ≥40 chars (32 random bytes)", len(token))
	}
}

func TestGenerateCSRFToken_TwoCallsProduceDifferentTokens(t *testing.T) {
	t.Parallel()
	t1, _ := GenerateCSRFToken(httptest.NewRecorder(), false)
	t2, _ := GenerateCSRFToken(httptest.NewRecorder(), false)
	if t1 == t2 {
		t.Error("two successive GenerateCSRFToken calls produced the same token")
	}
}

// ---------------------------------------------------------------------------
// ValidateCSRFToken
// ---------------------------------------------------------------------------

func TestValidateCSRFToken_ValidMatch_ReturnsTrue(t *testing.T) {
	t.Parallel()
	// 1. Generate a token (sets the cookie on w).
	w := httptest.NewRecorder()
	token, _ := GenerateCSRFToken(w, false)

	// 2. Build an incoming request carrying that cookie.
	r := httptest.NewRequest(http.MethodPost, "/oauth/authorize",
		strings.NewReader("csrf_token="+token))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range w.Result().Cookies() {
		r.AddCookie(c)
	}

	if !ValidateCSRFToken(r, token) {
		t.Error("ValidateCSRFToken() = false, want true when cookie == form value")
	}
}

func TestValidateCSRFToken_MissingCookie_ReturnsFalse(t *testing.T) {
	t.Parallel()
	r := httptest.NewRequest(http.MethodPost, "/oauth/authorize", nil)
	// No cookie set — simulates a request from a cross-origin attacker who
	// cannot forge the SameSite cookie.
	if ValidateCSRFToken(r, "anytoken") {
		t.Error("ValidateCSRFToken() = true when cookie is absent — CSRF attack possible")
	}
}

func TestValidateCSRFToken_EmptyFormToken_ReturnsFalse(t *testing.T) {
	t.Parallel()
	w := httptest.NewRecorder()
	_, _ = GenerateCSRFToken(w, false)

	r := httptest.NewRequest(http.MethodPost, "/oauth/authorize", nil)
	for _, c := range w.Result().Cookies() {
		r.AddCookie(c)
	}

	if ValidateCSRFToken(r, "" /* empty form field */) {
		t.Error("ValidateCSRFToken() = true with empty form token")
	}
}

func TestValidateCSRFToken_MismatchedValues_ReturnsFalse(t *testing.T) {
	t.Parallel()
	w := httptest.NewRecorder()
	_, _ = GenerateCSRFToken(w, false)

	r := httptest.NewRequest(http.MethodPost, "/oauth/authorize", nil)
	for _, c := range w.Result().Cookies() {
		r.AddCookie(c)
	}

	if ValidateCSRFToken(r, "wrong-token-value") {
		t.Error("ValidateCSRFToken() = true when form token does not match cookie")
	}
}

func TestValidateCSRFToken_TamperedCookieValue_ReturnsFalse(t *testing.T) {
	t.Parallel()
	w := httptest.NewRecorder()
	token, _ := GenerateCSRFToken(w, false)

	r := httptest.NewRequest(http.MethodPost, "/oauth/authorize", nil)
	// Use a tampered cookie value.
	r.AddCookie(&http.Cookie{Name: CSRFCookieName, Value: "tampered-" + token})

	if ValidateCSRFToken(r, token) {
		t.Error("ValidateCSRFToken() = true when cookie value is tampered")
	}
}
