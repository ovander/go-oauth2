package web

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// P3-6: the standalone POST /auth/login handler is gone; GET /auth/login
// forwards OAuth-parameterised requests to the hosted /oauth/authorize page and
// otherwise renders an informational page with no password form.

func p36Handler(t *testing.T) *WebHandler {
	t.Helper()
	h, err := NewWebHandler(nil, nil, nil, nil, nil, "https://auth.example")
	if err != nil {
		t.Fatalf("NewWebHandler: %v", err)
	}
	return h
}

func TestP36_LoginPage_ForwardsOAuthRequestsToAuthorize(t *testing.T) {
	h := p36Handler(t)
	rr := httptest.NewRecorder()
	h.LoginPage(rr, httptest.NewRequest(http.MethodGet,
		"/auth/login?client_id=app-1&redirect_uri=https%3A%2F%2Fapp.example%2Fcb&response_type=code&state=xyz&code_challenge=abc&code_challenge_method=S256", nil))
	if rr.Code != http.StatusFound {
		t.Fatalf("status %d, want 302", rr.Code)
	}
	loc := rr.Header().Get("Location")
	if !strings.HasPrefix(loc, "https://auth.example/oauth/authorize?") {
		t.Fatalf("Location = %q, want /oauth/authorize on the issuer", loc)
	}
	for _, p := range []string{"client_id=app-1", "redirect_uri=https%3A%2F%2Fapp.example%2Fcb", "state=xyz", "code_challenge=abc", "code_challenge_method=S256"} {
		if !strings.Contains(loc, p) {
			t.Errorf("Location %q lost parameter %q", loc, p)
		}
	}
}

func TestP36_LoginPage_WithoutOAuthParamsHasNoPasswordForm(t *testing.T) {
	h := p36Handler(t)
	rr := httptest.NewRecorder()
	h.LoginPage(rr, httptest.NewRequest(http.MethodGet, "/auth/login", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("status %d, want 200", rr.Code)
	}
	body := rr.Body.String()
	if strings.Contains(body, `action="/auth/login"`) || strings.Contains(body, `type="password"`) {
		t.Fatalf("informational login page still renders the dead password form")
	}
	if !strings.Contains(body, "forgot-password") {
		t.Fatalf("expected the forgot-password link to remain")
	}
}
