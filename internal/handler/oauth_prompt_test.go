package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/ovander/go-oauth2/internal/contextkeys"
	"github.com/ovander/go-oauth2/internal/model"
)

// OIDC prompt on GET /oauth/authorize (v1.8.0).

func promptHandler() *OAuthHandler {
	apps := &critAppService{getByClientID: func(_ context.Context, _ string) (*model.App, error) {
		return &model.App{ID: 1, ClientID: "app-1", Name: "App", RedirectURIs: []string{"https://app.example.com/cb"}, Active: true}, nil
	}}
	return newCritTestHandler(apps, &critOAuthService{}, &critAuthService{})
}

func promptGet(h *OAuthHandler, prompt string, signedIn bool) *httptest.ResponseRecorder {
	q := url.Values{
		"client_id": {"app-1"}, "redirect_uri": {"https://app.example.com/cb"},
		"response_type": {"code"}, "state": {"st-1"}, "scope": {"openid"},
		"code_challenge": {"abc"}, "code_challenge_method": {"S256"},
	}
	if prompt != "" {
		q.Set("prompt", prompt)
	}
	r := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
	if signedIn {
		r = r.WithContext(context.WithValue(r.Context(), contextkeys.UserIDKey, uint(42)))
	}
	w := httptest.NewRecorder()
	h.Authorize(w, r)
	return w
}

func isLoginPage(w *httptest.ResponseRecorder) bool {
	return w.Code == http.StatusOK && strings.Contains(w.Body.String(), `name="password"`)
}

func TestAuthorize_PromptLoginForcesTheLoginPage(t *testing.T) {
	h := promptHandler()
	if isLoginPage(promptGet(h, "", true)) {
		t.Fatal("without prompt, a signed-in user should go to consent, not the login page")
	}
	for _, p := range []string{"login", "login consent", "select_account login"} {
		if w := promptGet(h, p, true); !isLoginPage(w) {
			t.Errorf("prompt=%q, signed in: status %d, want the login page", p, w.Code)
		}
	}
	if w := promptGet(h, "login", false); !isLoginPage(w) {
		t.Errorf("prompt=login, signed out: status %d, want the login page", w.Code)
	}
}

func TestAuthorize_PromptNone(t *testing.T) {
	h := promptHandler()
	for name, tc := range map[string]struct {
		prompt   string
		signedIn bool
		wantErr  string
	}{
		"signed out":       {"none", false, "login_required"},
		"signed in":        {"none", true, "consent_required"},
		"none with others": {"none login", true, "invalid_request"},
	} {
		w := promptGet(h, tc.prompt, tc.signedIn)
		loc, err := url.Parse(w.Header().Get("Location"))
		if err != nil || w.Code != http.StatusFound || !strings.HasPrefix(loc.String(), "https://app.example.com/cb") {
			t.Errorf("%s: status %d Location %q, want a redirect to the client", name, w.Code, w.Header().Get("Location"))
			continue
		}
		if got := loc.Query().Get("error"); got != tc.wantErr || loc.Query().Get("state") != "st-1" {
			t.Errorf("%s: error=%q state=%q, want %s / st-1", name, got, loc.Query().Get("state"), tc.wantErr)
		}
	}
}

func TestParsePrompt(t *testing.T) {
	for raw, want := range map[string][2]bool{"": {}, "login": {false, true}, "none": {true, false}, "consent": {}, " login  consent ": {false, true}} {
		none, login, err := parsePrompt(raw)
		if err != nil || none != want[0] || login != want[1] {
			t.Errorf("parsePrompt(%q) = %v, %v, %v", raw, none, login, err)
		}
	}
	if _, _, err := parsePrompt("none consent"); err == nil {
		t.Error("none with another value accepted")
	}
}
