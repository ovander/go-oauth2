package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"github.com/ovander/go-oauth2/internal/contextkeys"
	"github.com/ovander/go-oauth2/internal/shared/auth"
)

// GET /oauth/authorize: an identity that comes from a bearer access token
// (claims in the context, as the bearer middlewares put them) is not a browser
// session. The handler answers as for a signed-out browser even if such a
// middleware is mounted on the route.
func authorizeAsBearer(h *OAuthHandler, prompt string) *httptest.ResponseRecorder {
	q := url.Values{
		"client_id": {"app-1"}, "redirect_uri": {"https://app.example.com/cb"},
		"response_type": {"code"}, "state": {"st-1"}, "scope": {"openid"},
		"code_challenge": {"abc"}, "code_challenge_method": {"S256"},
	}
	if prompt != "" {
		q.Set("prompt", prompt)
	}
	r := httptest.NewRequest(http.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
	ctx := context.WithValue(r.Context(), contextkeys.UserIDKey, uint(42))
	ctx = context.WithValue(ctx, contextkeys.JWTClaimsKey, &auth.AccessTokenClaims{AuthTime: 1, Amr: []string{"pwd", "mfa"}})
	w := httptest.NewRecorder()
	h.Authorize(w, r.WithContext(ctx))
	return w
}

func TestAuthorize_BearerIdentityGetsTheLoginPage(t *testing.T) {
	if w := authorizeAsBearer(promptHandler(), ""); !isLoginPage(w) {
		t.Fatalf("status %d, want the login page for a bearer-derived identity", w.Code)
	}
}

func TestAuthorize_BearerIdentityWithPromptNoneIsLoginRequired(t *testing.T) {
	w := authorizeAsBearer(promptHandler(), "none")
	loc, err := url.Parse(w.Header().Get("Location"))
	if err != nil || w.Code != http.StatusFound {
		t.Fatalf("status %d Location %q, want a redirect to the client", w.Code, w.Header().Get("Location"))
	}
	if got := loc.Query().Get("error"); got != "login_required" {
		t.Errorf("error=%q, want login_required", got)
	}
}
