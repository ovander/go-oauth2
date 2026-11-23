package http

import (
	"context"
	nethttp "net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/ovander/go-oauth2/internal/handler"
	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/repository"
	"github.com/ovander/go-oauth2/internal/service"
	"github.com/ovander/go-oauth2/internal/shared/auth"
)

// GET /oauth/authorize is a browser endpoint: the sign-in that leads to the
// consent page is the hosted login form. An Authorization header on the
// request is not a browser session and is ignored, through the real OAuth
// router and its middleware.

type authorizeRouteApps struct{ service.AppService }

func (authorizeRouteApps) GetByClientID(_ context.Context, clientID string) (*model.App, error) {
	return &model.App{ID: 2, ClientID: clientID, Name: "Other app", Active: true,
		RedirectURIs: []string{"https://other.example.com/cb"}}, nil
}

type authorizeRouteUsers struct{ repository.UserRepository }

func (authorizeRouteUsers) FindByID(_ context.Context, id uint) (*model.User, error) {
	return &model.User{ID: id, Email: "user@example.com", IsVerified: true}, nil
}

type authorizeRouteUsedTokens struct{ repository.UsedTokenRepository }

func (authorizeRouteUsedTokens) IsUsed(context.Context, string) (bool, error) { return false, nil }

func authorizeBearerRouter(t *testing.T) (nethttp.Handler, string) {
	t.Helper()
	km, err := auth.NewKeyManager(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ts := auth.NewTokenService(km, auth.TokenConfig{
		Issuer: "https://auth.example.com", AccessTokenTTL: time.Hour, RefreshTokenTTL: time.Hour,
		EmailTokenTTL: time.Hour, ResetTokenTTL: time.Hour, InviteTokenTTL: time.Hour,
	})
	// A valid access token of user 42, issued to another client.
	set, err := ts.GenerateTokenSet(&model.User{ID: 42, Email: "user@example.com", IsVerified: true},
		&model.App{ID: 1, ClientID: "client-a"}, "user", "openid", nil, "", time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	oauth := handler.NewOAuthHandler(nil, nil, authorizeRouteApps{}, service.NewTemplateService(), ts,
		"https://auth.example.com", []byte("router-test-secret-at-least-32-bytes!!"))
	login := newFind02Limiter()
	t.Cleanup(login.Stop)
	cfg := RouterConfig{LoginRateLimiter: login, SignupRateLimiter: login, TokenRateLimiter: login}
	r := newOAuthRouter(nil, oauth, nil, nil, nil, nil, nil, ts, authorizeRouteUsers{}, authorizeRouteUsedTokens{}, cfg)
	return r, set.AccessToken
}

func authorizeWithBearer(r nethttp.Handler, bearer, prompt string) *httptest.ResponseRecorder {
	q := url.Values{
		"client_id": {"client-b"}, "redirect_uri": {"https://other.example.com/cb"},
		"response_type": {"code"}, "state": {"st-1"}, "scope": {"openid"},
		"code_challenge": {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"}, "code_challenge_method": {"S256"},
	}
	if prompt != "" {
		q.Set("prompt", prompt)
	}
	req := httptest.NewRequest(nethttp.MethodGet, "/oauth/authorize?"+q.Encode(), nil)
	req.RemoteAddr = "203.0.113.7:5555"
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rr := httptest.NewRecorder()
	r.ServeHTTP(rr, req)
	return rr
}

func TestAuthorize_BearerTokenIsNotABrowserSession(t *testing.T) {
	r, bearer := authorizeBearerRouter(t)
	for name, token := range map[string]string{"no header": "", "valid access token": bearer} {
		rr := authorizeWithBearer(r, token, "")
		body := rr.Body.String()
		if rr.Code != nethttp.StatusOK || !strings.Contains(body, `name="password"`) {
			t.Errorf("%s: status %d, want the login page", name, rr.Code)
		}
		if strings.Contains(body, "consent_token") {
			t.Errorf("%s: the response carries a consent token; the login page must come first", name)
		}
	}
}

func TestAuthorize_PromptNoneWithBearerIsLoginRequired(t *testing.T) {
	r, bearer := authorizeBearerRouter(t)
	rr := authorizeWithBearer(r, bearer, "none")
	loc, err := url.Parse(rr.Header().Get("Location"))
	if err != nil || rr.Code != nethttp.StatusFound {
		t.Fatalf("status %d Location %q, want a redirect to the client", rr.Code, rr.Header().Get("Location"))
	}
	if got := loc.Query().Get("error"); got != "login_required" {
		t.Errorf("error=%q, want login_required: a bearer token is not a signed-in browser", got)
	}
}
