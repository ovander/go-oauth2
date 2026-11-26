package http

import (
	"context"
	nethttp "net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ovander/go-oauth2/internal/handler"
	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/service"
	"github.com/ovander/go-oauth2/internal/shared/auth"
	"github.com/ovander/go-oauth2/internal/shared/auth/dpop"
)

// Through the real OAuth router: under DPOP_MODE=enforce, a DPoP-bound token
// presented to /oauth/logout without a proof is not its user's, so the logout
// does not revoke that user's tokens (the v1.14.2 audit's G-4 follow-up).

type logoutRouteOAuth struct {
	service.OAuthService
	revokedFor []uint
}

func (o *logoutRouteOAuth) Revoke(_ context.Context, _ string, userID uint, _ string) error {
	o.revokedFor = append(o.revokedFor, userID)
	return nil
}

func TestLogout_BoundTokenWithoutProof(t *testing.T) {
	km, err := auth.NewKeyManager(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ts := auth.NewTokenService(km, auth.TokenConfig{
		Issuer: "https://auth.example.com", AccessTokenTTL: time.Hour, RefreshTokenTTL: time.Hour,
		EmailTokenTTL: time.Hour, ResetTokenTTL: time.Hour, InviteTokenTTL: time.Hour,
	})
	bound, err := ts.GenerateTokenSetWithDPoP(&model.User{ID: 42, Email: "user@example.com", IsVerified: true},
		&model.App{ID: 1, ClientID: "client-a"}, "user", "openid", nil, "", time.Now().Unix(), "some-key-thumbprint")
	if err != nil {
		t.Fatal(err)
	}
	cache := dpop.NewMemoryReplayCache(time.Minute)
	t.Cleanup(cache.Stop)
	for mode, wantRevoke := range map[string]bool{"enforce": false, "observe": true, "off": true} {
		oauth := &logoutRouteOAuth{}
		h := handler.NewOAuthHandler(oauth, nil, authorizeRouteApps{}, service.NewTemplateService(), ts,
			"https://auth.example.com", []byte("router-test-secret-at-least-32-bytes!!"))
		login := newFind02Limiter()
		t.Cleanup(login.Stop)
		r := newOAuthRouter(nil, h, nil, nil, nil, nil, nil, ts, authorizeRouteUsers{}, authorizeRouteUsedTokens{},
			RouterConfig{LoginRateLimiter: login, SignupRateLimiter: login, TokenRateLimiter: login,
				DPoPMode: mode, DPoPReplayCache: cache, DPoPHTUBase: "https://auth.example.com"})
		req := httptest.NewRequest(nethttp.MethodPost, "/oauth/logout", nil)
		req.Header.Set("Authorization", "Bearer "+bound.AccessToken)
		req.RemoteAddr = "203.0.113.7:5555"
		r.ServeHTTP(httptest.NewRecorder(), req)
		if revoked := len(oauth.revokedFor) == 1 && oauth.revokedFor[0] == 42; revoked != wantRevoke {
			t.Errorf("%s: revoked user 42's tokens = %v (%v), want %v", mode, revoked, oauth.revokedFor, wantRevoke)
		}
	}
}
