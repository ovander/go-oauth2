package http

import (
	"context"
	nethttp "net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ovander/go-oauth2/internal/handler"
	"github.com/ovander/go-oauth2/internal/middleware"
	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/service"
	"github.com/ovander/go-oauth2/internal/shared/auth"
)

// The MFA self-service posts check a password or a code: through the real
// OAuth router, they are rate-limited per user (the v1.14.2 audit's H-2
// follow-up), whatever address the requests come from.

type mfaRouteService struct{ service.MFAService }

func (mfaRouteService) Disable(context.Context, uint) error { return nil }

type mfaRouteReverifier struct{}

func (mfaRouteReverifier) ReverifyForMFAChange(context.Context, uint, *string, string) error {
	return service.ErrMFAInvalidCode
}

func TestMFAPosts_AreRateLimitedPerUser(t *testing.T) {
	km, err := auth.NewKeyManager(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ts := auth.NewTokenService(km, auth.TokenConfig{
		Issuer: "https://auth.example.com", AccessTokenTTL: time.Hour, RefreshTokenTTL: time.Hour,
		EmailTokenTTL: time.Hour, ResetTokenTTL: time.Hour, InviteTokenTTL: time.Hour,
	})
	token := func(id uint) string {
		set, err := ts.GenerateTokenSet(&model.User{ID: id, Email: "user@example.com", IsVerified: true},
			&model.App{ID: 1, ClientID: "client-a"}, "user", "openid", nil, "", time.Now().Unix())
		if err != nil {
			t.Fatal(err)
		}
		return set.AccessToken
	}
	login := middleware.NewRateLimiterWithConfig(middleware.RateLimiterConfig{
		Limit: 2, Window: time.Minute, MaxEntries: 100, CleanupInterval: time.Hour,
	})
	t.Cleanup(login.Stop)
	mfa := handler.NewMFAHandler(mfaRouteService{}, mfaRouteReverifier{})
	r := newOAuthRouter(nil, nil, nil, nil, mfa, nil, nil, ts, authorizeRouteUsers{}, authorizeRouteUsedTokens{},
		RouterConfig{LoginRateLimiter: login, SignupRateLimiter: login, TokenRateLimiter: login})

	post := func(bearer, addr string) int {
		req := httptest.NewRequest(nethttp.MethodPost, "/api/profile/mfa/disable",
			strings.NewReader(`{"password":"x","code":"000000"}`))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+bearer)
		req.RemoteAddr = addr
		rr := httptest.NewRecorder()
		r.ServeHTTP(rr, req)
		return rr.Code
	}
	alice, bob := token(42), token(43)
	for i, addr := range []string{"203.0.113.7:1", "198.51.100.9:2"} {
		if code := post(alice, addr); code != nethttp.StatusUnauthorized {
			t.Fatalf("attempt %d = %d, want 401 (a wrong code, within the budget)", i+1, code)
		}
	}
	// A third guess from yet another address is over the user's budget.
	if code := post(alice, "192.0.2.1:3"); code != nethttp.StatusTooManyRequests {
		t.Fatalf("third attempt = %d, want 429", code)
	}
	// Another user has a budget of their own.
	if code := post(bob, "203.0.113.7:4"); code != nethttp.StatusUnauthorized {
		t.Fatalf("another user = %d, want 401", code)
	}
}
