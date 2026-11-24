package middleware

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"

	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/shared/auth"
)

// A service-account token revoked through /oauth/revoke (its jti on the
// revoked list) is refused with 401, as a user token is; one that is not
// revoked still passes.
func TestServiceAccountMiddleware_RevokedTokenIsRefused(t *testing.T) {
	b := newTestBundle(t)
	app := &model.App{ID: 1, ClientID: "client-1", Active: true}
	repo := &stubAppRepo{findByID: func(_ context.Context, _ uint) (*model.App, error) { return app, nil }}

	revoked := makeServiceToken(t, b, app)
	live := makeServiceToken(t, b, app)
	claims, err := b.ts.VerifyAccessToken(revoked)
	if err != nil {
		t.Fatal(err)
	}
	used := &revokeStubRepo{revoked: map[string]bool{claims.ID: true}}
	mw := ServiceAccountMiddleware(repo, b.ts, used)

	for name, tc := range map[string]struct {
		token string
		want  int
	}{"revoked": {revoked, http.StatusUnauthorized}, "live": {live, http.StatusOK}} {
		called := false
		rr := httptest.NewRecorder()
		mw(okHandler(&called)).ServeHTTP(rr, saRequest("1", tc.token))
		if rr.Code != tc.want || called != (tc.want == http.StatusOK) {
			t.Errorf("%s token: status %d (next called %v), want %d", name, rr.Code, called, tc.want)
		}
	}
}

// A service-account token without a jti could never be revoked: refused.
func TestServiceAccountMiddleware_TokenWithoutJTIIsRefused(t *testing.T) {
	b := newTestBundle(t)
	app := &model.App{ID: 1, ClientID: "client-1", Active: true}
	repo := &stubAppRepo{findByID: func(_ context.Context, _ uint) (*model.App, error) { return app, nil }}
	claims := auth.AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://auth.example.com",
			Subject:   "app:1",
			Audience:  jwt.ClaimStrings{"client-1"},
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Minute)),
		},
		Scope: "api",
		Type:  "access",
	}
	raw := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	raw.Header["kid"] = b.km.GetKeyID()
	token, err := raw.SignedString(b.km.GetPrivateKey())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.ts.VerifyAccessToken(token); err != nil {
		t.Fatalf("the hand-made token must verify, so only the jti rule refuses it: %v", err)
	}

	called := false
	rr := httptest.NewRecorder()
	ServiceAccountMiddleware(repo, b.ts, &revokeStubRepo{})(okHandler(&called)).ServeHTTP(rr, saRequest("1", token))
	if rr.Code != http.StatusUnauthorized || called {
		t.Fatalf("token without jti: status %d (next called %v), want 401", rr.Code, called)
	}
}
