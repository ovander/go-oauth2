package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ovandermoten/go-oauth2/internal/dto"
)

// jwksOAuthService embeds the panic-by-default mock and returns an empty JWKS so
// the JWKS handler's caching headers can be asserted in isolation.
type jwksOAuthService struct {
	mockOAuthService
}

func (*jwksOAuthService) GetJWKS() dto.JWKS { return dto.JWKS{} }

func TestJWKS_CacheControlEnabled(t *testing.T) {
	h := &OAuthHandler{oauthService: &jwksOAuthService{}}
	h.SetJWKSCacheMaxAge(300)

	rr := httptest.NewRecorder()
	h.JWKS(rr, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if got := rr.Header().Get("Cache-Control"); got != "public, max-age=300" {
		t.Fatalf("Cache-Control = %q, want \"public, max-age=300\"", got)
	}
}

func TestJWKS_CacheControlDisabledWhenZero(t *testing.T) {
	h := &OAuthHandler{oauthService: &jwksOAuthService{}}
	h.SetJWKSCacheMaxAge(0)

	rr := httptest.NewRecorder()
	h.JWKS(rr, httptest.NewRequest(http.MethodGet, "/.well-known/jwks.json", nil))

	if got := rr.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want \"no-store\"", got)
	}
}
