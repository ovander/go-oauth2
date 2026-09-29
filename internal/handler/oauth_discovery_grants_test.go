package handler

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ovander/go-oauth2/internal/shared/auth/tokenexchange"
)

func TestOpenIDConfiguration_AdvertisesExtraGrantTypes(t *testing.T) {
	h := &OAuthHandler{oauthService: &cfgOAuthService{}, issuer: "https://auth.example.com"}
	h.SetExtraGrantTypes([]string{tokenexchange.GrantType})

	got := decodeDiscovery(t, h)
	found := false
	for _, g := range got.GrantTypesSupported {
		if g == tokenexchange.GrantType {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected token-exchange grant advertised, got %v", got.GrantTypesSupported)
	}
}

func TestOpenIDConfiguration_OmitsExtraGrantTypesWhenUnset(t *testing.T) {
	h := &OAuthHandler{oauthService: &cfgOAuthService{}, issuer: "https://auth.example.com"}
	// No SetExtraGrantTypes call.

	rr := httptest.NewRecorder()
	h.OpenIDConfiguration(rr, httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil))
	got := decodeDiscovery(t, h)
	for _, g := range got.GrantTypesSupported {
		if g == tokenexchange.GrantType {
			t.Fatal("token-exchange grant must not be advertised when unset")
		}
	}
}
