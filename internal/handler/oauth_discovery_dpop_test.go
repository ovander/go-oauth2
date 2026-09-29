package handler

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ovander/go-oauth2/internal/dto"
)

// cfgOAuthService returns a fixed discovery document so the handler's DPoP
// advertisement can be asserted independently of the service.
type cfgOAuthService struct {
	mockOAuthService
}

func (*cfgOAuthService) GetOpenIDConfiguration(issuer string) *dto.OpenIDConfiguration {
	return &dto.OpenIDConfiguration{Issuer: issuer}
}

func decodeDiscovery(t *testing.T, h *OAuthHandler) dto.OpenIDConfiguration {
	t.Helper()
	rr := httptest.NewRecorder()
	h.OpenIDConfiguration(rr, httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	var got dto.OpenIDConfiguration
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatalf("decode: %v", err)
	}
	return got
}

func TestOpenIDConfiguration_AdvertisesDPoPWhenSet(t *testing.T) {
	h := &OAuthHandler{oauthService: &cfgOAuthService{}, issuer: "https://auth.example.com"}
	h.SetDPoPSigningAlgs([]string{"ES256"})

	got := decodeDiscovery(t, h)
	if len(got.DPoPSigningAlgValuesSupported) != 1 || got.DPoPSigningAlgValuesSupported[0] != "ES256" {
		t.Fatalf("expected dpop_signing_alg_values_supported=[ES256], got %v", got.DPoPSigningAlgValuesSupported)
	}
}

func TestOpenIDConfiguration_OmitsDPoPWhenDisabled(t *testing.T) {
	h := &OAuthHandler{oauthService: &cfgOAuthService{}, issuer: "https://auth.example.com"}
	// No SetDPoPSigningAlgs call (DPoP disabled).

	rr := httptest.NewRecorder()
	h.OpenIDConfiguration(rr, httptest.NewRequest(http.MethodGet, "/.well-known/openid-configuration", nil))
	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	// The omitempty field must be absent from the raw JSON entirely.
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(rr.Body.Bytes(), &raw); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if _, present := raw["dpop_signing_alg_values_supported"]; present {
		t.Fatal("dpop_signing_alg_values_supported must be omitted when DPoP is disabled")
	}
}
