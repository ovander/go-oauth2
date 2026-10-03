package service

import "testing"

func TestDiscovery_AdvertisesPromptValues(t *testing.T) {
	cfg := (&oauthService{issuer: testIssuer}).GetOpenIDConfiguration(testIssuer)
	if !sliceHas(cfg.PromptValuesSupported, "login") || !sliceHas(cfg.PromptValuesSupported, "none") {
		t.Errorf("prompt_values_supported = %v, want login and none", cfg.PromptValuesSupported)
	}
}
