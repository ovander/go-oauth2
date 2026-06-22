package service

import "testing"

// Discovery advertises the claims added by recent capabilities and the acr
// values the OP can assert (RFC 8176 / OIDC Discovery / RFC-001).
func TestDiscovery_AdvertisesAuthContextClaims(t *testing.T) {
	svc := &oauthService{issuer: testIssuer}
	cfg := svc.GetOpenIDConfiguration(testIssuer)

	want := []string{"auth_time", "acr", "amr", "act", "cnf"}
	for _, c := range want {
		if !sliceHas(cfg.ClaimsSupported, c) {
			t.Errorf("claims_supported is missing %q: %v", c, cfg.ClaimsSupported)
		}
	}

	if !sliceHas(cfg.AcrValuesSupported, "pwd") || !sliceHas(cfg.AcrValuesSupported, "mfa") {
		t.Errorf("acr_values_supported = %v, want pwd + mfa", cfg.AcrValuesSupported)
	}
}

func sliceHas(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
