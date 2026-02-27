// Package service — tests for the HIGH-08 discovery document fix.
//
// HIGH-08 fix: "none" has been removed from token_endpoint_auth_methods_supported
// in the OpenID Connect discovery document.  Advertising "none" signals that
// unauthenticated token requests are acceptable, misleading clients and relying
// parties.  Public clients using PKCE simply omit credentials without needing
// "none" to be advertised.
package service

import (
	"testing"
)

// GetOpenIDConfiguration only reads s.issuer; no other fields are needed.
// Follow the same minimal-service pattern used in oauth_response_type_test.go.
const testIssuer = "https://auth.example.com"

// ---------------------------------------------------------------------------
// HIGH-08 tests
// ---------------------------------------------------------------------------

// TestHIGH08_DiscoveryDocument_NoneAbsent verifies that "none" is NOT present
// in token_endpoint_auth_methods_supported.
func TestHIGH08_DiscoveryDocument_NoneAbsent(t *testing.T) {
	svc := &oauthService{issuer: testIssuer}
	config := svc.GetOpenIDConfiguration(testIssuer)

	for _, method := range config.TokenEndpointAuthMethodsSupported {
		if method == "none" {
			t.Error("'none' must not appear in token_endpoint_auth_methods_supported (HIGH-08)")
		}
	}
}

// TestHIGH08_DiscoveryDocument_RequiredMethodsPresent verifies that the two
// standard client authentication methods are still advertised.
func TestHIGH08_DiscoveryDocument_RequiredMethodsPresent(t *testing.T) {
	svc := &oauthService{issuer: testIssuer}
	config := svc.GetOpenIDConfiguration(testIssuer)

	required := map[string]bool{
		"client_secret_basic": false,
		"client_secret_post":  false,
	}
	for _, method := range config.TokenEndpointAuthMethodsSupported {
		if _, ok := required[method]; ok {
			required[method] = true
		}
	}
	for method, found := range required {
		if !found {
			t.Errorf("required auth method %q is missing from token_endpoint_auth_methods_supported", method)
		}
	}
}

// TestHIGH08_DiscoveryDocument_IssuerMatches verifies that the issuer in the
// discovery document matches the one passed to GetOpenIDConfiguration.
func TestHIGH08_DiscoveryDocument_IssuerMatches(t *testing.T) {
	svc := &oauthService{issuer: testIssuer}
	config := svc.GetOpenIDConfiguration(testIssuer)

	if config.Issuer != testIssuer {
		t.Errorf("Issuer = %q, want %q", config.Issuer, testIssuer)
	}
}

// TestHIGH08_DiscoveryDocument_NoImplicitFlow verifies that the implicit flow
// ("token") is not advertised in response_types_supported.
func TestHIGH08_DiscoveryDocument_NoImplicitFlow(t *testing.T) {
	svc := &oauthService{issuer: testIssuer}
	config := svc.GetOpenIDConfiguration(testIssuer)

	for _, rt := range config.ResponseTypesSupported {
		if rt == "token" {
			t.Error("implicit flow ('token') must not be in response_types_supported")
		}
	}

	// "code" must be present.
	codeFound := false
	for _, rt := range config.ResponseTypesSupported {
		if rt == "code" {
			codeFound = true
		}
	}
	if !codeFound {
		t.Error("authorization code flow ('code') must be in response_types_supported")
	}
}
