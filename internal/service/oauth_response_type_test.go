// Package service — tests for H-01: implicit grant / hybrid flow must be
// blocked at the isValidResponseType gate.
//
// RFC 9700 / OAuth 2.1 formally deprecates the implicit grant.  Only
// "code" (Authorization Code flow) is permitted.
package service

import "testing"

// ---------------------------------------------------------------------------
// isValidResponseType — unit tests (white-box: same package)
// ---------------------------------------------------------------------------

func TestIsValidResponseType_Code_Accepted(t *testing.T) {
	if !isValidResponseType("code") {
		t.Error("expected response_type=code to be accepted")
	}
}

func TestIsValidResponseType_ImplicitGrant_Rejected(t *testing.T) {
	// H-01: "token" is the implicit grant — access token in URL fragment.
	if isValidResponseType("token") {
		t.Error("expected response_type=token (implicit grant) to be rejected")
	}
}

func TestIsValidResponseType_IDToken_Rejected(t *testing.T) {
	// Hybrid flow shorthand; not a valid OAuth 2.1 response type.
	if isValidResponseType("id_token") {
		t.Error("expected response_type=id_token to be rejected")
	}
}

func TestIsValidResponseType_HybridCodeToken_Rejected(t *testing.T) {
	// Hybrid flow: code + token in the same response.
	if isValidResponseType("code token") {
		t.Error("expected response_type='code token' (hybrid) to be rejected")
	}
}

func TestIsValidResponseType_HybridCodeIDToken_Rejected(t *testing.T) {
	// Hybrid flow used by some OIDC clients to get an id_token from /authorize.
	if isValidResponseType("code id_token") {
		t.Error("expected response_type='code id_token' (hybrid) to be rejected")
	}
}

func TestIsValidResponseType_HybridAll_Rejected(t *testing.T) {
	if isValidResponseType("code token id_token") {
		t.Error("expected response_type='code token id_token' to be rejected")
	}
}

func TestIsValidResponseType_Empty_Rejected(t *testing.T) {
	if isValidResponseType("") {
		t.Error("expected empty response_type to be rejected")
	}
}

func TestIsValidResponseType_CaseSensitive_Rejected(t *testing.T) {
	// Must not accept differently-cased variants — the spec is lowercase only.
	cases := []string{"Code", "CODE", "Token", "TOKEN"}
	for _, rt := range cases {
		if isValidResponseType(rt) {
			t.Errorf("expected response_type=%q (wrong case) to be rejected", rt)
		}
	}
}

func TestIsValidResponseType_Injection_Rejected(t *testing.T) {
	// Adversarial / unexpected values must be rejected.
	injections := []string{
		"code ",     // trailing space
		" code",     // leading space
		"code\n",    // newline
		"code%20",   // URL-encoded space (not yet decoded)
		"code\x00",  // null byte
	}
	for _, rt := range injections {
		if isValidResponseType(rt) {
			t.Errorf("expected response_type=%q to be rejected", rt)
		}
	}
}

// ---------------------------------------------------------------------------
// GetOpenIDConfiguration — discovery document must advertise only "code"
// ---------------------------------------------------------------------------

func TestGetOpenIDConfiguration_ResponseTypesSupported_OnlyCode(t *testing.T) {
	svc := &oauthService{issuer: "https://example.com"}
	doc := svc.GetOpenIDConfiguration("https://example.com")

	if len(doc.ResponseTypesSupported) != 1 {
		t.Fatalf("expected exactly 1 response_type in discovery, got %d: %v",
			len(doc.ResponseTypesSupported), doc.ResponseTypesSupported)
	}
	if doc.ResponseTypesSupported[0] != "code" {
		t.Errorf("expected ResponseTypesSupported[0]=%q, got %q",
			"code", doc.ResponseTypesSupported[0])
	}
}

func TestGetOpenIDConfiguration_NoImplicitInResponseTypes(t *testing.T) {
	svc := &oauthService{issuer: "https://example.com"}
	doc := svc.GetOpenIDConfiguration("https://example.com")

	forbidden := []string{"token", "id_token", "code token", "code id_token", "code token id_token"}
	for _, rt := range forbidden {
		for _, advertised := range doc.ResponseTypesSupported {
			if advertised == rt {
				t.Errorf("discovery document must not advertise response_type=%q", rt)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// GetOpenIDConfiguration — H-02: discovery doc must only advertise S256
// ---------------------------------------------------------------------------

func TestGetOpenIDConfiguration_CodeChallengeMethodsSupported_OnlyS256(t *testing.T) {
	svc := &oauthService{issuer: "https://example.com"}
	doc := svc.GetOpenIDConfiguration("https://example.com")

	if len(doc.CodeChallengeMethodsSupported) != 1 {
		t.Fatalf("expected exactly 1 code_challenge_method in discovery, got %d: %v",
			len(doc.CodeChallengeMethodsSupported), doc.CodeChallengeMethodsSupported)
	}
	if doc.CodeChallengeMethodsSupported[0] != "S256" {
		t.Errorf("expected CodeChallengeMethodsSupported[0]=%q, got %q",
			"S256", doc.CodeChallengeMethodsSupported[0])
	}
}

func TestGetOpenIDConfiguration_PlainNotAdvertised(t *testing.T) {
	// H-02: advertising "plain" invites clients to use it.  It must not appear.
	svc := &oauthService{issuer: "https://example.com"}
	doc := svc.GetOpenIDConfiguration("https://example.com")

	for _, m := range doc.CodeChallengeMethodsSupported {
		if m == "plain" {
			t.Error("discovery document must not advertise code_challenge_method=plain")
		}
	}
}

func TestGetOpenIDConfiguration_GrantTypesDoNotIncludeImplicit(t *testing.T) {
	// Implicit grant has no "grant_type" in the token request, but some
	// servers incorrectly list "implicit" in grant_types_supported.
	svc := &oauthService{issuer: "https://example.com"}
	doc := svc.GetOpenIDConfiguration("https://example.com")

	for _, gt := range doc.GrantTypesSupported {
		if gt == "implicit" {
			t.Error("discovery document must not advertise grant_type=implicit")
		}
	}
}
