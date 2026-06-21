// Package service — tests for public client token exchange (NEW-04).
//
// A public client (IsPublic=true, ClientSecretHash="") must:
//   - be accepted at the token endpoint with no client_secret
//   - be rejected when a code_challenge was stored but no code_verifier supplied
//   - be rejected when an invalid code_verifier is supplied
//   - succeed end-to-end when a valid code_verifier is supplied
//
// These tests complement the CRIT-02 suite (which tests secret enforcement for
// confidential clients) and the MED-02 suite (which tests RequirePKCE at the
// authorization endpoint).  This file focuses on the combination: IsPublic=true
// with PKCE at the token exchange step.
package service

import (
	"context"
	"errors"
	"testing"

	"github.com/ovandermoten/go-oauth2/internal/dto"
	"github.com/ovandermoten/go-oauth2/internal/model"
	"github.com/ovandermoten/go-oauth2/internal/shared/auth"
)

// ---------------------------------------------------------------------------
// Helper — seed a code that includes a PKCE challenge
// ---------------------------------------------------------------------------

// seedCodeWithPKCE generates an authorization code that carries a
// code_challenge (S256).  The returned string is the code_verifier — the
// caller must supply it on token exchange.
func seedCodeWithPKCE(t *testing.T, svc *oauthService, clientID, redirectURI string, userID uint) (code, verifier string) {
	t.Helper()

	verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" // 43-char URL-safe string
	challenge := auth.GenerateCodeChallenge(verifier)        // S256

	var err error
	code, err = svc.codeStore.GenerateCode(
		context.Background(),
		userID, 1, clientID,
		redirectURI, "openid",
		"", challenge, "S256",
		"user", nil,
	)
	if err != nil {
		t.Fatalf("seedCodeWithPKCE GenerateCode: %v", err)
	}
	return code, verifier
}

// publicClientApp returns a model.App configured as a public client.
func publicClientApp() *model.App {
	return &model.App{
		ID:               99,
		ClientID:         "public-spa",
		ClientSecretHash: "", // no secret — public client
		IsPublic:         true,
		RequirePKCE:      true,
		Active:           true,
		RedirectURIs:     model.StringArray{"https://spa.example.com/cb"},
	}
}

// ---------------------------------------------------------------------------
// NEW-04 tests: public client token exchange
// ---------------------------------------------------------------------------

// TestNEW04_PublicClient_NoSecret_NoVerifier_CodeHadChallenge_Rejected
// A public client that included a PKCE challenge at authorization must supply
// the matching verifier at token exchange.  Omitting it must be rejected.
func TestNEW04_PublicClient_NoSecret_NoVerifier_CodeHadChallenge_Rejected(t *testing.T) {
	app := publicClientApp()
	svc := newCrit02Service(t, app)

	code, _ := seedCodeWithPKCE(t, svc, "public-spa", "https://spa.example.com/cb", 10)

	req := dto.TokenRequest{
		GrantType:    "authorization_code",
		Code:         code,
		RedirectURI:  "https://spa.example.com/cb",
		CodeVerifier: "", // omitted — must be rejected
	}

	_, err := svc.handleAuthorizationCodeGrant(context.Background(), req, "public-spa", "")
	if err == nil {
		t.Fatal("expected error when code_verifier is missing for PKCE code, got nil")
	}
	if !errors.Is(err, ErrPKCERequired) && !errors.Is(err, ErrPKCEVerificationFail) {
		t.Errorf("error = %v; want ErrPKCERequired or ErrPKCEVerificationFail", err)
	}
	// Must NOT be a credential error — the client's lack of secret is correct.
	if errors.Is(err, ErrInvalidCredentials) {
		t.Error("public client rejected with ErrInvalidCredentials — credential check must be skipped")
	}
}

// TestNEW04_PublicClient_NoSecret_InvalidVerifier_Rejected
// A wrong code_verifier must produce a PKCE failure, not a credential error.
func TestNEW04_PublicClient_NoSecret_InvalidVerifier_Rejected(t *testing.T) {
	app := publicClientApp()
	svc := newCrit02Service(t, app)

	code, _ := seedCodeWithPKCE(t, svc, "public-spa", "https://spa.example.com/cb", 11)

	req := dto.TokenRequest{
		GrantType:    "authorization_code",
		Code:         code,
		RedirectURI:  "https://spa.example.com/cb",
		CodeVerifier: "wrong-verifier-that-does-not-match-the-challenge",
	}

	_, err := svc.handleAuthorizationCodeGrant(context.Background(), req, "public-spa", "")
	if err == nil {
		t.Fatal("expected error for invalid code_verifier, got nil")
	}
	if !errors.Is(err, ErrPKCEVerificationFail) {
		t.Errorf("error = %v; want ErrPKCEVerificationFail", err)
	}
	if errors.Is(err, ErrInvalidCredentials) {
		t.Error("public client rejected with ErrInvalidCredentials — credential check must be skipped")
	}
}

// TestNEW04_PublicClient_NoSecret_ValidVerifier_PassesCredentialAndPKCECheck
// A public client with no secret and a correct verifier must pass both
// the credential check and the PKCE check.  The call may still fail later
// (no user repo wired), but must NOT fail with ErrInvalidCredentials or any
// PKCE error.
func TestNEW04_PublicClient_NoSecret_ValidVerifier_PassesCredentialAndPKCECheck(t *testing.T) {
	app := publicClientApp()
	svc := newCrit02Service(t, app)

	code, verifier := seedCodeWithPKCE(t, svc, "public-spa", "https://spa.example.com/cb", 12)

	req := dto.TokenRequest{
		GrantType:    "authorization_code",
		Code:         code,
		RedirectURI:  "https://spa.example.com/cb",
		CodeVerifier: verifier,
	}

	_, err := svc.handleAuthorizationCodeGrant(context.Background(), req, "public-spa", "")
	// The stubUserRepo returns "user not found", so we expect ErrUserNotFound —
	// but credential and PKCE checks must have passed.
	if errors.Is(err, ErrInvalidCredentials) {
		t.Error("public client rejected with ErrInvalidCredentials — credential check must be skipped")
	}
	if errors.Is(err, ErrPKCERequired) || errors.Is(err, ErrPKCEVerificationFail) {
		t.Errorf("PKCE check failed with correct verifier: %v", err)
	}
}

// TestNEW04_PublicClient_IsPublicTrue_SecretIgnored
// Even if a public client accidentally sends a secret, it must not be used
// to gate access — the credential block is skipped entirely for public clients.
func TestNEW04_PublicClient_IsPublicTrue_SecretIgnored(t *testing.T) {
	app := publicClientApp() // IsPublic=true, ClientSecretHash=""
	svc := newCrit02Service(t, app)

	code, verifier := seedCodeWithPKCE(t, svc, "public-spa", "https://spa.example.com/cb", 13)

	req := dto.TokenRequest{
		GrantType:    "authorization_code",
		Code:         code,
		RedirectURI:  "https://spa.example.com/cb",
		CodeVerifier: verifier,
	}

	// Presenting a random secret alongside a valid verifier must not break things.
	_, err := svc.handleAuthorizationCodeGrant(context.Background(), req, "public-spa", "some-random-secret")
	if errors.Is(err, ErrInvalidCredentials) {
		t.Error("supplying an extra secret to a public client caused ErrInvalidCredentials — should be ignored")
	}
	if errors.Is(err, ErrPKCERequired) || errors.Is(err, ErrPKCEVerificationFail) {
		t.Errorf("PKCE failed with correct verifier: %v", err)
	}
}

// TestNEW04_ConfidentialClient_Regression_StillRequiresSecret
// Sanity regression: adding public client support must not weaken confidential
// client authentication.  A confidential client (ClientSecretHash set,
// IsPublic=false) without a secret must still be rejected.
func TestNEW04_ConfidentialClient_Regression_StillRequiresSecret(t *testing.T) {
	secretHash, _ := auth.HashClientSecret("my-secret")
	app := &model.App{
		ID:               50,
		ClientID:         "backend-app",
		ClientSecretHash: secretHash,
		IsPublic:         false,
		Active:           true,
		RedirectURIs:     model.StringArray{"https://backend.example.com/cb"},
	}
	svc := newCrit02Service(t, app)
	code := seedCode(t, svc, "backend-app", "https://backend.example.com/cb", 99)

	req := dto.TokenRequest{
		GrantType:   "authorization_code",
		Code:        code,
		RedirectURI: "https://backend.example.com/cb",
	}

	_, err := svc.handleAuthorizationCodeGrant(context.Background(), req, "backend-app", "")
	if err == nil {
		t.Fatal("confidential client accepted token exchange with no secret — regression")
	}
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("error = %v; want ErrInvalidCredentials for confidential client with no secret", err)
	}
}
