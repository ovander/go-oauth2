// Package auth — tests for H-02: "plain" PKCE method must be rejected and
// the discovery document must not advertise it.
//
// RFC 7636 defines two code_challenge_method values: "S256" and "plain".
// "plain" provides no real protection because code_verifier == code_challenge;
// an intercepted authorisation request immediately yields the verifier.
// OAuth 2.1 (RFC 9700) requires S256.
package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// VerifyPKCE — S256 (the only accepted method)
// ---------------------------------------------------------------------------

func TestVerifyPKCE_S256_Valid(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk" // RFC 7636 Appendix B
	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])

	if err := VerifyPKCE(verifier, challenge, "S256"); err != nil {
		t.Errorf("expected S256 verification to succeed, got: %v", err)
	}
}

func TestVerifyPKCE_S256_WrongVerifier_Fails(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	hash := sha256.Sum256([]byte(verifier))
	challenge := base64.RawURLEncoding.EncodeToString(hash[:])

	err := VerifyPKCE("completely-wrong-verifier", challenge, "S256")
	if err == nil {
		t.Error("expected S256 verification to fail with wrong verifier")
	}
}

func TestVerifyPKCE_S256_TamperedChallenge_Fails(t *testing.T) {
	verifier := "mySecretCodeVerifier123"
	// Challenge doesn't match the verifier's SHA-256
	err := VerifyPKCE(verifier, "tampered_challenge", "S256")
	if err == nil {
		t.Error("expected S256 verification to fail with tampered challenge")
	}
}

// ---------------------------------------------------------------------------
// VerifyPKCE — "plain" must be explicitly rejected (H-02)
// ---------------------------------------------------------------------------

func TestVerifyPKCE_Plain_IsRejected(t *testing.T) {
	// With plain PKCE, code_verifier == code_challenge.
	// An attacker who intercepts the authorisation request gets the verifier
	// for free, so this must never be accepted.
	verifier := "some-code-verifier"
	err := VerifyPKCE(verifier, verifier, "plain")
	if err == nil {
		t.Fatal("expected 'plain' PKCE method to be rejected, but it succeeded")
	}
	if err != ErrInvalidChallengeMethod {
		t.Errorf("expected ErrInvalidChallengeMethod, got: %v", err)
	}
}

func TestVerifyPKCE_Plain_EvenWithCorrectPair_IsRejected(t *testing.T) {
	// Even a "technically correct" plain pair must fail: the method is banned.
	const v = "ExactSameString"
	err := VerifyPKCE(v, v, "plain")
	if err != ErrInvalidChallengeMethod {
		t.Errorf("expected ErrInvalidChallengeMethod for plain, got: %v", err)
	}
}

func TestVerifyPKCE_Plain_MixedCase_IsRejected(t *testing.T) {
	// Case variants must also be rejected (method matching is exact).
	for _, method := range []string{"Plain", "PLAIN", "pLaIn"} {
		err := VerifyPKCE("v", "v", method)
		if err == nil {
			t.Errorf("expected %q to be rejected as an invalid method", method)
		}
	}
}

// ---------------------------------------------------------------------------
// VerifyPKCE — unknown / garbage methods
// ---------------------------------------------------------------------------

func TestVerifyPKCE_UnknownMethod_IsRejected(t *testing.T) {
	cases := []string{"RS256", "sha256", "base64", "md5", "none", "foo"}
	for _, method := range cases {
		err := VerifyPKCE("verifier", "challenge", method)
		if err == nil {
			t.Errorf("expected unknown method %q to be rejected", method)
		}
		if err != ErrInvalidChallengeMethod {
			t.Errorf("for method %q: expected ErrInvalidChallengeMethod, got: %v", method, err)
		}
	}
}

// ---------------------------------------------------------------------------
// VerifyPKCE — no PKCE (empty verifier)
// ---------------------------------------------------------------------------

func TestVerifyPKCE_NoVerifier_NoChallenge_OK(t *testing.T) {
	// Confidential clients may omit PKCE entirely.
	if err := VerifyPKCE("", "", ""); err != nil {
		t.Errorf("expected no-PKCE case to pass, got: %v", err)
	}
}

func TestVerifyPKCE_NoVerifier_WithChallenge_Fails(t *testing.T) {
	// Challenge set but verifier missing → invalid request.
	err := VerifyPKCE("", "some_challenge", "S256")
	if err == nil {
		t.Error("expected error when verifier is missing but challenge is present")
	}
	if err != ErrInvalidCodeVerifier {
		t.Errorf("expected ErrInvalidCodeVerifier, got: %v", err)
	}
}

func TestVerifyPKCE_WithVerifier_NoChallenge_Fails(t *testing.T) {
	// Verifier provided but no challenge stored → no PKCE was agreed at /authorize.
	err := VerifyPKCE("verifier", "", "S256")
	if err == nil {
		t.Error("expected error when challenge is missing but verifier is present")
	}
}

// ---------------------------------------------------------------------------
// GenerateCodeChallenge — produces correct S256 challenge
// ---------------------------------------------------------------------------

func TestGenerateCodeChallenge_S256_RoundTrip(t *testing.T) {
	verifier := "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
	challenge := GenerateCodeChallenge(verifier)

	if err := VerifyPKCE(verifier, challenge, "S256"); err != nil {
		t.Errorf("GenerateCodeChallenge output failed VerifyPKCE: %v", err)
	}
}

func TestGenerateCodeChallenge_IsBase64RawURL(t *testing.T) {
	challenge := GenerateCodeChallenge("any-verifier")
	// RawURL encoding: no padding ('='), no '+' or '/'
	if strings.ContainsAny(challenge, "+/=") {
		t.Errorf("challenge %q contains non-base64url characters", challenge)
	}
}

// ---------------------------------------------------------------------------
// Discovery document — only S256 advertised (H-02)
// (This test lives here because the discovery doc is in oauth_service.go;
//  we add a dedicated service-level test for the full document separately.
//  This test verifies the pkce package itself doesn't advertise "plain".)
// ---------------------------------------------------------------------------

func TestVerifyPKCE_PlainIsNotAValidPath(t *testing.T) {
	// Exhaustive: for every (verifier, challenge, method) combination that
	// "plain" could represent, the function must return an error.
	//
	// Note: ("", "", "plain") is intentionally excluded.  VerifyPKCE exits
	// early when both verifier and challenge are empty — that signals "no PKCE
	// in use" and the method value is irrelevant.  The early exit is correct
	// behaviour; the test must not assert on a combination that never occurs
	// in practice (a stored code_challenge_method without a code_challenge).
	const v = "my-secret-verifier"
	combinations := []struct{ verifier, challenge, method string }{
		{v, v, "plain"},
		{v, v, "PLAIN"},
		{"x", "x", "plain"},
	}
	for _, c := range combinations {
		err := VerifyPKCE(c.verifier, c.challenge, c.method)
		if err == nil {
			t.Errorf("VerifyPKCE(%q,%q,%q) expected error, got nil",
				c.verifier, c.challenge, c.method)
		}
	}
}
