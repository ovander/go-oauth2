// Package auth — tests for M-03: KID-aware token verification after key rotation.
//
// The core invariant: a JWT signed with key K1 must remain verifiable after the
// server rotates to K2, because K1's public key is kept in the retired ring and
// included in the JWKS.  Tokens signed with K2 must also verify correctly.
//
// All tests call t.Parallel(): every test has its own isolated temp directory
// so there is no shared state between them.
//
// Key size: tests use 2048-bit RSA via newKeyManagerWithBits(..., 2048).
package auth

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"
)

// newTestTokenService builds a TokenService backed by a fresh temporary KeyManager
// using 2048-bit RSA keys for faster test execution.
func newTestTokenService(t *testing.T) (*TokenService, *KeyManager) {
	t.Helper()
	km, err := newKeyManagerWithBits(t.TempDir(), 2048)
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}
	ts := NewTokenService(km, TokenConfig{
		Issuer:         "https://test.example.com",
		EmailTokenTTL:  time.Hour,
		ResetTokenTTL:  time.Hour,
		InviteTokenTTL: time.Hour,
	})
	return ts, km
}

// ---------------------------------------------------------------------------
// Happy path: sign → verify without rotation
// ---------------------------------------------------------------------------

func TestTokenService_Sign_Verify_NoRotation(t *testing.T) {
	t.Parallel()
	ts, _ := newTestTokenService(t)

	tok, err := ts.GenerateEmailVerificationToken("user@example.com", 1, nil)
	if err != nil {
		t.Fatalf("GenerateEmailVerificationToken: %v", err)
	}

	claims, err := ts.VerifyEmailToken(tok)
	if err != nil {
		t.Fatalf("VerifyEmailToken: %v", err)
	}
	if claims.Email != "user@example.com" {
		t.Errorf("expected email=user@example.com, got %q", claims.Email)
	}
}

// ---------------------------------------------------------------------------
// M-03: tokens signed BEFORE rotation must still verify AFTER rotation
// ---------------------------------------------------------------------------

func TestTokenRotation_TokenSignedBeforeRotation_VerifiesAfterRotation(t *testing.T) {
	t.Parallel()
	ts, km := newTestTokenService(t)

	// Sign a token with the original key.
	tok, err := ts.GenerateEmailVerificationToken("alice@example.com", 42, nil)
	if err != nil {
		t.Fatalf("sign before rotation: %v", err)
	}

	// Rotate the key — old key goes to retired ring, new key is now active.
	if err := km.RotateKey(); err != nil {
		t.Fatalf("RotateKey: %v", err)
	}

	// The token signed with the old key must still be valid.
	claims, err := ts.VerifyEmailToken(tok)
	if err != nil {
		t.Fatalf("verify pre-rotation token after rotation: %v\n"+
			"(M-03: retired key ring must keep old tokens valid)", err)
	}
	if claims.Email != "alice@example.com" {
		t.Errorf("expected email=alice@example.com, got %q", claims.Email)
	}
}

func TestTokenRotation_TokenSignedAfterRotation_VerifiesCorrectly(t *testing.T) {
	t.Parallel()
	ts, km := newTestTokenService(t)

	// Rotate first.
	if err := km.RotateKey(); err != nil {
		t.Fatalf("RotateKey: %v", err)
	}

	// Sign a token with the NEW key.
	tok, err := ts.GenerateEmailVerificationToken("bob@example.com", 99, nil)
	if err != nil {
		t.Fatalf("sign after rotation: %v", err)
	}

	claims, err := ts.VerifyEmailToken(tok)
	if err != nil {
		t.Fatalf("verify post-rotation token: %v", err)
	}
	if claims.Email != "bob@example.com" {
		t.Errorf("expected email=bob@example.com, got %q", claims.Email)
	}
}

func TestTokenRotation_MultipleRotations_AllPreRotationTokensStillValid(t *testing.T) {
	t.Parallel()
	// Issue one token per key generation and verify them all survive subsequent rotations.
	ts, km := newTestTokenService(t)

	type issuedToken struct {
		token string
		email string
	}
	issued := make([]issuedToken, 0, 4)

	// Issue token before any rotation.
	tok0, err := ts.GenerateEmailVerificationToken("gen0@example.com", 0, nil)
	if err != nil {
		t.Fatalf("issue gen0: %v", err)
	}
	issued = append(issued, issuedToken{tok0, "gen0@example.com"})

	// Three rotations, issuing a new token each time.
	for i := 1; i <= 3; i++ {
		if err := km.RotateKey(); err != nil {
			t.Fatalf("rotation %d: %v", i, err)
		}
		email := fmt.Sprintf("gen%d@example.com", i)
		tok, err := ts.GenerateEmailVerificationToken(email, uint(i), nil)
		if err != nil {
			t.Fatalf("issue gen%d: %v", i, err)
		}
		issued = append(issued, issuedToken{tok, email})
	}

	// Verify all tokens — each must still work regardless of which generation
	// key it was signed with.
	for i, it := range issued {
		claims, err := ts.VerifyEmailToken(it.token)
		if err != nil {
			t.Errorf("gen%d token failed after %d rotations: %v", i, 3, err)
			continue
		}
		if claims.Email != it.email {
			t.Errorf("gen%d: email mismatch: want %q, got %q", i, it.email, claims.Email)
		}
	}
}

func TestTokenRotation_PasswordResetToken_VerifiesAfterRotation(t *testing.T) {
	t.Parallel()
	ts, km := newTestTokenService(t)

	tok, err := ts.GeneratePasswordResetToken("reset@example.com", 7, nil)
	if err != nil {
		t.Fatalf("GeneratePasswordResetToken: %v", err)
	}

	if err := km.RotateKey(); err != nil {
		t.Fatalf("RotateKey: %v", err)
	}

	claims, err := ts.VerifyEmailToken(tok)
	if err != nil {
		t.Fatalf("verify reset token after rotation: %v", err)
	}
	if claims.Type != "password_reset" {
		t.Errorf("expected type=password_reset, got %q", claims.Type)
	}
}

func TestTokenRotation_InviteToken_VerifiesAfterRotation(t *testing.T) {
	t.Parallel()
	ts, km := newTestTokenService(t)

	tok, err := ts.GenerateInviteToken("invite@example.com", 5, "admin", 1)
	if err != nil {
		t.Fatalf("GenerateInviteToken: %v", err)
	}

	if err := km.RotateKey(); err != nil {
		t.Fatalf("RotateKey: %v", err)
	}

	claims, err := ts.VerifyInviteToken(tok)
	if err != nil {
		t.Fatalf("verify invite token after rotation: %v", err)
	}
	if claims.Email != "invite@example.com" {
		t.Errorf("expected email=invite@example.com, got %q", claims.Email)
	}
}

// ---------------------------------------------------------------------------
// M-03: KID is embedded in every signed token header
// ---------------------------------------------------------------------------

func TestSignedToken_KIDEmbeddedInHeader(t *testing.T) {
	t.Parallel()
	// The JWT header is base64url({"alg":"RS256","kid":"<uuid>",...}).
	// Decode the header and confirm "kid" is present and matches GetKeyID().
	ts, km := newTestTokenService(t)
	kid := km.GetKeyID()

	tok, err := ts.GenerateEmailVerificationToken("test@example.com", 1, nil)
	if err != nil {
		t.Fatalf("GenerateEmailVerificationToken: %v", err)
	}

	// The JWT header is the first dot-delimited segment, base64url-encoded.
	// Decode it manually and look for the kid value.
	parts := strings.SplitN(tok, ".", 3)
	if len(parts) != 3 {
		t.Fatalf("token is not a 3-part JWT: %q", tok)
	}
	// The UUID appears as a JSON string value inside the header.
	// A substring check of the decoded header is sufficient.
	headerJSON, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode JWT header: %v", err)
	}
	if !strings.Contains(string(headerJSON), kid) {
		t.Errorf("JWT header %q does not contain KID %q", string(headerJSON), kid)
	}
}

// ---------------------------------------------------------------------------
// M-03: Rotation survives process restart (retired keys reloaded from disk)
// ---------------------------------------------------------------------------

func TestTokenRotation_AfterRestart_PreRotationTokenStillValid(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()

	// First "process": generate a key manager, sign a token, rotate.
	km1, err := newKeyManagerWithBits(dir, 2048)
	if err != nil {
		t.Fatalf("NewKeyManager (process 1): %v", err)
	}
	ts1 := NewTokenService(km1, TokenConfig{
		Issuer:        "https://test.example.com",
		EmailTokenTTL: time.Hour,
	})

	tok, err := ts1.GenerateEmailVerificationToken("restart@example.com", 5, nil)
	if err != nil {
		t.Fatalf("sign pre-rotation: %v", err)
	}

	if err := km1.RotateKey(); err != nil {
		t.Fatalf("RotateKey: %v", err)
	}

	// Second "process": reload the key manager from the same directory.
	km2, err := newKeyManagerWithBits(dir, 2048)
	if err != nil {
		t.Fatalf("NewKeyManager (process 2): %v", err)
	}
	ts2 := NewTokenService(km2, TokenConfig{
		Issuer:        "https://test.example.com",
		EmailTokenTTL: time.Hour,
	})

	// The token signed in the first process must verify in the second process.
	claims, err := ts2.VerifyEmailToken(tok)
	if err != nil {
		t.Fatalf("verify pre-rotation token after restart: %v\n"+
			"(M-03: retired keys must be reloaded from disk on startup)", err)
	}
	if claims.Email != "restart@example.com" {
		t.Errorf("expected email=restart@example.com, got %q", claims.Email)
	}
}
