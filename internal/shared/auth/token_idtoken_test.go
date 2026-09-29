// Package auth — tests for M-06: VerifyIDToken must verify the signature of
// id_token_hint; forged tokens must be rejected outright.
//
// VerifyIDToken is the new method added as part of the M-06 fix.  It is used
// by EndSession to determine whether the id_token_hint supplied by the client
// can be trusted for client identification.
package auth

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ovander/go-oauth2/internal/model"
)

// newTestTokenServiceFull creates a TokenService with realistic non-zero TTLs
// so that generated tokens are not immediately expired.
// newTestTokenService (in token_rotation_test.go) only sets email/reset/invite TTLs;
// this helper also sets AccessTokenTTL and RefreshTokenTTL for ID token tests.
func newTestTokenServiceFull(t *testing.T) (*TokenService, *KeyManager) {
	t.Helper()
	km, err := newKeyManagerWithBits(t.TempDir(), 2048)
	if err != nil {
		t.Fatalf("newKeyManagerWithBits: %v", err)
	}
	ts := NewTokenService(km, TokenConfig{
		Issuer:          "https://test.example.com",
		AccessTokenTTL:  time.Hour,
		RefreshTokenTTL: 7 * 24 * time.Hour,
		EmailTokenTTL:   time.Hour,
		ResetTokenTTL:   time.Hour,
		InviteTokenTTL:  time.Hour,
	})
	return ts, km
}

// ---------------------------------------------------------------------------
// VerifyIDToken — happy path
// ---------------------------------------------------------------------------

func TestVerifyIDToken_ValidToken_ReturnsClaims(t *testing.T) {
	t.Parallel()
	ts, _ := newTestTokenServiceFull(t)

	user := &model.User{Email: "user@example.com", Name: "Test User", IsVerified: true}
	user.ID = 42
	app := &model.App{ClientID: "my-app"}

	tokens, err := ts.GenerateTokenSet(user, app, "user", "openid", nil, "", 0)
	if err != nil {
		t.Fatalf("GenerateTokenSet: %v", err)
	}

	claims, err := ts.VerifyIDToken(tokens.IDToken)
	if err != nil {
		t.Fatalf("VerifyIDToken: %v", err)
	}

	if claims.Type != "id_token" {
		t.Errorf("Type = %q, want %q", claims.Type, "id_token")
	}
	if claims.Email != "user@example.com" {
		t.Errorf("Email = %q, want %q", claims.Email, "user@example.com")
	}
	if len(claims.Audience) == 0 || claims.Audience[0] != "my-app" {
		t.Errorf("Audience = %v, want [my-app]", claims.Audience)
	}
}

func TestVerifyIDToken_AudienceClaimTrusted(t *testing.T) {
	t.Parallel()
	ts, _ := newTestTokenServiceFull(t)

	user := &model.User{Email: "test@example.com"}
	user.ID = 7
	app := &model.App{ClientID: "trusted-client"}

	tokens, err := ts.GenerateTokenSet(user, app, "user", "openid", nil, "", 0)
	if err != nil {
		t.Fatalf("GenerateTokenSet: %v", err)
	}

	claims, err := ts.VerifyIDToken(tokens.IDToken)
	if err != nil {
		t.Fatalf("VerifyIDToken: %v", err)
	}
	if len(claims.Audience) == 0 || claims.Audience[0] != "trusted-client" {
		t.Errorf("Audience = %v, want [trusted-client]", claims.Audience)
	}
}

// ---------------------------------------------------------------------------
// VerifyIDToken — wrong token type must be rejected
// ---------------------------------------------------------------------------

func TestVerifyIDToken_AccessToken_ReturnsTypeError(t *testing.T) {
	t.Parallel()
	ts, _ := newTestTokenServiceFull(t)

	user := &model.User{Email: "u@example.com"}
	user.ID = 1
	app := &model.App{ClientID: "app1"}

	tokens, err := ts.GenerateTokenSet(user, app, "user", "openid", nil, "", 0)
	if err != nil {
		t.Fatalf("GenerateTokenSet: %v", err)
	}

	// Pass the access token where an id_token is expected.
	_, err = ts.VerifyIDToken(tokens.AccessToken)
	if err == nil {
		t.Fatal("VerifyIDToken: expected error for access token, got nil")
	}
	if !errors.Is(err, ErrTokenInvalidType) {
		t.Errorf("VerifyIDToken: expected ErrTokenInvalidType, got %v", err)
	}
}

func TestVerifyIDToken_RefreshToken_ReturnsTypeError(t *testing.T) {
	t.Parallel()
	ts, _ := newTestTokenServiceFull(t)

	user := &model.User{Email: "u@example.com"}
	user.ID = 1
	app := &model.App{ClientID: "app1"}

	tokens, err := ts.GenerateTokenSet(user, app, "user", "openid", nil, "", 0)
	if err != nil {
		t.Fatalf("GenerateTokenSet: %v", err)
	}

	_, err = ts.VerifyIDToken(tokens.RefreshToken)
	if err == nil {
		t.Fatal("VerifyIDToken: expected error for refresh token, got nil")
	}
	if !errors.Is(err, ErrTokenInvalidType) {
		t.Errorf("VerifyIDToken: expected ErrTokenInvalidType, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// VerifyIDToken — bad/forged signature must be rejected
// ---------------------------------------------------------------------------

func TestVerifyIDToken_FakeSignature_ReturnsSignatureError(t *testing.T) {
	t.Parallel()
	ts, _ := newTestTokenServiceFull(t)

	user := &model.User{Email: "u@example.com"}
	user.ID = 1
	app := &model.App{ClientID: "app1"}

	tokens, err := ts.GenerateTokenSet(user, app, "user", "openid", nil, "", 0)
	if err != nil {
		t.Fatalf("GenerateTokenSet: %v", err)
	}

	// Tamper with the signature (replace it entirely with junk).
	parts := strings.Split(tokens.IDToken, ".")
	if len(parts) != 3 {
		t.Fatalf("unexpected token format")
	}
	parts[2] = "forgedsignatureXXXXXXXX"
	tampered := strings.Join(parts, ".")

	_, err = ts.VerifyIDToken(tampered)
	if err == nil {
		t.Fatal("VerifyIDToken: expected error for forged signature, got nil")
	}
	if !errors.Is(err, ErrTokenSignature) {
		t.Errorf("VerifyIDToken: expected ErrTokenSignature, got %v", err)
	}
}

func TestVerifyIDToken_TokenSignedByDifferentKey_Rejected(t *testing.T) {
	t.Parallel()
	// Use two completely independent token services with different keys.
	ts1, _ := newTestTokenServiceFull(t)
	ts2, _ := newTestTokenServiceFull(t)

	user := &model.User{Email: "u@example.com"}
	user.ID = 1
	app := &model.App{ClientID: "app"}

	// Sign with ts1's key.
	tokens, err := ts1.GenerateTokenSet(user, app, "user", "openid", nil, "", 0)
	if err != nil {
		t.Fatalf("GenerateTokenSet: %v", err)
	}

	// Verify with ts2 — different key ring, must fail.
	_, err = ts2.VerifyIDToken(tokens.IDToken)
	if err == nil {
		t.Fatal("VerifyIDToken: expected error when verifying token from a different key, got nil")
	}
}

// ---------------------------------------------------------------------------
// VerifyIDToken — expired token returns ErrTokenExpired
// ---------------------------------------------------------------------------

func TestVerifyIDToken_ExpiredToken_ReturnsExpiredError(t *testing.T) {
	t.Parallel()

	km, err := newKeyManagerWithBits(t.TempDir(), 2048)
	if err != nil {
		t.Fatalf("newKeyManagerWithBits: %v", err)
	}
	// Negative AccessTokenTTL means the token is already expired at issuance.
	ts := NewTokenService(km, TokenConfig{
		Issuer:          "https://test.example.com",
		AccessTokenTTL:  -time.Second,
		RefreshTokenTTL: time.Hour,
		EmailTokenTTL:   time.Hour,
		ResetTokenTTL:   time.Hour,
		InviteTokenTTL:  time.Hour,
	})

	user := &model.User{Email: "u@example.com"}
	user.ID = 1
	app := &model.App{ClientID: "app"}

	tokens, err := ts.GenerateTokenSet(user, app, "user", "openid", nil, "", 0)
	if err != nil {
		t.Fatalf("GenerateTokenSet: %v", err)
	}

	_, err = ts.VerifyIDToken(tokens.IDToken)
	if err == nil {
		t.Fatal("VerifyIDToken: expected error for expired token, got nil")
	}
	if !errors.Is(err, ErrTokenExpired) {
		t.Errorf("VerifyIDToken: expected ErrTokenExpired, got %v", err)
	}
}

// ---------------------------------------------------------------------------
// VerifyIDToken — malformed input
// ---------------------------------------------------------------------------

func TestVerifyIDToken_MalformedToken_ReturnsError(t *testing.T) {
	t.Parallel()
	ts, _ := newTestTokenServiceFull(t)

	malformed := []string{
		"",
		"not.a.jwt",
		"just-one-part",
	}

	for _, tok := range malformed {
		_, err := ts.VerifyIDToken(tok)
		if err == nil {
			t.Errorf("VerifyIDToken(%q): expected error, got nil", tok)
		}
	}
}

// ---------------------------------------------------------------------------
// ErrTokenExpired sentinel — unit test of the error value itself
// ---------------------------------------------------------------------------

func TestErrTokenExpired_IsDistinctFromOtherErrors(t *testing.T) {
	t.Parallel()
	otherErrors := []error{
		ErrTokenSignature,
		ErrTokenMalformed,
		ErrTokenInvalidType,
		ErrTokenNotYetValid,
		ErrTokenClaimsInvalid,
	}
	for _, e := range otherErrors {
		if errors.Is(ErrTokenExpired, e) {
			t.Errorf("ErrTokenExpired must not equal %v", e)
		}
		if errors.Is(e, ErrTokenExpired) {
			t.Errorf("%v must not wrap ErrTokenExpired", e)
		}
	}
}

// ---------------------------------------------------------------------------
// VerifyIDToken — survives key rotation (M-03 + M-06 interaction)
// ---------------------------------------------------------------------------

func TestVerifyIDToken_RemainsValidAfterKeyRotation(t *testing.T) {
	t.Parallel()
	ts, km := newTestTokenServiceFull(t)

	user := &model.User{Email: "user@example.com"}
	user.ID = 3
	app := &model.App{ClientID: "app-x"}

	tokens, err := ts.GenerateTokenSet(user, app, "user", "openid", nil, "", 0)
	if err != nil {
		t.Fatalf("GenerateTokenSet: %v", err)
	}

	// Rotate the signing key — old tokens must still verify via retired ring.
	if err := km.RotateKey(); err != nil {
		t.Fatalf("RotateKey: %v", err)
	}

	claims, err := ts.VerifyIDToken(tokens.IDToken)
	if err != nil {
		t.Fatalf("VerifyIDToken after rotation: %v", err)
	}
	if claims.Email != "user@example.com" {
		t.Errorf("Email = %q, want %q", claims.Email, "user@example.com")
	}
}
