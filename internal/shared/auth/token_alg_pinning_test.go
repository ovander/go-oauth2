// Package auth — tests for RFC-002 verification algorithm pinning.
//
// verifyToken pins acceptance to an explicit allow-list of exactly "RS256"
// (jwt.WithValidMethods). These tests prove that tokens signed with any other
// algorithm are rejected even when signed with the server's own key, and that
// legitimate RS256 tokens still verify.
package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// signWithMethod builds a token with the given signing method and the server's
// current kid, signed with the provided key.
func signWithMethod(t *testing.T, km *KeyManager, method jwt.SigningMethod, key interface{}) string {
	t.Helper()
	claims := AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Subject:   "1",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			ID:        "test-jti",
		},
		Type: "access",
	}
	tok := jwt.NewWithClaims(method, claims)
	tok.Header["kid"] = km.GetKeyID()
	signed, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("SignedString(%s): %v", method.Alg(), err)
	}
	return signed
}

func newPinningTokenService(t *testing.T) (*TokenService, *KeyManager) {
	t.Helper()
	km := newTestKeyManager(t)
	ts := NewTokenService(km, TokenConfig{
		Issuer:         "https://test.example.com",
		AccessTokenTTL: time.Hour,
	})
	return ts, km
}

// Negative: a token signed with RS384 using the server's own private key must
// be rejected, because verification is pinned to RS256.
func TestVerify_RejectsRS384EvenWithServerKey(t *testing.T) {
	t.Parallel()
	ts, km := newPinningTokenService(t)

	token := signWithMethod(t, km, jwt.SigningMethodRS384, km.GetPrivateKey())

	if _, err := ts.VerifyAccessToken(token); err == nil {
		t.Fatal("expected RS384 token to be rejected by RS256 allow-list, got nil error")
	}
}

// Negative: a token signed with RS512 using the server's own key must be rejected.
func TestVerify_RejectsRS512EvenWithServerKey(t *testing.T) {
	t.Parallel()
	ts, km := newPinningTokenService(t)

	token := signWithMethod(t, km, jwt.SigningMethodRS512, km.GetPrivateKey())

	if _, err := ts.VerifyAccessToken(token); err == nil {
		t.Fatal("expected RS512 token to be rejected by RS256 allow-list, got nil error")
	}
}

// Negative: an unsigned ("none") token must be rejected.
func TestVerify_RejectsNoneAlg(t *testing.T) {
	t.Parallel()
	ts, km := newPinningTokenService(t)

	token := signWithMethod(t, km, jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType)

	if _, err := ts.VerifyAccessToken(token); err == nil {
		t.Fatal("expected none-alg token to be rejected, got nil error")
	}
}

// Regression: legitimately issued RS256 tokens continue to verify.
func TestVerify_AcceptsRS256(t *testing.T) {
	t.Parallel()
	ts, km := newPinningTokenService(t)

	token := signWithMethod(t, km, jwt.SigningMethodRS256, km.GetPrivateKey())

	claims, err := ts.VerifyAccessToken(token)
	if err != nil {
		t.Fatalf("RS256 token should verify, got error: %v", err)
	}
	if claims.Type != "access" {
		t.Errorf("Type = %q, want access", claims.Type)
	}
}
