// Package auth — tests for RFC-002 issuer/expiry verification hardening (#38).
package auth

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/ovandermoten/go-oauth2/internal/model"
)

const testIssuer = "https://test.example.com"

func newIssuerTokenService(t *testing.T) (*TokenService, *KeyManager) {
	t.Helper()
	km := newTestKeyManager(t)
	ts := NewTokenService(km, TokenConfig{Issuer: testIssuer, AccessTokenTTL: time.Hour})
	return ts, km
}

// signClaims signs arbitrary claims with the server's current RS256 key + kid,
// so the signature is valid and only claim validation can reject the token.
func signClaims(t *testing.T, km *KeyManager, claims jwt.Claims) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = km.GetKeyID()
	s, err := tok.SignedString(km.GetPrivateKey())
	if err != nil {
		t.Fatalf("SignedString: %v", err)
	}
	return s
}

func TestVerify_RejectsWrongIssuer(t *testing.T) {
	t.Parallel()
	ts, km := newIssuerTokenService(t)

	token := signClaims(t, km, AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://evil.example.com",
			Subject:   "1",
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
		Type: "access",
	})

	if _, err := ts.VerifyAccessToken(token); err == nil {
		t.Fatal("expected token with a foreign issuer to be rejected")
	}
}

func TestVerify_RejectsMissingExpiry(t *testing.T) {
	t.Parallel()
	ts, km := newIssuerTokenService(t)

	token := signClaims(t, km, AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:  testIssuer,
			Subject: "1",
			// no ExpiresAt
		},
		Type: "access",
	})

	if _, err := ts.VerifyAccessToken(token); err == nil {
		t.Fatal("expected token without an expiry to be rejected")
	}
}

// Regression: a normally-issued token (correct issuer + expiry) still verifies.
func TestVerify_AcceptsCorrectIssuerAndExpiry(t *testing.T) {
	t.Parallel()
	ts, _ := newIssuerTokenService(t)

	token, err := ts.GenerateClientCredentialsToken(&model.App{ClientID: "c"}, "read")
	if err != nil {
		t.Fatalf("GenerateClientCredentialsToken: %v", err)
	}
	if _, err := ts.VerifyAccessToken(token); err != nil {
		t.Errorf("normally-issued token should verify, got: %v", err)
	}
}
