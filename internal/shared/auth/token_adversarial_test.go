// Package auth — Phase 2 adversarial suite (docs/program/TEST-STRATEGY.md).
//
// Classic JWT / OAuth attacks against access-token verification, mapped to the
// OAuth 2.0 Security BCP (RFC 9700) and OWASP ASVS. Each test asserts the
// attack is REJECTED — these guard the highest-blast-radius code in the server.
package auth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/ovandermoten/go-oauth2/internal/model"
)

func advTokenService(t *testing.T, issuer string, accessTTL time.Duration) *TokenService {
	t.Helper()
	km := newTestKeyManager(t)
	return NewTokenService(km, TokenConfig{
		Issuer:          issuer,
		AccessTokenTTL:  accessTTL,
		RefreshTokenTTL: 24 * time.Hour,
	})
}

// validLookingAccessClaims builds claims that would pass the semantic checks, so
// each test isolates the one thing under attack (signature/alg/issuer/etc.).
func validLookingAccessClaims(issuer string) AccessTokenClaims {
	now := time.Now()
	return AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    issuer,
			Subject:   "1",
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
		},
		Type: "access",
	}
}

// alg=none must be rejected (the unsigned-token attack).
func TestAdversarial_AlgNone_Rejected(t *testing.T) {
	ts := advTokenService(t, "https://test.example.com", time.Hour)
	tok := jwt.NewWithClaims(jwt.SigningMethodNone, validLookingAccessClaims("https://test.example.com"))
	s, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("sign none: %v", err)
	}
	if _, err := ts.VerifyAccessToken(s); err == nil {
		t.Fatal("alg=none token MUST be rejected")
	}
}

// RS256→HS256 algorithm-confusion: HS256 signed with the RSA *public* key bytes
// as the HMAC secret. A naive verifier would accept it; ours must not.
func TestAdversarial_AlgConfusionHS256_Rejected(t *testing.T) {
	km := newTestKeyManager(t)
	ts := NewTokenService(km, TokenConfig{Issuer: "https://test.example.com", AccessTokenTTL: time.Hour, RefreshTokenTTL: 24 * time.Hour})
	pubBytes, err := x509.MarshalPKIXPublicKey(km.GetPublicKey())
	if err != nil {
		t.Fatalf("marshal pub: %v", err)
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodHS256, validLookingAccessClaims("https://test.example.com"))
	s, err := tok.SignedString(pubBytes)
	if err != nil {
		t.Fatalf("sign hs256: %v", err)
	}
	if _, err := ts.VerifyAccessToken(s); err == nil {
		t.Fatal("HS256 alg-confusion token MUST be rejected")
	}
}

// A token signed with a foreign RSA key (valid RS256, wrong key) must fail the
// signature check against the server's keys.
func TestAdversarial_ForeignKey_Rejected(t *testing.T) {
	ts := advTokenService(t, "https://test.example.com", time.Hour)
	foreign, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, validLookingAccessClaims("https://test.example.com"))
	tok.Header["kid"] = "attacker-kid"
	s, err := tok.SignedString(foreign)
	if err != nil {
		t.Fatalf("sign foreign: %v", err)
	}
	if _, err := ts.VerifyAccessToken(s); !errors.Is(err, ErrTokenSignature) {
		t.Fatalf("foreign-key token must fail signature, got %v", err)
	}
}

// A tampered signature on an otherwise-valid token must be rejected.
func TestAdversarial_TamperedSignature_Rejected(t *testing.T) {
	ts := advTokenService(t, "https://test.example.com", time.Hour)
	set, err := ts.GenerateTokenSet(&model.User{ID: 1, TokenVersion: 1}, &model.App{ClientID: "c"}, "user", "openid", nil, "", 0)
	if err != nil {
		t.Fatalf("GenerateTokenSet: %v", err)
	}
	tampered := set.AccessToken[:len(set.AccessToken)-2] + flip(set.AccessToken[len(set.AccessToken)-2:])
	if _, err := ts.VerifyAccessToken(tampered); err == nil {
		t.Fatal("tampered-signature token MUST be rejected")
	}
}

func flip(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] == 'A' {
			b[i] = 'B'
		} else {
			b[i] = 'A'
		}
	}
	return string(b)
}

// An expired token must be rejected.
func TestAdversarial_Expired_Rejected(t *testing.T) {
	ts := advTokenService(t, "https://test.example.com", -time.Hour) // already expired at issue
	set, err := ts.GenerateTokenSet(&model.User{ID: 1, TokenVersion: 1}, &model.App{ClientID: "c"}, "user", "openid", nil, "", 0)
	if err != nil {
		t.Fatalf("GenerateTokenSet: %v", err)
	}
	if _, err := ts.VerifyAccessToken(set.AccessToken); !errors.Is(err, ErrTokenExpired) {
		t.Fatalf("expired token must be ErrTokenExpired, got %v", err)
	}
}

// A token from a different issuer (same signing key) must be rejected — guards
// against issuer/mix-up confusion.
func TestAdversarial_WrongIssuer_Rejected(t *testing.T) {
	km := newTestKeyManager(t)
	good := NewTokenService(km, TokenConfig{Issuer: "https://good.example.com", AccessTokenTTL: time.Hour, RefreshTokenTTL: 24 * time.Hour})
	evil := NewTokenService(km, TokenConfig{Issuer: "https://evil.example.com", AccessTokenTTL: time.Hour, RefreshTokenTTL: 24 * time.Hour})

	set, err := evil.GenerateTokenSet(&model.User{ID: 1, TokenVersion: 1}, &model.App{ClientID: "c"}, "user", "openid", nil, "", 0)
	if err != nil {
		t.Fatalf("GenerateTokenSet: %v", err)
	}
	if _, err := good.VerifyAccessToken(set.AccessToken); !errors.Is(err, ErrTokenClaimsInvalid) {
		t.Fatalf("wrong-issuer token must be rejected (ErrTokenClaimsInvalid), got %v", err)
	}
}

// A refresh token presented to the access-token verifier must be rejected
// (token-type confusion).
func TestAdversarial_TypeConfusion_RefreshAsAccess_Rejected(t *testing.T) {
	ts := advTokenService(t, "https://test.example.com", time.Hour)
	set, err := ts.GenerateTokenSet(&model.User{ID: 1, TokenVersion: 1}, &model.App{ClientID: "c"}, "user", "openid", nil, "", 0)
	if err != nil {
		t.Fatalf("GenerateTokenSet: %v", err)
	}
	if _, err := ts.VerifyAccessToken(set.RefreshToken); !errors.Is(err, ErrTokenInvalidType) {
		t.Fatalf("refresh-as-access must be ErrTokenInvalidType, got %v", err)
	}
}

// Garbage / malformed input must be rejected, not panic.
func TestAdversarial_Malformed_Rejected(t *testing.T) {
	ts := advTokenService(t, "https://test.example.com", time.Hour)
	for _, bad := range []string{"", "not-a-jwt", "a.b.c", "....", "Bearer x"} {
		if _, err := ts.VerifyAccessToken(bad); err == nil {
			t.Errorf("malformed token %q MUST be rejected", bad)
		}
	}
}
