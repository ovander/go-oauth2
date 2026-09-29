// Package auth — tests for the Signer seam (RFC-002 / EPIC-3, capability C3).
//
// These tests assert that:
//   - the default localSigner reproduces the prior RS256 + "kid" behaviour and
//     that tokens it signs verify through TokenService;
//   - a Signer can be injected via NewTokenServiceWithSigner and is actually
//     used by token generation (including error propagation);
//   - a nil signer falls back to the local signer.
//
// All tests use 2048-bit RSA via newKeyManagerWithBits for speed and run in
// parallel with isolated temp directories.
package auth

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/ovander/go-oauth2/internal/model"
)

// newTestKeyManager is defined in keys_test.go (same package) and returns a
// fresh 2048-bit KeyManager in an isolated temp dir.

// --- localSigner unit tests ------------------------------------------------

func TestLocalSigner_Algorithm(t *testing.T) {
	t.Parallel()
	s := NewLocalSigner(newTestKeyManager(t))
	if got := s.Algorithm(); got != "RS256" {
		t.Errorf("Algorithm() = %q, want RS256", got)
	}
}

func TestLocalSigner_KeyID_MatchesKeyManager(t *testing.T) {
	t.Parallel()
	km := newTestKeyManager(t)
	s := NewLocalSigner(km)
	if got, want := s.KeyID(), km.GetKeyID(); got != want {
		t.Errorf("KeyID() = %q, want %q", got, want)
	}
	if s.KeyID() == "" {
		t.Error("KeyID() is empty")
	}
}

func TestLocalSigner_SignToken_SetsKidAndAlgHeaders(t *testing.T) {
	t.Parallel()
	km := newTestKeyManager(t)
	s := NewLocalSigner(km)

	signed, err := s.SignToken(jwt.RegisteredClaims{
		Subject:   "1",
		ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
	})
	if err != nil {
		t.Fatalf("SignToken: %v", err)
	}

	// Parse without verifying to inspect the header.
	parser := jwt.NewParser()
	tok, _, err := parser.ParseUnverified(signed, jwt.MapClaims{})
	if err != nil {
		t.Fatalf("ParseUnverified: %v", err)
	}
	if got := tok.Header["alg"]; got != "RS256" {
		t.Errorf("header alg = %v, want RS256", got)
	}
	if got := tok.Header["kid"]; got != km.GetKeyID() {
		t.Errorf("header kid = %v, want %v", got, km.GetKeyID())
	}
}

// Integration: a token signed by localSigner verifies through TokenService.
func TestLocalSigner_SignToken_RoundTripVerifies(t *testing.T) {
	t.Parallel()
	km := newTestKeyManager(t)
	ts := NewTokenServiceWithSigner(km, NewLocalSigner(km), TokenConfig{
		Issuer:         "https://test.example.com",
		AccessTokenTTL: time.Hour,
	})

	app := &model.App{ClientID: "client-roundtrip"}
	token, err := ts.GenerateClientCredentialsToken(app, "read")
	if err != nil {
		t.Fatalf("GenerateClientCredentialsToken: %v", err)
	}
	claims, err := ts.VerifyAccessToken(token)
	if err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}
	if claims.Type != "access" {
		t.Errorf("Type = %q, want access", claims.Type)
	}
}

// --- injection tests -------------------------------------------------------

// recordingSigner is a stub Signer used to prove the injected signer is used.
type recordingSigner struct {
	out    string
	err    error
	called int
}

func (r *recordingSigner) SignToken(jwt.Claims) (string, error) {
	r.called++
	return r.out, r.err
}
func (r *recordingSigner) KeyID() string     { return "stub-kid" }
func (r *recordingSigner) Algorithm() string { return "RS256" }

func TestNewTokenServiceWithSigner_UsesInjectedSigner(t *testing.T) {
	t.Parallel()
	km := newTestKeyManager(t)
	stub := &recordingSigner{out: "stub.signed.token"}
	ts := NewTokenServiceWithSigner(km, stub, TokenConfig{
		Issuer:         "https://test.example.com",
		AccessTokenTTL: time.Hour,
	})

	got, err := ts.GenerateClientCredentialsToken(&model.App{ClientID: "c"}, "read")
	if err != nil {
		t.Fatalf("GenerateClientCredentialsToken: %v", err)
	}
	if got != "stub.signed.token" {
		t.Errorf("token = %q, want stub.signed.token (injected signer not used)", got)
	}
	if stub.called != 1 {
		t.Errorf("injected signer called %d times, want 1", stub.called)
	}
}

// Negative: an injected signer's error must propagate to callers.
func TestNewTokenServiceWithSigner_PropagatesSignerError(t *testing.T) {
	t.Parallel()
	km := newTestKeyManager(t)
	sentinel := errors.New("kms unavailable")
	stub := &recordingSigner{err: sentinel}
	ts := NewTokenServiceWithSigner(km, stub, TokenConfig{
		Issuer:         "https://test.example.com",
		AccessTokenTTL: time.Hour,
	})

	_, err := ts.GenerateClientCredentialsToken(&model.App{ClientID: "c"}, "read")
	if !errors.Is(err, sentinel) {
		t.Fatalf("error = %v, want it to wrap %v", err, sentinel)
	}
}

func TestNewTokenServiceWithSigner_NilSignerFallsBackToLocal(t *testing.T) {
	t.Parallel()
	km := newTestKeyManager(t)
	ts := NewTokenServiceWithSigner(km, nil, TokenConfig{
		Issuer:         "https://test.example.com",
		AccessTokenTTL: time.Hour,
	})

	token, err := ts.GenerateClientCredentialsToken(&model.App{ClientID: "c"}, "read")
	if err != nil {
		t.Fatalf("GenerateClientCredentialsToken: %v", err)
	}
	if strings.Count(token, ".") != 2 {
		t.Fatalf("expected a 3-part JWS, got %q", token)
	}
	if _, err := ts.VerifyAccessToken(token); err != nil {
		t.Errorf("VerifyAccessToken after nil-signer fallback: %v", err)
	}
}

// Default constructor must remain behaviourally identical (regression guard).
func TestNewTokenService_DefaultSignerRoundTrips(t *testing.T) {
	t.Parallel()
	km := newTestKeyManager(t)
	ts := NewTokenService(km, TokenConfig{
		Issuer:         "https://test.example.com",
		AccessTokenTTL: time.Hour,
	})
	token, err := ts.GenerateClientCredentialsToken(&model.App{ClientID: "c"}, "read")
	if err != nil {
		t.Fatalf("GenerateClientCredentialsToken: %v", err)
	}
	if _, err := ts.VerifyAccessToken(token); err != nil {
		t.Errorf("VerifyAccessToken: %v", err)
	}
}
