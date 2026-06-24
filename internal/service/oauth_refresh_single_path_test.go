// Package service — tests for the single hardened refresh code path.
//
// The bearer refresh endpoint (POST /api/auth/refresh) no longer has its own
// weaker implementation; AuthService.RefreshTokens delegates to
// oauthService.RefreshFromBearer, which derives the client from the refresh
// token's audience and runs the same handleRefreshTokenGrant path as
// /oauth/token. These tests assert that rotation / single-use replay detection
// therefore applies on the bearer path too, and that the delegation is wired.
package service

import (
	"context"
	"errors"
	"testing"
)

// TestSingleRefreshPath_Bearer_DerivesClient_AndEnforcesReplay verifies that
// RefreshFromBearer (the /api/auth/refresh path) routes through the hardened
// grant: the first use succeeds without being rejected by the token checks, and
// re-presenting the same token is rejected with ErrInvalidToken (single-use).
func TestSingleRefreshPath_Bearer_DerivesClient_AndEnforcesReplay(t *testing.T) {
	usedRepo := newMemUsedTokenRepo()
	svc, refreshToken := newHigh04Service(t, usedRepo)
	ctx := context.Background()

	// First use: client_id is derived from the token's audience ("test-client").
	resp, firstErr := svc.RefreshFromBearer(ctx, refreshToken)
	if errors.Is(firstErr, ErrInvalidToken) {
		t.Fatalf("first bearer refresh unexpectedly rejected with ErrInvalidToken: %v", firstErr)
	}
	if firstErr == nil && resp.AccessToken == "" {
		t.Error("expected a non-empty access token on first bearer refresh")
	}

	// Second use of the same token: must be rejected as a replay, proving the
	// rotation/single-use machinery applies on the bearer path.
	if _, secondErr := svc.RefreshFromBearer(ctx, refreshToken); !errors.Is(secondErr, ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken on bearer refresh replay, got: %v", secondErr)
	}
}

// TestSingleRefreshPath_Bearer_RejectsGarbage verifies a malformed token is
// rejected (and never panics on audience derivation).
func TestSingleRefreshPath_Bearer_RejectsGarbage(t *testing.T) {
	svc, _ := newHigh04Service(t, newMemUsedTokenRepo())
	if _, err := svc.RefreshFromBearer(context.Background(), "not-a-jwt"); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken for malformed token, got: %v", err)
	}
}

// TestSingleRefreshPath_AuthServiceDelegates verifies AuthService.RefreshTokens
// delegates to the wired RefreshGranter, and fails closed when unconfigured
// (no silent fallback to an unhardened path).
func TestSingleRefreshPath_AuthServiceDelegates(t *testing.T) {
	usedRepo := newMemUsedTokenRepo()
	svc, refreshToken := newHigh04Service(t, usedRepo)
	ctx := context.Background()

	// Unconfigured: must fail closed.
	unconfigured := &authService{}
	if _, err := unconfigured.RefreshTokens(ctx, refreshToken); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("unconfigured RefreshTokens should fail closed with ErrInvalidToken, got: %v", err)
	}

	// Wired to the hardened granter: delegates and enforces single-use.
	wired := &authService{refreshGranter: svc}
	if _, err := wired.RefreshTokens(ctx, refreshToken); errors.Is(err, ErrInvalidToken) {
		t.Fatalf("first delegated refresh unexpectedly rejected: %v", err)
	}
	if _, err := wired.RefreshTokens(ctx, refreshToken); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("expected replay rejection through delegation, got: %v", err)
	}
}
