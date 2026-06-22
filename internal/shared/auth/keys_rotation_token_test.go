// Package auth — Phase 4 crypto / key-lifecycle tests (docs/program/TEST-STRATEGY.md).
//
// The retired-key ring exists so that a token signed before a key rotation
// still verifies afterwards (zero-downtime rotation, RFC-002 / EPIC-3). These
// tests assert that property at the *token* level — not just the key files —
// across rotation and pruning.
package auth

import (
	"os"
	"testing"
	"time"

	"github.com/ovandermoten/go-oauth2/internal/model"
)

func rotationTokenService(t *testing.T) (*KeyManager, *TokenService) {
	t.Helper()
	km := newTestKeyManager(t)
	ts := NewTokenService(km, TokenConfig{
		Issuer:          "https://test.example.com",
		AccessTokenTTL:  time.Hour,
		RefreshTokenTTL: 24 * time.Hour,
	})
	return km, ts
}

func mintRotationToken(t *testing.T, ts *TokenService) string {
	t.Helper()
	set, err := ts.GenerateTokenSet(&model.User{ID: 1, TokenVersion: 1}, &model.App{ClientID: "c"}, "user", "openid", nil, "", 0)
	if err != nil {
		t.Fatalf("GenerateTokenSet: %v", err)
	}
	return set.AccessToken
}

// NOTE: cross-rotation token verification (pre-rotation tokens still valid after
// rotation, multiple rotations, after restart) is already covered by
// token_rotation_test.go. These tests fill the remaining gap — connecting the
// key *lifecycle* (JWKS exposure, pruning) to actual token verification.

// After a rotation, JWKS must expose both the current and the retired key, so a
// resource server can fetch the key to verify either token.
func TestRotation_JWKSExposesCurrentAndRetired(t *testing.T) {
	km, _ := rotationTokenService(t)
	kid0 := km.GetKeyID()
	if err := km.RotateKey(); err != nil {
		t.Fatalf("RotateKey: %v", err)
	}
	kid1 := km.GetKeyID()

	have := map[string]bool{}
	for _, k := range km.GetJWKS().Keys {
		have[k.Kid] = true
	}
	if !have[kid0] || !have[kid1] {
		t.Fatalf("JWKS must expose current (%s) + retired (%s); got %v", kid1, kid0, have)
	}
}

// Once the retired key is pruned, the token it signed must no longer verify —
// pruning bounds the verification window (so retention must outlive the TTL).
func TestRotation_PrunedKeyTokenNoLongerVerifies(t *testing.T) {
	km, ts := rotationTokenService(t)
	kid0 := km.GetKeyID()
	before := mintRotationToken(t, ts)

	if err := km.RotateKey(); err != nil {
		t.Fatalf("RotateKey: %v", err)
	}
	// Backdate the retired key so it is older than the prune window.
	old := time.Now().Add(-48 * time.Hour)
	if err := os.Chtimes(retiredKeyPath(km, kid0), old, old); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}
	pruned, err := km.PruneRetiredKeys(time.Hour)
	if err != nil {
		t.Fatalf("PruneRetiredKeys: %v", err)
	}
	if len(pruned) != 1 || pruned[0] != kid0 {
		t.Fatalf("expected kid0 (%s) pruned, got %v", kid0, pruned)
	}

	// The pre-rotation token can no longer be verified (its key is gone).
	if _, err := ts.VerifyAccessToken(before); err == nil {
		t.Fatal("token signed with a pruned key MUST no longer verify")
	}
}
