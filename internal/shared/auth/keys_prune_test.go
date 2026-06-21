// Package auth — tests for RFC-002 / EPIC-3 retired-key pruning.
//
// PruneRetiredKeys bounds the retired key ring and the JWKS by removing
// archived keys older than a retention window (mod-time based). These tests
// cover age-based pruning, the disabled (maxAge <= 0) path, conservative
// behaviour on filesystem errors, and the schedule-integrated pruning.
package auth

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func retiredKeyPath(km *KeyManager, kid string) string {
	return filepath.Join(km.keysPath, "retired", kid+".pub")
}

func jwksKIDs(km *KeyManager) map[string]bool {
	out := map[string]bool{}
	for _, k := range km.GetJWKS().Keys {
		out[k.Kid] = true
	}
	return out
}

// Rotate twice so that two keys (kid0, kid1) are retired and kid2 is current.
func setupTwoRetired(t *testing.T) (km *KeyManager, kid0, kid1, kid2 string) {
	t.Helper()
	km = newTestKeyManager(t)
	kid0 = km.GetKeyID()
	if err := km.RotateKey(); err != nil {
		t.Fatalf("RotateKey #1: %v", err)
	}
	kid1 = km.GetKeyID()
	if err := km.RotateKey(); err != nil {
		t.Fatalf("RotateKey #2: %v", err)
	}
	kid2 = km.GetKeyID()
	return km, kid0, kid1, kid2
}

func TestPruneRetiredKeys_RemovesOldKeepsFresh(t *testing.T) {
	t.Parallel()
	km, kid0, kid1, kid2 := setupTwoRetired(t)

	// Age kid0's archived file to 2h ago; kid1 stays fresh.
	old := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(retiredKeyPath(km, kid0), old, old); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}

	pruned, err := km.PruneRetiredKeys(time.Hour)
	if err != nil {
		t.Fatalf("PruneRetiredKeys: %v", err)
	}

	if len(pruned) != 1 || pruned[0] != kid0 {
		t.Fatalf("pruned = %v, want [%s]", pruned, kid0)
	}
	// kid0 gone from ring, disk, and JWKS.
	if _, err := km.GetPublicKeyByID(kid0); !errors.Is(err, ErrUnknownKeyID) {
		t.Errorf("GetPublicKeyByID(kid0) err = %v, want ErrUnknownKeyID", err)
	}
	if _, err := os.Stat(retiredKeyPath(km, kid0)); !os.IsNotExist(err) {
		t.Errorf("retired file for kid0 still present (stat err = %v)", err)
	}
	// kid1 (fresh, retired) and kid2 (current) remain.
	if _, err := km.GetPublicKeyByID(kid1); err != nil {
		t.Errorf("GetPublicKeyByID(kid1) = %v, want nil", err)
	}
	kids := jwksKIDs(km)
	if kids[kid0] {
		t.Errorf("JWKS still advertises pruned kid0")
	}
	if !kids[kid1] || !kids[kid2] {
		t.Errorf("JWKS missing expected keys: kid1=%v kid2=%v", kids[kid1], kids[kid2])
	}
}

func TestPruneRetiredKeys_DisabledWhenMaxAgeNonPositive(t *testing.T) {
	t.Parallel()
	km, kid0, kid1, _ := setupTwoRetired(t)

	for _, maxAge := range []time.Duration{0, -time.Hour} {
		pruned, err := km.PruneRetiredKeys(maxAge)
		if err != nil || pruned != nil {
			t.Fatalf("PruneRetiredKeys(%v) = (%v, %v), want (nil, nil)", maxAge, pruned, err)
		}
	}
	// Both retired keys must still resolve.
	for _, kid := range []string{kid0, kid1} {
		if _, err := km.GetPublicKeyByID(kid); err != nil {
			t.Errorf("GetPublicKeyByID(%s) = %v, want nil", kid, err)
		}
	}
}

// Conservative path: if a retired key's file cannot be stat'd, the key is kept
// in the ring and an error is reported (no silent loss of verification).
func TestPruneRetiredKeys_KeepsKeyWhenFileUnreadable(t *testing.T) {
	t.Parallel()
	km := newTestKeyManager(t)
	kid0 := km.GetKeyID()
	if err := km.RotateKey(); err != nil {
		t.Fatalf("RotateKey: %v", err)
	}
	// Remove the archived file out from under the in-memory ring.
	if err := os.Remove(retiredKeyPath(km, kid0)); err != nil {
		t.Fatalf("Remove: %v", err)
	}

	pruned, err := km.PruneRetiredKeys(time.Nanosecond)
	if err == nil {
		t.Fatal("expected an error when the retired file is missing, got nil")
	}
	if len(pruned) != 0 {
		t.Errorf("pruned = %v, want empty (key must be kept)", pruned)
	}
	if _, gerr := km.GetPublicKeyByID(kid0); gerr != nil {
		t.Errorf("kid0 should be retained for verification, GetPublicKeyByID = %v", gerr)
	}
}

// Integration: with a tiny retention, the schedule prunes each just-retired key
// after rotation, keeping the JWKS bounded to the current key.
func TestStartRotationScheduleWithRetention_PrunesAfterRotation(t *testing.T) {
	t.Parallel()
	km := newTestKeyManager(t)

	stop := km.StartRotationScheduleWithRetention(25*time.Millisecond, time.Nanosecond)
	time.Sleep(120 * time.Millisecond) // allow several rotations
	stop()                             // blocks until the goroutine exits

	// Every retired key is older than 1ns by the time prune runs, so the ring
	// is emptied after each tick; only the current key remains in the JWKS.
	if got := len(km.retired); got != 0 {
		t.Errorf("retired ring size = %d, want 0", got)
	}
	if got := len(km.GetJWKS().Keys); got != 1 {
		t.Errorf("JWKS key count = %d, want 1 (current only)", got)
	}
}
