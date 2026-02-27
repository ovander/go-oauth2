// Package auth — tests for the HIGH-05 RSA private key file permission fix.
//
// HIGH-05 fix: the RSA private key must be written (and enforced on load) with
// mode 0400 (read-only owner) instead of the previous 0600 (read-write owner).
// Additionally, loadKeys auto-tightens permissions when an existing file has
// wider-than-0400 mode — ensuring rolling upgrades immediately close the window
// without requiring a manual chmod.
package auth

import (
	"os"
	"path/filepath"
	"testing"
)

// TestHIGH05_GenerateKeys_PrivateKeyIs0400 verifies that a freshly generated
// RSA private key file is written with mode 0400.
func TestHIGH05_GenerateKeys_PrivateKeyIs0400(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	_, err := newKeyManagerWithBits(dir, 2048)
	if err != nil {
		t.Fatalf("newKeyManagerWithBits: %v", err)
	}

	privatePath := filepath.Join(dir, "private.pem")
	info, err := os.Stat(privatePath)
	if err != nil {
		t.Fatalf("os.Stat private.pem: %v", err)
	}

	perm := info.Mode().Perm()
	if perm != 0400 {
		t.Errorf("private key file has mode %04o, want 0400", perm)
	}
}

// TestHIGH05_GenerateKeys_PublicKeyPermission verifies that the public key is
// world-readable (0644) as expected — not over-restricted.
func TestHIGH05_GenerateKeys_PublicKeyPermission(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	_, err := newKeyManagerWithBits(dir, 2048)
	if err != nil {
		t.Fatalf("newKeyManagerWithBits: %v", err)
	}

	publicPath := filepath.Join(dir, "public.pem")
	info, err := os.Stat(publicPath)
	if err != nil {
		t.Fatalf("os.Stat public.pem: %v", err)
	}

	perm := info.Mode().Perm()
	if perm != 0644 {
		t.Errorf("public key file has mode %04o, want 0644", perm)
	}
}

// TestHIGH05_LoadKeys_AutoTightens0600To0400 verifies that when an existing
// private key file has mode 0600 (e.g. created by an older version of the
// server), loadKeys automatically tightens the permissions to 0400 and still
// loads the key successfully.
func TestHIGH05_LoadKeys_AutoTightens0600To0400(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	// Generate an initial key pair so we have valid PEM files.
	km1, err := newKeyManagerWithBits(dir, 2048)
	if err != nil {
		t.Fatalf("initial newKeyManagerWithBits: %v", err)
	}
	originalKID := km1.GetKeyID()

	// Widen the private key permissions to 0600 to simulate the pre-fix state.
	privatePath := filepath.Join(dir, "private.pem")
	if err := os.Chmod(privatePath, 0600); err != nil {
		t.Fatalf("os.Chmod to 0600: %v", err)
	}

	// Reload — loadKeys should tighten permissions automatically.
	km2, err := newKeyManagerWithBits(dir, 2048)
	if err != nil {
		t.Fatalf("newKeyManagerWithBits on reload: %v", err)
	}

	// The key must be tightened to 0400.
	info, err := os.Stat(privatePath)
	if err != nil {
		t.Fatalf("os.Stat after reload: %v", err)
	}
	if info.Mode().Perm() != 0400 {
		t.Errorf("expected mode 0400 after auto-tighten, got %04o", info.Mode().Perm())
	}

	// The same KID must be loaded (we did not rotate).
	if km2.GetKeyID() != originalKID {
		t.Errorf("KID changed unexpectedly: got %s, want %s", km2.GetKeyID(), originalKID)
	}
}

// TestHIGH05_LoadKeys_0400_AlreadyCorrect_NoError verifies that loading a key
// that already has 0400 permissions works without error and without changing
// any state.
func TestHIGH05_LoadKeys_0400_AlreadyCorrect_NoError(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	// First load generates with 0400.
	km1, err := newKeyManagerWithBits(dir, 2048)
	if err != nil {
		t.Fatalf("initial load: %v", err)
	}
	kid1 := km1.GetKeyID()

	// Second load should succeed without error.
	km2, err := newKeyManagerWithBits(dir, 2048)
	if err != nil {
		t.Fatalf("reload with already-correct permissions: %v", err)
	}

	if km2.GetKeyID() != kid1 {
		t.Errorf("KID changed across reload: got %s, want %s", km2.GetKeyID(), kid1)
	}
}
