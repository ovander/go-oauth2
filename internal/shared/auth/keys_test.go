// Package auth — tests for M-03 (key rotation support) and M-04 (UUID KIDs).
//
// All tests use t.TempDir() for key storage so no files escape the test run.
// All tests call t.Parallel(): every test has its own isolated temp directory
// so there is no shared state between them.
//
// Key size: tests use 2048-bit RSA via newKeyManagerWithBits(..., 2048).
// Production uses 3072-bit; the smaller size is ~3× faster to generate and
// still exercises every code path identically.
package auth

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/google/uuid"
)

// newTestKeyManager creates a KeyManager backed by a fresh temp directory,
// using 2048-bit RSA keys for faster test execution.
func newTestKeyManager(t *testing.T) *KeyManager {
	t.Helper()
	km, err := newKeyManagerWithBits(t.TempDir(), 2048)
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}
	return km
}

// isUUID returns true if s is a valid UUID (version-agnostic).
func isUUID(s string) bool {
	_, err := uuid.Parse(s)
	return err == nil
}

// ---------------------------------------------------------------------------
// M-04: Key ID must be a random UUID, not a timestamp
// ---------------------------------------------------------------------------

func TestNewKeyManager_GeneratesUUIDKeyID(t *testing.T) {
	t.Parallel()
	km := newTestKeyManager(t)
	kid := km.GetKeyID()

	if !isUUID(kid) {
		t.Errorf("expected key ID to be a UUID, got %q", kid)
	}
}

func TestNewKeyManager_KeyIDNotTimestampFormat(t *testing.T) {
	t.Parallel()
	// Old format: "key-<unix>" — must never appear for new key managers.
	km := newTestKeyManager(t)
	kid := km.GetKeyID()

	if strings.HasPrefix(kid, "key-") {
		t.Errorf("key ID must not use timestamp format 'key-<unix>', got %q", kid)
	}
}

func TestNewKeyManager_TwoFreshManagers_DifferentKIDs(t *testing.T) {
	t.Parallel()
	// Each new key manager must generate a different KID (random UUID).
	km1 := newTestKeyManager(t)
	km2 := newTestKeyManager(t)

	if km1.GetKeyID() == km2.GetKeyID() {
		t.Error("two independent KeyManagers must not produce the same key ID")
	}
}

func TestNewKeyManager_LegacyTimestampKID_MigratedToUUID(t *testing.T) {
	t.Parallel()
	// M-04 migration path: if an existing key_id file contains "key-<unix>",
	// KeyManager rewrites it to a UUID on load.
	dir := t.TempDir()

	// Step 1: generate a fresh key pair so private.pem / public.pem exist.
	km1, err := newKeyManagerWithBits(dir, 2048)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	_ = km1

	// Step 2: overwrite the key_id file with a legacy timestamp KID.
	legacyKID := "key-1706123456"
	keyIDPath := filepath.Join(dir, "key_id")
	if err := os.WriteFile(keyIDPath, []byte(legacyKID), 0644); err != nil {
		t.Fatalf("could not write legacy key_id: %v", err)
	}

	// Step 3: reload from the same directory.
	km2, err := newKeyManagerWithBits(dir, 2048)
	if err != nil {
		t.Fatalf("NewKeyManager with legacy KID: %v", err)
	}

	migratedKID := km2.GetKeyID()

	if migratedKID == legacyKID {
		t.Error("legacy timestamp KID was not replaced with a UUID")
	}
	if !isUUID(migratedKID) {
		t.Errorf("migrated KID is not a valid UUID: %q", migratedKID)
	}

	// Step 4: verify the file on disk was also updated.
	written, _ := os.ReadFile(keyIDPath)
	if strings.TrimSpace(string(written)) != migratedKID {
		t.Error("key_id file on disk was not updated to the new UUID")
	}
}

func TestNewKeyManager_MissingKeyIDFile_CreatesUUID(t *testing.T) {
	t.Parallel()
	// If the key_id file is missing (can happen with manually deployed keys),
	// a new UUID must be generated and persisted.
	dir := t.TempDir()

	// Create keys without a key_id file.
	km1, err := newKeyManagerWithBits(dir, 2048)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	_ = km1

	// Remove the key_id file.
	if err := os.Remove(filepath.Join(dir, "key_id")); err != nil {
		t.Fatalf("could not remove key_id: %v", err)
	}

	// Reload: must produce a new UUID and write it.
	km2, err := newKeyManagerWithBits(dir, 2048)
	if err != nil {
		t.Fatalf("reload without key_id: %v", err)
	}
	if !isUUID(km2.GetKeyID()) {
		t.Errorf("expected UUID after missing key_id, got %q", km2.GetKeyID())
	}
}

func TestNewKeyManager_PersistingKeyID_SameOnReload(t *testing.T) {
	t.Parallel()
	// If the key_id file is a valid UUID, it must be kept as-is on reload.
	dir := t.TempDir()
	km1, err := newKeyManagerWithBits(dir, 2048)
	if err != nil {
		t.Fatalf("setup: %v", err)
	}
	originalKID := km1.GetKeyID()

	// Reload from the same directory.
	km2, err := newKeyManagerWithBits(dir, 2048)
	if err != nil {
		t.Fatalf("reload: %v", err)
	}
	if km2.GetKeyID() != originalKID {
		t.Errorf("KID changed on reload: %q → %q", originalKID, km2.GetKeyID())
	}
}

// ---------------------------------------------------------------------------
// M-03: GetPublicKeyByID — current and retired key lookup
// ---------------------------------------------------------------------------

func TestGetPublicKeyByID_CurrentKey_Found(t *testing.T) {
	t.Parallel()
	km := newTestKeyManager(t)
	kid := km.GetKeyID()

	pub, err := km.GetPublicKeyByID(kid)
	if err != nil {
		t.Fatalf("GetPublicKeyByID current: %v", err)
	}
	if pub == nil {
		t.Fatal("GetPublicKeyByID returned nil public key for current KID")
	}
}

func TestGetPublicKeyByID_CurrentKey_MatchesGetPublicKey(t *testing.T) {
	t.Parallel()
	km := newTestKeyManager(t)
	kid := km.GetKeyID()

	byID, _ := km.GetPublicKeyByID(kid)
	direct := km.GetPublicKey()

	if byID.N.Cmp(direct.N) != 0 {
		t.Error("GetPublicKeyByID returned different key than GetPublicKey for current KID")
	}
}

func TestGetPublicKeyByID_UnknownKID_ReturnsErrUnknownKeyID(t *testing.T) {
	t.Parallel()
	km := newTestKeyManager(t)

	_, err := km.GetPublicKeyByID("nonexistent-kid")
	if err == nil {
		t.Fatal("expected error for unknown KID, got nil")
	}
	if !strings.Contains(err.Error(), "unknown key ID") {
		t.Errorf("expected ErrUnknownKeyID, got: %v", err)
	}
}

func TestGetPublicKeyByID_EmptyKID_ReturnsError(t *testing.T) {
	t.Parallel()
	km := newTestKeyManager(t)
	_, err := km.GetPublicKeyByID("")
	if err == nil {
		t.Fatal("expected error for empty KID, got nil")
	}
}

// ---------------------------------------------------------------------------
// M-03: RotateKey — generates new key and retires the old one
// ---------------------------------------------------------------------------

func TestRotateKey_Succeeds(t *testing.T) {
	t.Parallel()
	km := newTestKeyManager(t)
	if err := km.RotateKey(); err != nil {
		t.Fatalf("RotateKey: %v", err)
	}
}

func TestRotateKey_ChangesCurrentKID(t *testing.T) {
	t.Parallel()
	km := newTestKeyManager(t)
	oldKID := km.GetKeyID()

	if err := km.RotateKey(); err != nil {
		t.Fatalf("RotateKey: %v", err)
	}

	newKID := km.GetKeyID()
	if newKID == oldKID {
		t.Error("key ID must change after RotateKey")
	}
	if !isUUID(newKID) {
		t.Errorf("new key ID must be a UUID, got %q", newKID)
	}
}

func TestRotateKey_OldKIDReachableViaGetPublicKeyByID(t *testing.T) {
	t.Parallel()
	km := newTestKeyManager(t)
	oldKID := km.GetKeyID()
	oldPub := km.GetPublicKey()

	if err := km.RotateKey(); err != nil {
		t.Fatalf("RotateKey: %v", err)
	}

	retiredPub, err := km.GetPublicKeyByID(oldKID)
	if err != nil {
		t.Fatalf("GetPublicKeyByID retired: %v", err)
	}
	// The retired public key must be the same as the old current key.
	if retiredPub.N.Cmp(oldPub.N) != 0 {
		t.Error("retired public key does not match the old current key")
	}
}

func TestRotateKey_WritesRetiredKeyFileToDisk(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	km, _ := newKeyManagerWithBits(dir, 2048)
	oldKID := km.GetKeyID()

	if err := km.RotateKey(); err != nil {
		t.Fatalf("RotateKey: %v", err)
	}

	retiredPath := filepath.Join(dir, "retired", oldKID+".pub")
	if _, err := os.Stat(retiredPath); os.IsNotExist(err) {
		t.Errorf("expected retired key file at %s but it does not exist", retiredPath)
	}
}

func TestRotateKey_RetiredKeyLoadedOnRestart(t *testing.T) {
	t.Parallel()
	// Retired keys must survive a process restart (be reloaded from the retired/ dir).
	dir := t.TempDir()
	km1, _ := newKeyManagerWithBits(dir, 2048)
	oldKID := km1.GetKeyID()

	if err := km1.RotateKey(); err != nil {
		t.Fatalf("RotateKey: %v", err)
	}

	// Simulate restart by creating a brand-new KeyManager from the same dir.
	km2, err := newKeyManagerWithBits(dir, 2048)
	if err != nil {
		t.Fatalf("reload after rotation: %v", err)
	}

	// Old KID must still be in the ring after reload.
	_, err = km2.GetPublicKeyByID(oldKID)
	if err != nil {
		t.Errorf("retired KID %q not reloaded after restart: %v", oldKID, err)
	}
}

func TestRotateKey_MultipleRotations_AllRetiredKeysAvailable(t *testing.T) {
	t.Parallel()
	km := newTestKeyManager(t)
	retired := make([]string, 0, 3)

	for i := 0; i < 3; i++ {
		retired = append(retired, km.GetKeyID())
		if err := km.RotateKey(); err != nil {
			t.Fatalf("rotation %d: %v", i+1, err)
		}
	}

	for _, kid := range retired {
		if _, err := km.GetPublicKeyByID(kid); err != nil {
			t.Errorf("retired KID %q not found after %d rotations: %v", kid, len(retired), err)
		}
	}
}

// ---------------------------------------------------------------------------
// M-03: GetJWKS — must include current + retired keys
// ---------------------------------------------------------------------------

func TestGetJWKS_FreshKeyManager_ExactlyOneKey(t *testing.T) {
	t.Parallel()
	km := newTestKeyManager(t)
	jwks := km.GetJWKS()

	if len(jwks.Keys) != 1 {
		t.Errorf("expected 1 key in JWKS for fresh KeyManager, got %d", len(jwks.Keys))
	}
}

func TestGetJWKS_CurrentKIDInJWKS(t *testing.T) {
	t.Parallel()
	km := newTestKeyManager(t)
	kid := km.GetKeyID()
	jwks := km.GetJWKS()

	for _, k := range jwks.Keys {
		if k.Kid == kid {
			return
		}
	}
	t.Errorf("current KID %q not found in JWKS", kid)
}

func TestGetJWKS_AfterOneRotation_TwoKeys(t *testing.T) {
	t.Parallel()
	km := newTestKeyManager(t)
	if err := km.RotateKey(); err != nil {
		t.Fatalf("RotateKey: %v", err)
	}

	jwks := km.GetJWKS()
	if len(jwks.Keys) != 2 {
		t.Errorf("expected 2 keys in JWKS after one rotation, got %d", len(jwks.Keys))
	}
}

func TestGetJWKS_AfterNRotations_NPlus1Keys(t *testing.T) {
	t.Parallel()
	const rotations = 4
	km := newTestKeyManager(t)

	for i := 0; i < rotations; i++ {
		if err := km.RotateKey(); err != nil {
			t.Fatalf("rotation %d: %v", i+1, err)
		}
	}

	jwks := km.GetJWKS()
	expected := rotations + 1
	if len(jwks.Keys) != expected {
		t.Errorf("expected %d keys in JWKS after %d rotations, got %d",
			expected, rotations, len(jwks.Keys))
	}
}

func TestGetJWKS_AllKeysHaveRequiredFields(t *testing.T) {
	t.Parallel()
	km := newTestKeyManager(t)
	_ = km.RotateKey()
	jwks := km.GetJWKS()

	for i, k := range jwks.Keys {
		if k.Kty != "RSA" {
			t.Errorf("key[%d]: expected kty=RSA, got %q", i, k.Kty)
		}
		if k.Use != "sig" {
			t.Errorf("key[%d]: expected use=sig, got %q", i, k.Use)
		}
		if k.Alg != "RS256" {
			t.Errorf("key[%d]: expected alg=RS256, got %q", i, k.Alg)
		}
		if k.Kid == "" {
			t.Errorf("key[%d]: kid must not be empty", i)
		}
		if k.N == "" {
			t.Errorf("key[%d]: N modulus must not be empty", i)
		}
		if k.E == "" {
			t.Errorf("key[%d]: E exponent must not be empty", i)
		}
	}
}

func TestGetJWKS_NoDuplicateKIDs(t *testing.T) {
	t.Parallel()
	km := newTestKeyManager(t)
	for i := 0; i < 3; i++ {
		_ = km.RotateKey()
	}
	jwks := km.GetJWKS()

	seen := make(map[string]bool)
	for _, k := range jwks.Keys {
		if seen[k.Kid] {
			t.Errorf("duplicate KID %q in JWKS", k.Kid)
		}
		seen[k.Kid] = true
	}
}

// ---------------------------------------------------------------------------
// M-03: Concurrent safety — RotateKey under concurrent reads
// ---------------------------------------------------------------------------

func TestRotateKey_ConcurrentReads_NoRaceCondition(t *testing.T) {
	t.Parallel()
	// Run with -race to detect data races.
	km := newTestKeyManager(t)

	var wg sync.WaitGroup
	errs := make(chan error, 50)

	// 10 concurrent readers
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = km.GetKeyID()
			_ = km.GetPublicKey()
			_ = km.GetJWKS()
		}()
	}

	// 2 concurrent rotations
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := km.RotateKey(); err != nil {
				errs <- err
			}
		}()
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Errorf("concurrent RotateKey error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// M-03: GetPublicKeyByID after multiple rotations
// ---------------------------------------------------------------------------

func TestGetPublicKeyByID_AllRotatedKIDsRemainAvailable(t *testing.T) {
	t.Parallel()
	km := newTestKeyManager(t)
	generations := make([]struct {
		kid string
		n   string // stringified modulus for comparison
	}, 0, 4)

	// Record the starting key.
	generations = append(generations, struct {
		kid string
		n   string
	}{km.GetKeyID(), km.GetPublicKey().N.String()})

	for i := 0; i < 3; i++ {
		if err := km.RotateKey(); err != nil {
			t.Fatalf("rotation %d: %v", i+1, err)
		}
		generations = append(generations, struct {
			kid string
			n   string
		}{km.GetKeyID(), km.GetPublicKey().N.String()})
	}

	// Every KID from every generation must be retrievable, and the key must
	// match what was current at that time.
	for i, gen := range generations[:len(generations)-1] { // all except the last (still current)
		pub, err := km.GetPublicKeyByID(gen.kid)
		if err != nil {
			t.Errorf("generation %d KID %q not found: %v", i, gen.kid, err)
			continue
		}
		if pub.N.String() != gen.n {
			t.Errorf("generation %d: public key modulus mismatch for KID %q", i, gen.kid)
		}
	}
}

// ---------------------------------------------------------------------------
// Helpers: invalid keysPath
// ---------------------------------------------------------------------------

func TestNewKeyManager_UnwritableDirectory_ReturnsError(t *testing.T) {
	t.Parallel()
	// Passing a file (not a directory) as keysPath must return an error.
	f, err := os.CreateTemp(t.TempDir(), "notadir")
	if err != nil {
		t.Fatal(err)
	}
	f.Close()

	_, err = newKeyManagerWithBits(fmt.Sprintf("%s/subdir", f.Name()), 2048)
	if err == nil {
		t.Error("expected error when keysPath is nested under a file, got nil")
	}
}
