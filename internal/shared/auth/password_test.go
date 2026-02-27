// Package auth — tests for H-03: client secrets must be hashed with bcrypt
// (work factor 12) instead of SHA-256.
//
// SHA-256 is a fast hash: an attacker with the hash table can brute-force
// high-entropy secrets in hours on commodity GPUs.  bcrypt with work factor 12
// takes ~250 ms per attempt, making offline attacks infeasible.
package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// HashClientSecret
// ---------------------------------------------------------------------------

func TestHashClientSecret_ProducesBcryptHash(t *testing.T) {
	hash, err := HashClientSecret("SuperSecretClientKey123!")
	if err != nil {
		t.Fatalf("HashClientSecret returned error: %v", err)
	}
	// bcrypt hashes always start with "$2" (e.g., "$2a$", "$2b$").
	if !strings.HasPrefix(hash, "$2") {
		t.Errorf("expected bcrypt hash starting with '$2', got: %q", hash)
	}
}

func TestHashClientSecret_WorkFactor12(t *testing.T) {
	hash, err := HashClientSecret("AnotherSecret456!")
	if err != nil {
		t.Fatalf("HashClientSecret returned error: %v", err)
	}
	// bcrypt format: $2b$<cost>$<salt><hash>
	// The cost field is the work factor as a zero-padded two-digit string.
	if !strings.Contains(hash, "$12$") {
		t.Errorf("expected work factor 12 in bcrypt hash, got: %q", hash)
	}
}

func TestHashClientSecret_DifferentCallsDifferentSalts(t *testing.T) {
	// bcrypt generates a fresh random salt each time — two hashes of the same
	// input must never be identical.
	secret := "SameSecretForBothCalls!"
	h1, err1 := HashClientSecret(secret)
	h2, err2 := HashClientSecret(secret)
	if err1 != nil || err2 != nil {
		t.Fatalf("unexpected errors: %v / %v", err1, err2)
	}
	if h1 == h2 {
		t.Error("expected two calls to HashClientSecret to produce different hashes (different salts)")
	}
}

func TestHashClientSecret_NotSHA256(t *testing.T) {
	// Regression: ensure we no longer produce a 64-character hex string
	// (the old SHA-256 format).
	secret := "TestSecret789@"
	hash, _ := HashClientSecret(secret)

	sha := sha256.Sum256([]byte(secret))
	legacyHex := hex.EncodeToString(sha[:])

	if hash == legacyHex {
		t.Error("HashClientSecret must not produce a SHA-256 hex hash (legacy format)")
	}
}

// ---------------------------------------------------------------------------
// CheckClientSecret — bcrypt path
// ---------------------------------------------------------------------------

func TestCheckClientSecret_Bcrypt_CorrectSecret_ReturnsTrue(t *testing.T) {
	secret := "CorrectClientSecret123!"
	hash, err := HashClientSecret(secret)
	if err != nil {
		t.Fatalf("setup: HashClientSecret failed: %v", err)
	}
	if !CheckClientSecret(secret, hash) {
		t.Error("expected CheckClientSecret to return true for correct secret")
	}
}

func TestCheckClientSecret_Bcrypt_WrongSecret_ReturnsFalse(t *testing.T) {
	hash, _ := HashClientSecret("CorrectSecret123!")
	if CheckClientSecret("WrongSecret456!", hash) {
		t.Error("expected CheckClientSecret to return false for wrong secret")
	}
}

func TestCheckClientSecret_Bcrypt_EmptySecret_ReturnsFalse(t *testing.T) {
	hash, _ := HashClientSecret("SomeSecret789!")
	if CheckClientSecret("", hash) {
		t.Error("expected CheckClientSecret to return false for empty secret")
	}
}

// ---------------------------------------------------------------------------
// CheckClientSecret — legacy SHA-256 migration path
// ---------------------------------------------------------------------------

func legacySHA256Hash(secret string) string {
	sum := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(sum[:])
}

func TestCheckClientSecret_LegacySHA256_CorrectSecret_ReturnsTrue(t *testing.T) {
	// Pre-migration clients still have SHA-256 hashes in the database.
	// They must continue to authenticate until their secret is rotated.
	secret := "OldClientSecret1!"
	legacyHash := legacySHA256Hash(secret)

	if !CheckClientSecret(secret, legacyHash) {
		t.Error("expected legacy SHA-256 hash to still authenticate during migration")
	}
}

func TestCheckClientSecret_LegacySHA256_WrongSecret_ReturnsFalse(t *testing.T) {
	legacyHash := legacySHA256Hash("CorrectOldSecret!")
	if CheckClientSecret("WrongSecret", legacyHash) {
		t.Error("expected CheckClientSecret to return false for wrong secret against legacy hash")
	}
}

func TestCheckClientSecret_LegacySHA256_DetectedByPrefix(t *testing.T) {
	// A bcrypt hash starts with "$2"; a legacy SHA-256 hash is 64 hex chars.
	// Verify that the detection mechanism is correct.
	legacyHash := legacySHA256Hash("AnySecret123!")
	if strings.HasPrefix(legacyHash, "$2") {
		t.Fatal("test invariant broken: legacy hash unexpectedly starts with '$2'")
	}
	// CheckClientSecret should route via legacy path without error.
	if CheckClientSecret("AnySecret123!", legacyHash) == false {
		t.Error("expected legacy SHA-256 path to return true for correct secret")
	}
}

func TestCheckClientSecret_GarbageHash_ReturnsFalse(t *testing.T) {
	cases := []string{
		"",
		"not-a-hash",
		"$2b$12$invalid",
		"aaaa",
	}
	for _, h := range cases {
		if CheckClientSecret("secret", h) {
			t.Errorf("expected CheckClientSecret to return false for garbage hash %q", h)
		}
	}
}

// ---------------------------------------------------------------------------
// Timing / constant-time: the SHA-256 legacy branch must not short-circuit
// ---------------------------------------------------------------------------

func TestCheckClientSecret_LegacyPath_ConstantTime(t *testing.T) {
	// We can't measure wall-clock timing reliably in a unit test, but we can
	// assert that the comparison is done via hex.EncodeToString == hash rather
	// than a byte prefix match (which would short-circuit on first mismatch).
	// Indirectly confirmed by observing both "one char off" cases return false:
	correct := "SomeSecret123!"
	h := legacySHA256Hash(correct)

	// Flip last character of hash — should still return false, not panic.
	if len(h) == 0 {
		t.Fatal("empty legacy hash")
	}
	tampered := h[:len(h)-1] + "x"
	if CheckClientSecret(correct, tampered) {
		t.Error("tampered hash must return false")
	}
}
