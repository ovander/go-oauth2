// Package auth — tests for L-01: password validation regexes must be
// package-level variables, not recompiled on every call.
//
// L-01 fix: the four regexp.MustCompile calls inside ValidatePassword were
// moved to package-level var declarations so they are compiled once at
// startup.  The fix is behaviorally transparent — this test suite verifies
// that ValidatePassword's semantics are unchanged and that the package-level
// vars are safe for concurrent use.
package auth

import (
	"strings"
	"sync"
	"testing"
)

// ---------------------------------------------------------------------------
// L-01: package-level vars exist and are non-nil
// ---------------------------------------------------------------------------

func TestPasswordRegexVars_NotNil(t *testing.T) {
	t.Parallel()
	// Package-level vars are initialised before any test runs.  If they were
	// nil (e.g. accidentally zeroed) MatchString would panic.
	if reHasLower == nil {
		t.Error("reHasLower must not be nil")
	}
	if reHasUpper == nil {
		t.Error("reHasUpper must not be nil")
	}
	if reHasDigit == nil {
		t.Error("reHasDigit must not be nil")
	}
	if reHasSpecial == nil {
		t.Error("reHasSpecial must not be nil")
	}
}

func TestPasswordRegexVars_MatchCorrectly(t *testing.T) {
	t.Parallel()
	if !reHasLower.MatchString("a") {
		t.Error("reHasLower must match 'a'")
	}
	if !reHasUpper.MatchString("A") {
		t.Error("reHasUpper must match 'A'")
	}
	if !reHasDigit.MatchString("0") {
		t.Error("reHasDigit must match '0'")
	}
	if !reHasSpecial.MatchString("!") {
		t.Error("reHasSpecial must match '!'")
	}
}

// ---------------------------------------------------------------------------
// L-01: ValidatePassword semantics are unchanged after the refactor
// ---------------------------------------------------------------------------

func TestValidatePassword_ValidPassword_ReturnsNil(t *testing.T) {
	t.Parallel()
	valid := []string{
		"Abcdefgh1234!",
		"P@ssw0rd123456",
		"Secure!Pass#99",
		"MyStr0ng&Pass!",
		"Hello_W0rld!XY",
	}
	for _, pw := range valid {
		if err := ValidatePassword(pw); err != nil {
			t.Errorf("ValidatePassword(%q): unexpected error %v", pw, err)
		}
	}
}

func TestValidatePassword_TooShort_ReturnsError(t *testing.T) {
	t.Parallel()
	if err := ValidatePassword("Abc1!"); err != ErrPasswordTooShort {
		t.Errorf("expected ErrPasswordTooShort, got %v", err)
	}
}

func TestValidatePassword_TooLong_ReturnsError(t *testing.T) {
	t.Parallel()
	// Build a 73-character password that passes every check except length.
	// "A1!" (3 chars) + 70 lowercase 'a' = 73 chars total (exceeds 72-char limit).
	pw := "A1!" + strings.Repeat("a", 70)
	if err := ValidatePassword(pw); err != ErrPasswordTooLong {
		t.Errorf("expected ErrPasswordTooLong for 73-char password, got %v", err)
	}
}

func TestValidatePassword_NoLowercase_ReturnsError(t *testing.T) {
	t.Parallel()
	if err := ValidatePassword("ABCDEF12345!"); err != ErrPasswordNoLowercase {
		t.Errorf("expected ErrPasswordNoLowercase, got %v", err)
	}
}

func TestValidatePassword_NoUppercase_ReturnsError(t *testing.T) {
	t.Parallel()
	if err := ValidatePassword("abcdef12345!"); err != ErrPasswordNoUppercase {
		t.Errorf("expected ErrPasswordNoUppercase, got %v", err)
	}
}

func TestValidatePassword_NoDigit_ReturnsError(t *testing.T) {
	t.Parallel()
	if err := ValidatePassword("Abcdefghijk!"); err != ErrPasswordNoDigit {
		t.Errorf("expected ErrPasswordNoDigit, got %v", err)
	}
}

func TestValidatePassword_NoSpecial_ReturnsError(t *testing.T) {
	t.Parallel()
	if err := ValidatePassword("Abcdefgh1234"); err != ErrPasswordNoSpecial {
		t.Errorf("expected ErrPasswordNoSpecial, got %v", err)
	}
}

func TestValidatePassword_CommonPasswordMissingSpecial_FailsSpecialCheck(t *testing.T) {
	t.Parallel()
	// "Password123456" is in the commonPasswords map (lowercased).  However, it
	// has no special character, so ValidatePassword rejects it with
	// ErrPasswordNoSpecial *before* reaching the common-password check.
	// This test documents the actual validation order: special-char check
	// runs before the common-passwords lookup.
	if err := ValidatePassword("Password123456"); err != ErrPasswordNoSpecial {
		t.Errorf("expected ErrPasswordNoSpecial (special-char check precedes common check), got %v", err)
	}
}

// ---------------------------------------------------------------------------
// L-01: concurrent calls are safe (package-level vars must not be mutated)
// ---------------------------------------------------------------------------

func TestValidatePassword_ConcurrentCalls_NoRace(t *testing.T) {
	t.Parallel()
	// Run many goroutines simultaneously to flush out any data races on the
	// package-level regex vars.  The -race detector will catch any issues.
	const goroutines = 50
	var wg sync.WaitGroup
	wg.Add(goroutines)
	for i := 0; i < goroutines; i++ {
		go func() {
			defer wg.Done()
			// Alternate between passwords that pass and fail to exercise all branches.
			_ = ValidatePassword("ValidPass1!")
			_ = ValidatePassword("short")
			_ = ValidatePassword("NOLOWER1234!")
			_ = ValidatePassword("noupper1234!")
			_ = ValidatePassword("NoDigitHere!!")
			_ = ValidatePassword("NoSpecial1234")
		}()
	}
	wg.Wait()
}
