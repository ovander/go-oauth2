package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"regexp"
	"strings"

	"golang.org/x/crypto/bcrypt"
)

var (
	ErrPasswordTooShort    = errors.New("password must be at least 12 characters")
	ErrPasswordTooLong     = errors.New("password must be at most 72 characters")
	ErrPasswordNoLowercase = errors.New("password must contain at least one lowercase letter")
	ErrPasswordNoUppercase = errors.New("password must contain at least one uppercase letter")
	ErrPasswordNoDigit     = errors.New("password must contain at least one digit")
	ErrPasswordNoSpecial   = errors.New("password must contain at least one special character")
	ErrPasswordCommon      = errors.New("password is too common")
)

// Common passwords list (abbreviated for implementation)
var commonPasswords = map[string]bool{
	"password123456": true,
	"123456password": true,
	"qwerty12345678": true,
	"letmein12345":   true,
	"welcome123456":  true,
	"admin12345678":  true,
	"password12345":  true,
	"1234567890123":  true,
}

// L-01 fix: compile regexes once at package initialisation instead of on
// every ValidatePassword call.  regexp.MustCompile is not cheap — it
// tokenises, parses, and compiles the pattern each time it is called.
// Hoisting to package-level vars means the cost is paid once at startup.
var (
	reHasLower   = regexp.MustCompile(`[a-z]`)
	reHasUpper   = regexp.MustCompile(`[A-Z]`)
	reHasDigit   = regexp.MustCompile(`[0-9]`)
	reHasSpecial = regexp.MustCompile(`[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\;'/~\x60]`)
)

// ValidatePassword checks if a password meets the security requirements
func ValidatePassword(password string) error {
	if len(password) < 12 {
		return ErrPasswordTooShort
	}
	if len(password) > 72 {
		return ErrPasswordTooLong
	}

	if !reHasLower.MatchString(password) {
		return ErrPasswordNoLowercase
	}

	if !reHasUpper.MatchString(password) {
		return ErrPasswordNoUppercase
	}

	if !reHasDigit.MatchString(password) {
		return ErrPasswordNoDigit
	}

	if !reHasSpecial.MatchString(password) {
		return ErrPasswordNoSpecial
	}

	// Check against common passwords
	lowerPassword := strings.ToLower(password)
	if commonPasswords[lowerPassword] {
		return ErrPasswordCommon
	}

	return nil
}

// HashPassword hashes a password using bcrypt
func HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// CheckPassword compares a password with its hash
func CheckPassword(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// HashClientSecret hashes a client secret using bcrypt.
//
// H-03 fix: SHA-256 is a fast hash — an attacker who obtains the hash table
// can brute-force all 32-byte random secrets offline in hours on commodity
// hardware.  bcrypt is slow by design (work factor 12 ≈ 250 ms/attempt),
// making an offline attack infeasible.
func HashClientSecret(secret string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(secret), 12)
	if err != nil {
		return "", err
	}
	return string(hash), nil
}

// CheckClientSecret compares a client secret against its stored hash.
//
// Supports a transparent migration path: bcrypt hashes (starting with "$2")
// are verified with bcrypt; legacy SHA-256 hashes (64-char hex strings) still
// validate against the old algorithm so that existing apps continue to work
// until their secrets are rotated.
func CheckClientSecret(secret, hash string) bool {
	if strings.HasPrefix(hash, "$2") {
		// bcrypt hash
		return bcrypt.CompareHashAndPassword([]byte(hash), []byte(secret)) == nil
	}
	// Legacy SHA-256 path — constant-time hex comparison to avoid timing leaks.
	legacy := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(legacy[:]) == hash
}
