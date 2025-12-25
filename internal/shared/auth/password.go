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

// ValidatePassword checks if a password meets the security requirements
func ValidatePassword(password string) error {
	if len(password) < 12 {
		return ErrPasswordTooShort
	}
	if len(password) > 72 {
		return ErrPasswordTooLong
	}

	hasLower := regexp.MustCompile(`[a-z]`).MatchString(password)
	if !hasLower {
		return ErrPasswordNoLowercase
	}

	hasUpper := regexp.MustCompile(`[A-Z]`).MatchString(password)
	if !hasUpper {
		return ErrPasswordNoUppercase
	}

	hasDigit := regexp.MustCompile(`[0-9]`).MatchString(password)
	if !hasDigit {
		return ErrPasswordNoDigit
	}

	hasSpecial := regexp.MustCompile(`[!@#$%^&*(),.?":{}|<>_\-+=\[\]\\;'/~\x60]`).MatchString(password)
	if !hasSpecial {
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

// HashClientSecret hashes a client secret using SHA-256
func HashClientSecret(secret string) string {
	hash := sha256.Sum256([]byte(secret))
	return hex.EncodeToString(hash[:])
}

// CheckClientSecret compares a client secret with its hash
func CheckClientSecret(secret, hash string) bool {
	computed := HashClientSecret(secret)
	return computed == hash
}
