package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

var (
	ErrInvalidCodeVerifier = errors.New("invalid code verifier")
	ErrInvalidChallengeMethod = errors.New("invalid code challenge method")
	ErrPKCEVerificationFailed = errors.New("PKCE verification failed")
)

// VerifyPKCE verifies the code verifier against the code challenge
func VerifyPKCE(codeVerifier, codeChallenge, codeChallengeMethod string) error {
	if codeVerifier == "" {
		if codeChallenge != "" {
			return ErrInvalidCodeVerifier
		}
		// No PKCE used, that's fine
		return nil
	}

	if codeChallenge == "" {
		return ErrInvalidCodeVerifier
	}

	switch codeChallengeMethod {
	case "S256":
		// SHA-256 hash of the code verifier
		hash := sha256.Sum256([]byte(codeVerifier))
		computed := base64.RawURLEncoding.EncodeToString(hash[:])
		if computed != codeChallenge {
			return ErrPKCEVerificationFailed
		}
	case "plain", "":
		// Plain comparison
		if codeVerifier != codeChallenge {
			return ErrPKCEVerificationFailed
		}
	default:
		return ErrInvalidChallengeMethod
	}

	return nil
}

// GenerateCodeChallenge generates a code challenge from a verifier using S256 method
func GenerateCodeChallenge(codeVerifier string) string {
	hash := sha256.Sum256([]byte(codeVerifier))
	return base64.RawURLEncoding.EncodeToString(hash[:])
}
