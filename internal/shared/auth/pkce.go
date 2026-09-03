package auth

import (
	"crypto/sha256"
	"encoding/base64"
	"errors"
)

var (
	ErrInvalidCodeVerifier    = errors.New("invalid code verifier")
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
		// SHA-256 hash of the code verifier, base64url-encoded (RFC 7636 §4.2).
		hash := sha256.Sum256([]byte(codeVerifier))
		computed := base64.RawURLEncoding.EncodeToString(hash[:])
		if computed != codeChallenge {
			return ErrPKCEVerificationFailed
		}
	case "":
		// P3-4: a stored challenge with no method used to be compared verbatim
		// against the verifier — i.e. "plain" PKCE by omission, which the
		// explicit "plain" branch below rejects. Authorize now refuses to store
		// a challenge without S256, so an empty method here is a malformed
		// code, never a legitimate no-PKCE flow (that case returned above when
		// both verifier and challenge were empty).
		return ErrInvalidChallengeMethod
	case "plain":
		// H-02 fix: "plain" is explicitly rejected.  With plain PKCE the
		// code_verifier equals the code_challenge, so an attacker who can
		// intercept the authorisation request obtains the verifier for free —
		// providing zero additional security over no PKCE at all.
		return ErrInvalidChallengeMethod
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
