package auth

import (
	"github.com/golang-jwt/jwt/v5"
)

// Signer abstracts the JWT signing operation so that the signing backend can be
// replaced — for example with a KMS/HSM-backed implementation in which the
// private key never leaves the cryptographic boundary — without changing
// TokenService or any token-generation code.
//
// This is the "adapters before replacements" seam for RFC-002 (KMS Signing &
// Key Rotation), capability C3 / EPIC-3. It abstracts *signing only*: public-key
// verification continues to be served from the local key ring and the JWKS
// endpoint via KeyManager. Introducing the seam is intentionally behaviour-
// preserving; substituting a KMS-backed Signer is a later, separate change.
type Signer interface {
	// SignToken signs the provided claims and returns a compact JWS (JWT) string.
	// Implementations are responsible for selecting the signing key and setting
	// the "kid" header so that the matching public key can be located during
	// verification.
	SignToken(claims jwt.Claims) (string, error)

	// KeyID returns the identifier of the current active signing key. It MUST
	// match the "kid" header that SignToken writes onto issued tokens.
	KeyID() string

	// Algorithm returns the JWS "alg" identifier used for signing (e.g. "RS256").
	Algorithm() string
}

// localSigner is the default Signer implementation. It signs with the RSA
// private key held in process by the KeyManager, preserving the exact behaviour
// (RS256 signature + "kid" header sourced from the KeyManager) used before the
// Signer seam was introduced.
type localSigner struct {
	keyManager *KeyManager
}

// NewLocalSigner returns a Signer backed by the in-process RSA key managed by
// the given KeyManager. This is the default signer used by NewTokenService.
func NewLocalSigner(keyManager *KeyManager) Signer {
	return &localSigner{keyManager: keyManager}
}

// SignToken signs the claims with RS256 using the KeyManager's current private
// key and stamps the active key id into the "kid" header.
func (s *localSigner) SignToken(claims jwt.Claims) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	token.Header["kid"] = s.keyManager.GetKeyID()

	return token.SignedString(s.keyManager.GetPrivateKey())
}

// KeyID returns the KeyManager's current active key id.
func (s *localSigner) KeyID() string {
	return s.keyManager.GetKeyID()
}

// Algorithm returns the JWS "alg" used by this signer ("RS256").
func (s *localSigner) Algorithm() string {
	return jwt.SigningMethodRS256.Alg()
}
