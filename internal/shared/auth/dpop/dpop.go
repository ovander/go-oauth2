// Package dpop implements verification of DPoP proof JWTs (RFC 9449) — the
// sender-constraining mechanism for OAuth 2.0 access tokens (EPIC-8 / RFC-003).
//
// A DPoP proof is a JWT, signed by the client's private key, that a client
// attaches (in the `DPoP` header) to a token request or a resource request. The
// proof embeds the client's public key (`jwk` header) and binds the request via
// the `htm` (method) and `htu` (URL) claims plus a unique `jti` and a fresh
// `iat`. Verify validates all of this and returns the JWK SHA-256 thumbprint
// (RFC 7638) — the `jkt` value the authorization server places in the token's
// `cnf` claim to bind the token to this key.
//
// This package is the standalone verification primitive; wiring it into the
// token endpoint (issue `cnf.jkt`) and resource path (require a matching proof)
// are separate slices. It intentionally supports only ES256 (the
// RFC-recommended, most widely deployed DPoP algorithm); other algorithms are
// rejected rather than silently accepted.
package dpop

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/url"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Verification errors.
var (
	ErrMalformed      = errors.New("dpop: malformed proof")
	ErrInvalidTyp     = errors.New("dpop: header typ must be dpop+jwt")
	ErrUnsupportedAlg = errors.New("dpop: unsupported algorithm (want ES256)")
	ErrMissingJWK     = errors.New("dpop: missing or invalid embedded jwk")
	ErrInvalidJWK     = errors.New("dpop: invalid jwk")
	ErrSignature      = errors.New("dpop: signature verification failed")
	ErrClaimMissing   = errors.New("dpop: required claim missing (htm/htu/jti/iat)")
	ErrMethodMismatch = errors.New("dpop: htm does not match the request method")
	ErrURIMismatch    = errors.New("dpop: htu does not match the request URI")
	ErrStale          = errors.New("dpop: iat is outside the acceptable window")
)

const (
	// headerTyp is the required JOSE `typ` for a DPoP proof.
	headerTyp = "dpop+jwt"
	// MaxAge is how old a proof's iat may be (replay window upper bound).
	MaxAge = 60 * time.Second
	// leeway tolerates small clock skew when checking iat.
	leeway = 5 * time.Second
)

// Proof holds the validated, security-relevant content of a DPoP proof.
type Proof struct {
	// JTI is the proof's unique identifier (callers should track it to reject
	// replays within the acceptance window; this package does not store state).
	JTI string
	// HTM / HTU are the bound HTTP method and URI.
	HTM string
	HTU string
	// IssuedAt is the proof's iat.
	IssuedAt time.Time
	// Thumbprint is the RFC 7638 JWK SHA-256 thumbprint (base64url, no padding)
	// — the `jkt` value used to bind an access token to this key.
	Thumbprint string
	// PublicKey is the client's verified public key from the embedded jwk.
	PublicKey *ecdsa.PublicKey
}

// proofClaims are the DPoP-specific claims plus the registered iat/jti.
type proofClaims struct {
	HTM string `json:"htm"`
	HTU string `json:"htu"`
	jwt.RegisteredClaims
}

// Verify validates a DPoP proof JWT against the HTTP method (htm) and URI (htu)
// of the request it accompanies, at time now. On success it returns the parsed
// proof, including the JWK thumbprint. It does not perform replay detection
// (jti bookkeeping) — that is the caller's responsibility.
func Verify(proofJWT, htm, htu string, now time.Time) (*Proof, error) {
	claims := &proofClaims{}
	var pub *ecdsa.PublicKey

	parser := jwt.NewParser(jwt.WithValidMethods([]string{"ES256"}))
	_, err := parser.ParseWithClaims(proofJWT, claims, func(t *jwt.Token) (interface{}, error) {
		if typ, _ := t.Header["typ"].(string); !strings.EqualFold(typ, headerTyp) {
			return nil, ErrInvalidTyp
		}
		raw, ok := t.Header["jwk"].(map[string]interface{})
		if !ok {
			return nil, ErrMissingJWK
		}
		key, perr := parseECPublicKey(raw)
		if perr != nil {
			return nil, perr
		}
		pub = key
		return pub, nil
	})
	if err != nil {
		return nil, mapParseError(err)
	}

	// Required claims.
	if claims.HTM == "" || claims.HTU == "" || claims.ID == "" || claims.IssuedAt == nil {
		return nil, ErrClaimMissing
	}
	// Binding to the request.
	if !strings.EqualFold(claims.HTM, htm) {
		return nil, ErrMethodMismatch
	}
	if !sameURI(claims.HTU, htu) {
		return nil, ErrURIMismatch
	}
	// Freshness: not from the future (beyond leeway) and not older than MaxAge.
	iat := claims.IssuedAt.Time
	if iat.After(now.Add(leeway)) || now.Sub(iat) > MaxAge {
		return nil, ErrStale
	}

	thumb, err := thumbprint(pub)
	if err != nil {
		return nil, err
	}
	return &Proof{
		JTI:        claims.ID,
		HTM:        claims.HTM,
		HTU:        claims.HTU,
		IssuedAt:   iat,
		Thumbprint: thumb,
		PublicKey:  pub,
	}, nil
}

// mapParseError translates golang-jwt parse failures (and the sentinel errors
// returned from the keyfunc) into this package's sentinels.
func mapParseError(err error) error {
	for _, s := range []error{ErrInvalidTyp, ErrMissingJWK, ErrInvalidJWK} {
		if errors.Is(err, s) {
			return s
		}
	}
	switch {
	case strings.Contains(err.Error(), "signing method"):
		// golang-jwt's WithValidMethods rejection (wraps ErrTokenSignatureInvalid).
		return ErrUnsupportedAlg
	case errors.Is(err, jwt.ErrTokenSignatureInvalid):
		return ErrSignature
	case errors.Is(err, jwt.ErrTokenMalformed):
		return ErrMalformed
	default:
		return fmt.Errorf("%w: %v", ErrMalformed, err)
	}
}

// parseECPublicKey builds a P-256 public key from a JWK map, rejecting anything
// that is not a public EC P-256 key (and any key carrying a private `d`).
func parseECPublicKey(m map[string]interface{}) (*ecdsa.PublicKey, error) {
	kty, _ := m["kty"].(string)
	crv, _ := m["crv"].(string)
	if kty != "EC" || crv != "P-256" {
		return nil, fmt.Errorf("%w: want EC/P-256", ErrInvalidJWK)
	}
	if _, hasPriv := m["d"]; hasPriv {
		return nil, fmt.Errorf("%w: jwk must not contain a private key", ErrInvalidJWK)
	}
	xs, _ := m["x"].(string)
	ys, _ := m["y"].(string)
	if xs == "" || ys == "" {
		return nil, fmt.Errorf("%w: missing x/y", ErrInvalidJWK)
	}
	xb, err := base64.RawURLEncoding.DecodeString(xs)
	if err != nil {
		return nil, fmt.Errorf("%w: bad x", ErrInvalidJWK)
	}
	yb, err := base64.RawURLEncoding.DecodeString(ys)
	if err != nil {
		return nil, fmt.Errorf("%w: bad y", ErrInvalidJWK)
	}
	x := new(big.Int).SetBytes(xb)
	y := new(big.Int).SetBytes(yb)
	if !elliptic.P256().IsOnCurve(x, y) {
		return nil, fmt.Errorf("%w: point not on P-256", ErrInvalidJWK)
	}
	return &ecdsa.PublicKey{Curve: elliptic.P256(), X: x, Y: y}, nil
}

// thumbprint computes the RFC 7638 JWK SHA-256 thumbprint of an EC P-256 public
// key. The required members are serialized in lexicographic order with no
// whitespace ({"crv","kty","x","y"}) and the coordinates are fixed 32-byte
// big-endian, so the value is canonical regardless of the proof's own encoding.
func thumbprint(pub *ecdsa.PublicKey) (string, error) {
	canonical := map[string]string{
		"crv": "P-256",
		"kty": "EC",
		"x":   base64.RawURLEncoding.EncodeToString(leftPad(pub.X.Bytes(), 32)),
		"y":   base64.RawURLEncoding.EncodeToString(leftPad(pub.Y.Bytes(), 32)),
	}
	// encoding/json marshals map keys in sorted order, matching RFC 7638.
	b, err := json.Marshal(canonical)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// leftPad returns b left-padded with zero bytes to exactly size bytes.
func leftPad(b []byte, size int) []byte {
	if len(b) >= size {
		return b
	}
	out := make([]byte, size)
	copy(out[size-len(b):], b)
	return out
}

// sameURI compares two HTTP URIs for DPoP htu purposes: scheme and host are
// compared case-insensitively and the query and fragment are ignored (RFC 9449
// §4.3); the path is compared exactly.
func sameURI(a, b string) bool {
	ua, erra := url.Parse(a)
	ub, errb := url.Parse(b)
	if erra != nil || errb != nil {
		return false
	}
	return strings.EqualFold(ua.Scheme, ub.Scheme) &&
		strings.EqualFold(ua.Host, ub.Host) &&
		ua.Path == ub.Path
}
