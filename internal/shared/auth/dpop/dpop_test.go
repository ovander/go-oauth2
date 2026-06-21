package dpop

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// newKey returns a fresh P-256 key and its public JWK map.
func newKey(t *testing.T) (*ecdsa.PrivateKey, map[string]interface{}) {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	jwk := map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(leftPad(k.X.Bytes(), 32)),
		"y":   base64.RawURLEncoding.EncodeToString(leftPad(k.Y.Bytes(), 32)),
	}
	return k, jwk
}

// makeProof builds a signed DPoP proof with the given header/claim overrides.
func makeProof(t *testing.T, key *ecdsa.PrivateKey, jwk map[string]interface{}, htm, htu string, iat time.Time, jti string) string {
	t.Helper()
	claims := &proofClaims{
		HTM: htm,
		HTU: htu,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:       jti,
			IssuedAt: jwt.NewNumericDate(iat),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["typ"] = headerTyp
	if jwk != nil {
		tok.Header["jwk"] = jwk
	}
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

const (
	testHTM = "POST"
	testHTU = "https://id.example.com/oauth/token"
)

func TestVerify_Success(t *testing.T) {
	key, jwk := newKey(t)
	now := time.Now()
	proof := makeProof(t, key, jwk, testHTM, testHTU, now, "jti-1")

	p, err := Verify(proof, testHTM, testHTU, now)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if p.JTI != "jti-1" || p.HTM != testHTM || p.HTU != testHTU {
		t.Fatalf("unexpected proof: %+v", p)
	}
	if p.Thumbprint == "" {
		t.Fatal("expected a thumbprint")
	}
}

func TestVerify_ThumbprintStableAndKeySpecific(t *testing.T) {
	key, jwk := newKey(t)
	now := time.Now()

	p1, _ := Verify(makeProof(t, key, jwk, testHTM, testHTU, now, "a"), testHTM, testHTU, now)
	p2, _ := Verify(makeProof(t, key, jwk, testHTM, testHTU, now, "b"), testHTM, testHTU, now)
	if p1.Thumbprint != p2.Thumbprint {
		t.Fatal("thumbprint must be stable for the same key")
	}

	key2, jwk2 := newKey(t)
	p3, _ := Verify(makeProof(t, key2, jwk2, testHTM, testHTU, now, "c"), testHTM, testHTU, now)
	if p3.Thumbprint == p1.Thumbprint {
		t.Fatal("different keys must yield different thumbprints")
	}
}

func TestVerify_MethodMismatch(t *testing.T) {
	key, jwk := newKey(t)
	now := time.Now()
	proof := makeProof(t, key, jwk, "GET", testHTU, now, "j")
	if _, err := Verify(proof, "POST", testHTU, now); !errors.Is(err, ErrMethodMismatch) {
		t.Fatalf("want ErrMethodMismatch, got %v", err)
	}
}

func TestVerify_URIMismatch(t *testing.T) {
	key, jwk := newKey(t)
	now := time.Now()
	proof := makeProof(t, key, jwk, testHTM, "https://id.example.com/other", now, "j")
	if _, err := Verify(proof, testHTM, testHTU, now); !errors.Is(err, ErrURIMismatch) {
		t.Fatalf("want ErrURIMismatch, got %v", err)
	}
}

func TestVerify_URIIgnoresQueryAndFragmentAndCase(t *testing.T) {
	key, jwk := newKey(t)
	now := time.Now()
	// Proof htu carries query+fragment and upper-case host; the request URI is
	// the canonical form. They must still match.
	proof := makeProof(t, key, jwk, testHTM, "https://ID.EXAMPLE.com/oauth/token?x=1#frag", now, "j")
	if _, err := Verify(proof, testHTM, testHTU, now); err != nil {
		t.Fatalf("expected match ignoring query/fragment/case, got %v", err)
	}
}

func TestVerify_StaleIat(t *testing.T) {
	key, jwk := newKey(t)
	now := time.Now()
	proof := makeProof(t, key, jwk, testHTM, testHTU, now.Add(-2*MaxAge), "j")
	if _, err := Verify(proof, testHTM, testHTU, now); !errors.Is(err, ErrStale) {
		t.Fatalf("want ErrStale, got %v", err)
	}
}

func TestVerify_FutureIat(t *testing.T) {
	key, jwk := newKey(t)
	now := time.Now()
	proof := makeProof(t, key, jwk, testHTM, testHTU, now.Add(30*time.Second), "j")
	if _, err := Verify(proof, testHTM, testHTU, now); !errors.Is(err, ErrStale) {
		t.Fatalf("want ErrStale for a future iat, got %v", err)
	}
}

func TestVerify_WithinLeeway(t *testing.T) {
	key, jwk := newKey(t)
	now := time.Now()
	// A proof a hair in the future (within leeway) is accepted.
	proof := makeProof(t, key, jwk, testHTM, testHTU, now.Add(3*time.Second), "j")
	if _, err := Verify(proof, testHTM, testHTU, now); err != nil {
		t.Fatalf("expected acceptance within leeway, got %v", err)
	}
}

func TestVerify_MissingJTI(t *testing.T) {
	key, jwk := newKey(t)
	now := time.Now()
	proof := makeProof(t, key, jwk, testHTM, testHTU, now, "")
	if _, err := Verify(proof, testHTM, testHTU, now); !errors.Is(err, ErrClaimMissing) {
		t.Fatalf("want ErrClaimMissing, got %v", err)
	}
}

func TestVerify_TamperedSignature(t *testing.T) {
	key, jwk := newKey(t)
	now := time.Now()
	proof := makeProof(t, key, jwk, testHTM, testHTU, now, "j")
	// Flip the last character of the signature segment.
	b := []byte(proof)
	b[len(b)-1] ^= 0x01
	if _, err := Verify(string(b), testHTM, testHTU, now); err == nil {
		t.Fatal("expected verification to fail for a tampered proof")
	}
}

func TestVerify_SignatureFromDifferentKey(t *testing.T) {
	signing, _ := newKey(t)
	_, otherJWK := newKey(t) // advertise a different public key than the signer
	now := time.Now()
	proof := makeProof(t, signing, otherJWK, testHTM, testHTU, now, "j")
	if _, err := Verify(proof, testHTM, testHTU, now); !errors.Is(err, ErrSignature) {
		t.Fatalf("want ErrSignature when jwk does not match signer, got %v", err)
	}
}

func TestVerify_MissingJWK(t *testing.T) {
	key, _ := newKey(t)
	now := time.Now()
	proof := makeProof(t, key, nil, testHTM, testHTU, now, "j")
	if _, err := Verify(proof, testHTM, testHTU, now); !errors.Is(err, ErrMissingJWK) {
		t.Fatalf("want ErrMissingJWK, got %v", err)
	}
}

func TestVerify_RejectsPrivateKeyInJWK(t *testing.T) {
	key, jwk := newKey(t)
	jwk["d"] = base64.RawURLEncoding.EncodeToString(key.D.Bytes()) // leak private param
	now := time.Now()
	proof := makeProof(t, key, jwk, testHTM, testHTU, now, "j")
	if _, err := Verify(proof, testHTM, testHTU, now); !errors.Is(err, ErrInvalidJWK) {
		t.Fatalf("want ErrInvalidJWK when jwk carries a private key, got %v", err)
	}
}

func TestVerify_WrongTyp(t *testing.T) {
	key, jwk := newKey(t)
	now := time.Now()
	claims := &proofClaims{HTM: testHTM, HTU: testHTU, RegisteredClaims: jwt.RegisteredClaims{ID: "j", IssuedAt: jwt.NewNumericDate(now)}}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["typ"] = "JWT" // wrong
	tok.Header["jwk"] = jwk
	s, _ := tok.SignedString(key)
	if _, err := Verify(s, testHTM, testHTU, now); !errors.Is(err, ErrInvalidTyp) {
		t.Fatalf("want ErrInvalidTyp, got %v", err)
	}
}

func TestVerify_RejectsNonES256(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("rsa: %v", err)
	}
	now := time.Now()
	claims := &proofClaims{HTM: testHTM, HTU: testHTU, RegisteredClaims: jwt.RegisteredClaims{ID: "j", IssuedAt: jwt.NewNumericDate(now)}}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["typ"] = headerTyp
	s, _ := tok.SignedString(rsaKey)
	if _, err := Verify(s, testHTM, testHTU, now); !errors.Is(err, ErrUnsupportedAlg) {
		t.Fatalf("want ErrUnsupportedAlg for RS256, got %v", err)
	}
}

func TestVerify_Malformed(t *testing.T) {
	now := time.Now()
	if _, err := Verify("not-a-jwt", testHTM, testHTU, now); err == nil {
		t.Fatal("expected an error for a malformed proof")
	}
}
