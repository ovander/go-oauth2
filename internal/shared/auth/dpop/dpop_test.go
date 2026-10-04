package dpop

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
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
	x, y, err := p256Coordinates(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	jwk := map[string]interface{}{
		"kty": "EC",
		"crv": "P-256",
		"x":   base64.RawURLEncoding.EncodeToString(x),
		"y":   base64.RawURLEncoding.EncodeToString(y),
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
	d, err := key.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	jwk["d"] = base64.RawURLEncoding.EncodeToString(d) // leak private param
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

// jwkWith returns a P-256 JWK with the given raw coordinate bytes.
func jwkWith(x, y []byte) map[string]interface{} {
	return map[string]interface{}{
		"kty": "EC", "crv": "P-256",
		"x": base64.RawURLEncoding.EncodeToString(x),
		"y": base64.RawURLEncoding.EncodeToString(y),
	}
}

// The key in a proof's header is attacker-chosen. Whatever it is, the parser
// must accept only real P-256 points — an off-curve point is the classic
// invalid-curve input.
func TestParseECPublicKey_RejectsInvalidPoints(t *testing.T) {
	k, _ := newKey(t)
	x, y, err := p256Coordinates(&k.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	offCurve := append([]byte(nil), y...)
	offCurve[31] ^= 0x01

	// p itself: a coordinate that is not a field element.
	p := elliptic.P256().Params().P.Bytes()

	cases := map[string]map[string]interface{}{
		"off-curve point":        jwkWith(x, offCurve),
		"point at infinity":      jwkWith(make([]byte, 32), make([]byte, 32)),
		"x equal to the modulus": jwkWith(p, y),
		"33-byte coordinate":     jwkWith(append([]byte{0}, x...), y),
	}
	for name, jwk := range cases {
		if _, err := parseECPublicKey(jwk); !errors.Is(err, ErrInvalidJWK) {
			t.Errorf("%s: err = %v, want ErrInvalidJWK", name, err)
		}
	}

	if pub, err := parseECPublicKey(jwkWith(x, y)); err != nil || !pub.Equal(&k.PublicKey) {
		t.Fatalf("valid key: pub=%v err=%v", pub, err)
	}
}

// A coordinate with its leading zero byte dropped names the same point. It is
// accepted, and — the part that matters — binds to the same thumbprint as the
// canonical encoding, so the lenient parse cannot change a token's binding.
func TestParseECPublicKey_ShortCoordinate_SameThumbprint(t *testing.T) {
	var x, y []byte
	for {
		k, _ := newKey(t)
		var err error
		if x, y, err = p256Coordinates(&k.PublicKey); err != nil {
			t.Fatal(err)
		}
		if x[0] == 0 { // ~1 key in 256 has a leading zero byte
			break
		}
	}
	short, err := parseECPublicKey(jwkWith(bytes.TrimLeft(x, "\x00"), y))
	if err != nil {
		t.Fatalf("short coordinate rejected: %v", err)
	}
	full, err := parseECPublicKey(jwkWith(x, y))
	if err != nil {
		t.Fatal(err)
	}
	ts, _ := thumbprint(short)
	tf, _ := thumbprint(full)
	if ts != tf {
		t.Fatalf("thumbprints differ: %s vs %s", ts, tf)
	}
}

// RFC 7638 thumbprint of a fixed P-256 key (RFC 7517 Appendix A.1), computed
// independently from its canonical JSON: the coordinates read through
// ecdsa.PublicKey.Bytes() bind tokens exactly as before.
func TestThumbprint_KnownKey(t *testing.T) {
	const x, y = "MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4", "4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM"
	pub, err := parseECPublicKey(map[string]interface{}{"kty": "EC", "crv": "P-256", "x": x, "y": y})
	if err != nil {
		t.Fatal(err)
	}
	got, err := thumbprint(pub)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(`{"crv":"P-256","kty":"EC","x":"` + x + `","y":"` + y + `"}`))
	if want := base64.RawURLEncoding.EncodeToString(sum[:]); got != want {
		t.Fatalf("thumbprint = %s, want %s", got, want)
	}
}
