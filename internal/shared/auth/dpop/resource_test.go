package dpop

import (
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// makeResourceProof signs a proof for a protected-resource request, with ath.
func makeResourceProof(t *testing.T, ath, jti string) (string, string) {
	t.Helper()
	key, jwk := newKey(t)
	claims := &proofClaims{
		HTM: "GET",
		HTU: "https://id.example.com/oauth/userinfo",
		ATH: ath,
		RegisteredClaims: jwt.RegisteredClaims{
			ID:       jti,
			IssuedAt: jwt.NewNumericDate(time.Now()),
		},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, claims)
	tok.Header["typ"] = headerTyp
	tok.Header["jwk"] = jwk
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	p, err := Verify(s, "GET", "https://id.example.com/oauth/userinfo", time.Now())
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	return s, p.Thumbprint
}

func TestVerifyForResource(t *testing.T) {
	const token = "the.access.token"
	const htu = "https://id.example.com/oauth/userinfo"
	cache := NewMemoryReplayCache(time.Minute)
	defer cache.Stop()

	proof, jkt := makeResourceProof(t, AccessTokenHash(token), "jti-ok")
	if _, err := VerifyForResource(proof, "GET", htu, token, jkt, time.Now(), cache); err != nil {
		t.Fatalf("valid proof: %v", err)
	}
	if _, err := VerifyForResource(proof, "GET", htu, token, jkt, time.Now(), cache); !errors.Is(err, ErrReplayed) {
		t.Errorf("replayed proof: %v, want ErrReplayed", err)
	}

	for name, tc := range map[string]struct {
		ath, token, jkt, htm string
		want                 error
	}{
		"ath of another token": {AccessTokenHash("other.token"), token, "", "GET", ErrATHMismatch},
		"no ath":               {"", token, "", "GET", ErrATHMismatch},
		"another key":          {AccessTokenHash(token), token, "not-the-thumbprint", "GET", ErrKeyMismatch},
		"no cnf.jkt":           {AccessTokenHash(token), token, "-", "GET", ErrKeyMismatch},
		"wrong method":         {AccessTokenHash(token), token, "", "POST", ErrMethodMismatch},
	} {
		t.Run(name, func(t *testing.T) {
			p, thumb := makeResourceProof(t, tc.ath, "jti-"+name)
			jkt := thumb
			switch tc.jkt {
			case "-":
				jkt = ""
			case "":
			default:
				jkt = tc.jkt
			}
			if _, err := VerifyForResource(p, tc.htm, htu, tc.token, jkt, time.Now(), cache); !errors.Is(err, tc.want) {
				t.Fatalf("err %v, want %v", err, tc.want)
			}
		})
	}

	// A proof refused for its key is not recorded as used.
	p, thumb := makeResourceProof(t, AccessTokenHash(token), "jti-retry")
	if _, err := VerifyForResource(p, "GET", htu, token, "wrong", time.Now(), cache); !errors.Is(err, ErrKeyMismatch) {
		t.Fatalf("wrong key: %v", err)
	}
	if _, err := VerifyForResource(p, "GET", htu, token, thumb, time.Now(), cache); err != nil {
		t.Fatalf("the refused proof's jti was recorded: %v", err)
	}
	if _, err := VerifyForResource(p, "GET", htu, token, thumb, time.Now(), nil); !errors.Is(err, ErrReplayed) {
		t.Errorf("no replay cache: %v, want a refusal", err)
	}
}

// ath is the base64url SHA-256 of the token (RFC 9449 §4.2 example).
func TestAccessTokenHash_RFCExample(t *testing.T) {
	const token = "Kz~8mXK1EalYznwH-LC-1fBAo.4Ljp~zsPE_NeO.gxU"
	if got := AccessTokenHash(token); got != "fUHyO2r2Z3DZ53EsNrWBb0xWXoaNy59IiKCAqksmQEo" {
		t.Fatalf("ath %q", got)
	}
}
