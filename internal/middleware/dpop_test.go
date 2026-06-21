package middleware

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/ovandermoten/go-oauth2/internal/shared/auth/dpop"
)

const (
	htuBase  = "https://id.example.com"
	tokenURI = "https://id.example.com/oauth/token"
)

// makeProof builds a valid DPoP proof for POST tokenURI.
func makeProof(t *testing.T) string {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("genkey: %v", err)
	}
	pad := func(b []byte) string {
		out := make([]byte, 32)
		copy(out[32-len(b):], b)
		return base64.RawURLEncoding.EncodeToString(out)
	}
	jwk := map[string]interface{}{"kty": "EC", "crv": "P-256", "x": pad(k.X.Bytes()), "y": pad(k.Y.Bytes())}
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"htm": "POST",
		"htu": tokenURI,
		"jti": "jti-mw-1",
		"iat": time.Now().Unix(),
	})
	tok.Header["typ"] = "dpop+jwt"
	tok.Header["jwk"] = jwk
	s, err := tok.SignedString(k)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	return s
}

// dpopOKHandler is a terminal handler that records that it ran and returns 200.
func dpopOKHandler(ran *bool) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		*ran = true
		w.WriteHeader(http.StatusOK)
	})
}

func doPost(h http.Handler, dpopHeader string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, tokenURI+"?grant_type=x", nil)
	if dpopHeader != "" {
		req.Header.Set("DPoP", dpopHeader)
	}
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestDPoPObserve_OffIsPassthrough(t *testing.T) {
	cache := dpop.NewMemoryReplayCache(time.Minute)
	defer cache.Stop()
	ran := false
	h := DPoPObserve(cache, "off", htuBase)(dpopOKHandler(&ran))
	rr := doPost(h, makeProof(t))
	if !ran || rr.Code != http.StatusOK {
		t.Fatalf("off mode must pass through; ran=%v code=%d", ran, rr.Code)
	}
}

func TestDPoPObserve_NilCacheIsPassthrough(t *testing.T) {
	ran := false
	h := DPoPObserve(nil, "observe", htuBase)(dpopOKHandler(&ran))
	rr := doPost(h, makeProof(t))
	if !ran || rr.Code != http.StatusOK {
		t.Fatalf("nil cache must pass through; ran=%v code=%d", ran, rr.Code)
	}
}

func TestDPoPObserve_ValidProofNeverBlocks(t *testing.T) {
	cache := dpop.NewMemoryReplayCache(time.Minute)
	defer cache.Stop()
	ran := false
	h := DPoPObserve(cache, "observe", htuBase)(dpopOKHandler(&ran))
	rr := doPost(h, makeProof(t))
	if !ran || rr.Code != http.StatusOK {
		t.Fatalf("observe must not block a valid proof; ran=%v code=%d", ran, rr.Code)
	}
}

func TestDPoPObserve_InvalidProofNeverBlocks(t *testing.T) {
	cache := dpop.NewMemoryReplayCache(time.Minute)
	defer cache.Stop()
	ran := false
	h := DPoPObserve(cache, "observe", htuBase)(dpopOKHandler(&ran))
	rr := doPost(h, "garbage-not-a-jwt")
	if !ran || rr.Code != http.StatusOK {
		t.Fatalf("observe must not block an invalid proof; ran=%v code=%d", ran, rr.Code)
	}
}

func TestDPoPObserve_NoHeaderNeverBlocks(t *testing.T) {
	cache := dpop.NewMemoryReplayCache(time.Minute)
	defer cache.Stop()
	ran := false
	h := DPoPObserve(cache, "observe", htuBase)(dpopOKHandler(&ran))
	rr := doPost(h, "")
	if !ran || rr.Code != http.StatusOK {
		t.Fatalf("observe must pass through when no DPoP header is present; ran=%v code=%d", ran, rr.Code)
	}
}

func TestJktPrefix(t *testing.T) {
	if got := jktPrefix("abc"); got != "abc" {
		t.Errorf("short thumbprint: got %q", got)
	}
	if got := jktPrefix("0123456789abcdef"); got != "01234567…" {
		t.Errorf("long thumbprint prefix: got %q", got)
	}
}
