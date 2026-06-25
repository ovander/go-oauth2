package middleware

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/ovandermoten/go-oauth2/internal/contextkeys"
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

func TestDPoP_OffIsPassthrough(t *testing.T) {
	cache := dpop.NewMemoryReplayCache(time.Minute)
	defer cache.Stop()
	ran := false
	h := DPoP(cache, "off", htuBase)(dpopOKHandler(&ran))
	rr := doPost(h, makeProof(t))
	if !ran || rr.Code != http.StatusOK {
		t.Fatalf("off mode must pass through; ran=%v code=%d", ran, rr.Code)
	}
}

func TestDPoP_NilCacheIsPassthrough(t *testing.T) {
	ran := false
	h := DPoP(nil, "observe", htuBase)(dpopOKHandler(&ran))
	rr := doPost(h, makeProof(t))
	if !ran || rr.Code != http.StatusOK {
		t.Fatalf("nil cache must pass through; ran=%v code=%d", ran, rr.Code)
	}
}

func TestDPoP_ValidProofNeverBlocks(t *testing.T) {
	cache := dpop.NewMemoryReplayCache(time.Minute)
	defer cache.Stop()
	ran := false
	h := DPoP(cache, "observe", htuBase)(dpopOKHandler(&ran))
	rr := doPost(h, makeProof(t))
	if !ran || rr.Code != http.StatusOK {
		t.Fatalf("observe must not block a valid proof; ran=%v code=%d", ran, rr.Code)
	}
}

func TestDPoP_InvalidProofNeverBlocks(t *testing.T) {
	cache := dpop.NewMemoryReplayCache(time.Minute)
	defer cache.Stop()
	ran := false
	h := DPoP(cache, "observe", htuBase)(dpopOKHandler(&ran))
	rr := doPost(h, "garbage-not-a-jwt")
	if !ran || rr.Code != http.StatusOK {
		t.Fatalf("observe must not block an invalid proof; ran=%v code=%d", ran, rr.Code)
	}
}

func TestDPoP_OnRejectFiresForInvalidProof(t *testing.T) {
	var called int
	var gotBlocked bool
	sink := func(_ *http.Request, reason string, blocked bool) {
		called++
		gotBlocked = blocked
		if reason == "" {
			t.Error("reject reason should be non-empty")
		}
	}
	ran := false

	// observe: onReject fires, request not blocked.
	c1 := dpop.NewMemoryReplayCache(time.Minute)
	defer c1.Stop()
	rr := doPost(DPoP(c1, "observe", htuBase, sink)(dpopOKHandler(&ran)), "garbage-not-a-jwt")
	if called != 1 || gotBlocked || rr.Code != http.StatusOK {
		t.Fatalf("observe: called=%d blocked=%v code=%d", called, gotBlocked, rr.Code)
	}

	// enforce: onReject fires, request blocked (400).
	called = 0
	c2 := dpop.NewMemoryReplayCache(time.Minute)
	defer c2.Stop()
	rr = doPost(DPoP(c2, "enforce", htuBase, sink)(dpopOKHandler(&ran)), "garbage-not-a-jwt")
	if called != 1 || !gotBlocked || rr.Code != http.StatusBadRequest {
		t.Fatalf("enforce: called=%d blocked=%v code=%d", called, gotBlocked, rr.Code)
	}
}

func TestDPoP_OnRejectNotCalledWithoutProof(t *testing.T) {
	c := dpop.NewMemoryReplayCache(time.Minute)
	defer c.Stop()
	called := 0
	sink := func(_ *http.Request, _ string, _ bool) { called++ }
	ran := false
	doPost(DPoP(c, "observe", htuBase, sink)(dpopOKHandler(&ran)), "") // no DPoP header
	if called != 0 {
		t.Fatalf("onReject must not fire when no proof is present: called=%d", called)
	}
}

func TestDPoP_NoHeaderNeverBlocks(t *testing.T) {
	cache := dpop.NewMemoryReplayCache(time.Minute)
	defer cache.Stop()
	ran := false
	h := DPoP(cache, "observe", htuBase)(dpopOKHandler(&ran))
	rr := doPost(h, "")
	if !ran || rr.Code != http.StatusOK {
		t.Fatalf("observe must pass through when no DPoP header is present; ran=%v code=%d", ran, rr.Code)
	}
}

func TestDPoP_StashesThumbprintForValidProof(t *testing.T) {
	cache := dpop.NewMemoryReplayCache(time.Minute)
	defer cache.Stop()

	var gotJKT string
	var present bool
	terminal := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotJKT, present = r.Context().Value(contextkeys.DPoPJKTKey).(string)
		w.WriteHeader(http.StatusOK)
	})
	h := DPoP(cache, "observe", htuBase)(terminal)

	doPost(h, makeProof(t))
	if !present || gotJKT == "" {
		t.Fatalf("expected a verified jkt on the context, present=%v jkt=%q", present, gotJKT)
	}
}

func TestDPoP_NoThumbprintForInvalidProof(t *testing.T) {
	cache := dpop.NewMemoryReplayCache(time.Minute)
	defer cache.Stop()

	var present bool
	terminal := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, present = r.Context().Value(contextkeys.DPoPJKTKey).(string)
		w.WriteHeader(http.StatusOK)
	})
	h := DPoP(cache, "observe", htuBase)(terminal)

	doPost(h, "garbage-not-a-jwt")
	if present {
		t.Fatal("an invalid proof must not place a jkt on the context")
	}
}

func TestDPoP_EnforceRejectsInvalidProof(t *testing.T) {
	cache := dpop.NewMemoryReplayCache(time.Minute)
	defer cache.Stop()
	ran := false
	h := DPoP(cache, "enforce", htuBase)(dpopOKHandler(&ran))

	rr := doPost(h, "garbage-not-a-jwt")
	if ran {
		t.Fatal("enforce must not call the handler for an invalid proof")
	}
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Code)
	}
	if !strings.Contains(rr.Body.String(), "invalid_dpop_proof") {
		t.Fatalf("expected invalid_dpop_proof body, got %q", rr.Body.String())
	}
}

func TestDPoP_EnforceAllowsValidProof(t *testing.T) {
	cache := dpop.NewMemoryReplayCache(time.Minute)
	defer cache.Stop()
	var gotJKT string
	terminal := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotJKT, _ = r.Context().Value(contextkeys.DPoPJKTKey).(string)
		w.WriteHeader(http.StatusOK)
	})
	h := DPoP(cache, "enforce", htuBase)(terminal)

	rr := doPost(h, makeProof(t))
	if rr.Code != http.StatusOK {
		t.Fatalf("enforce must allow a valid proof; got %d", rr.Code)
	}
	if gotJKT == "" {
		t.Fatal("enforce must bind a valid proof's thumbprint")
	}
}

func TestDPoP_EnforceAllowsMissingProof(t *testing.T) {
	// This slice rejects only present-but-invalid proofs; a request with no DPoP
	// header still proceeds (requiring DPoP per client is a later slice).
	cache := dpop.NewMemoryReplayCache(time.Minute)
	defer cache.Stop()
	ran := false
	h := DPoP(cache, "enforce", htuBase)(dpopOKHandler(&ran))

	rr := doPost(h, "")
	if !ran || rr.Code != http.StatusOK {
		t.Fatalf("enforce must allow a request with no proof; ran=%v code=%d", ran, rr.Code)
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
