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
	"github.com/google/uuid"

	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/shared/auth"
	"github.com/ovander/go-oauth2/internal/shared/auth/dpop"
)

const bindingHTUBase = "https://test.example.com"
const bindingPath = "/api/userinfo"

// dpopKey is a client's ES256 key and its public JWK.
type dpopKey struct {
	priv *ecdsa.PrivateKey
	jwk  map[string]interface{}
}

func newDPoPKey(t *testing.T) dpopKey {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// Uncompressed point: 0x04 || X (32 bytes) || Y (32 bytes).
	point, err := priv.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	return dpopKey{priv: priv, jwk: map[string]interface{}{
		"kty": "EC", "crv": "P-256",
		"x": base64.RawURLEncoding.EncodeToString(point[1:33]),
		"y": base64.RawURLEncoding.EncodeToString(point[33:65]),
	}}
}

// proof signs a DPoP proof for GET bindingPath carrying ath.
func (k dpopKey) proof(t *testing.T, ath string) string {
	t.Helper()
	return k.proofFor(t, http.MethodGet, bindingHTUBase+bindingPath, ath)
}

// proofFor signs a DPoP proof for method and htu carrying ath.
func (k dpopKey) proofFor(t *testing.T, method, htu, ath string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{
		"htm": method, "htu": htu, "ath": ath,
		"jti": uuid.NewString(), "iat": time.Now().Unix(),
	})
	tok.Header["typ"] = "dpop+jwt"
	tok.Header["jwk"] = k.jwk
	s, err := tok.SignedString(k.priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// thumbprint is the key's jkt, as the token endpoint computes it.
func (k dpopKey) thumbprint(t *testing.T) string {
	t.Helper()
	p, err := dpop.Verify(k.proof(t, ""), http.MethodGet, bindingHTUBase+bindingPath, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	return p.Thumbprint
}

// bindingFixture is a user, an access token bound to key (cnf.jkt) and an
// unbound one.
type bindingFixture struct {
	ts      *auth.TokenService
	repo    *find01UserRepo
	key     dpopKey
	bound   string
	unbound string
}

func newBindingFixture(t *testing.T) bindingFixture {
	t.Helper()
	ts := newFind01TokenService(t)
	user := &model.User{ID: 42, Email: "bound@example.com", IsVerified: true}
	app := &model.App{ID: 1, ClientID: "test-client"}
	key := newDPoPKey(t)
	bound, err := ts.GenerateTokenSetWithDPoP(user, app, "user", "openid", nil, "", time.Now().Unix(), key.thumbprint(t))
	if err != nil {
		t.Fatal(err)
	}
	unbound, err := ts.GenerateTokenSet(user, app, "user", "openid", nil, "", time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	return bindingFixture{ts: ts, repo: &find01UserRepo{user: user}, key: key, bound: bound.AccessToken, unbound: unbound.AccessToken}
}

type bindingReport struct {
	reason  string
	blocked bool
}

// serve sends GET bindingPath with the given Authorization header and DPoP
// proof (none when empty) through AuthMiddlewareWithDPoP in mode.
func (f bindingFixture) serve(mode, authorization, proof string, cache dpop.ReplayCache, reports *[]bindingReport) *httptest.ResponseRecorder {
	if cache == nil {
		cache = dpop.NewMemoryReplayCache(time.Minute)
	}
	binding := NewDPoPBinding(cache, mode, bindingHTUBase+"/", func(_ *http.Request, reason string, blocked bool) {
		if reports != nil {
			*reports = append(*reports, bindingReport{reason, blocked})
		}
	})
	r := httptest.NewRequest(http.MethodGet, bindingPath, nil)
	r.Header.Set("Authorization", authorization)
	if proof != "" {
		r.Header.Set("DPoP", proof)
	}
	rr := httptest.NewRecorder()
	AuthMiddlewareWithDPoP(binding, f.ts, f.repo, nil)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(rr, r)
	return rr
}

// Under enforce, a bound token passes only with a valid, fresh proof of its
// key for this request, under either scheme (the token endpoint answers
// token_type Bearer); an unbound token is unaffected.
func TestDPoPBinding_Enforce(t *testing.T) {
	f := newBindingFixture(t)
	other := newDPoPKey(t)
	athBound := dpop.AccessTokenHash(f.bound)

	reused := f.key.proof(t, athBound)
	cache := dpop.NewMemoryReplayCache(time.Minute)
	defer cache.Stop()
	if rr := f.serve("enforce", "DPoP "+f.bound, reused, cache, nil); rr.Code != http.StatusNoContent {
		t.Fatalf("bound token with a valid proof: %d %s", rr.Code, rr.Body.String())
	}

	for name, tc := range map[string]struct {
		authorization, proof string
		cache                dpop.ReplayCache
		want                 int
	}{
		"bound, DPoP scheme, valid proof (lower-case scheme)": {"dpop " + f.bound, f.key.proof(t, athBound), nil, http.StatusNoContent},
		"bound, Bearer scheme with a valid proof":             {"Bearer " + f.bound, f.key.proof(t, athBound), nil, http.StatusNoContent},
		"bound, Bearer scheme, no proof":                      {"Bearer " + f.bound, "", nil, http.StatusUnauthorized},
		"bound, DPoP scheme, no proof":                        {"DPoP " + f.bound, "", nil, http.StatusUnauthorized},
		"bound, proof of another key":                         {"DPoP " + f.bound, other.proof(t, athBound), nil, http.StatusUnauthorized},
		"bound, proof for another token":                      {"DPoP " + f.bound, f.key.proof(t, dpop.AccessTokenHash(f.unbound)), nil, http.StatusUnauthorized},
		"bound, replayed proof":                               {"DPoP " + f.bound, reused, cache, http.StatusUnauthorized},
		"unbound, Bearer":                                     {"Bearer " + f.unbound, "", nil, http.StatusNoContent},
		"unbound, DPoP scheme":                                {"DPoP " + f.unbound, "", nil, http.StatusNoContent},
	} {
		t.Run(name, func(t *testing.T) {
			rr := f.serve("enforce", tc.authorization, tc.proof, tc.cache, nil)
			if rr.Code != tc.want {
				t.Fatalf("status %d, want %d (%s)", rr.Code, tc.want, rr.Body.String())
			}
			if got := rr.Header().Get("WWW-Authenticate"); tc.want == http.StatusUnauthorized && !strings.HasPrefix(got, "DPoP ") {
				t.Errorf("WWW-Authenticate %q, want a DPoP challenge", got)
			}
		})
	}
}

// Under observe, a failed binding is reported and the request goes through.
func TestDPoPBinding_ObserveReportsAndAllows(t *testing.T) {
	f := newBindingFixture(t)
	var reports []bindingReport
	if rr := f.serve("observe", "Bearer "+f.bound, "", nil, &reports); rr.Code != http.StatusNoContent {
		t.Fatalf("observe: %d", rr.Code)
	}
	if len(reports) != 1 || reports[0].blocked || reports[0].reason == "" {
		t.Fatalf("reports %+v, want one unblocked failure", reports)
	}
	reports = nil
	if rr := f.serve("observe", "DPoP "+f.bound, f.key.proof(t, dpop.AccessTokenHash(f.bound)), nil, &reports); rr.Code != http.StatusNoContent || len(reports) != 0 {
		t.Fatalf("observe with a valid proof: %d, reports %+v", rr.Code, reports)
	}
}

// With DPOP_MODE off nothing changes: a bound token is accepted as a bearer
// token, and the DPoP scheme is not accepted.
func TestDPoPBinding_OffIsUnchanged(t *testing.T) {
	f := newBindingFixture(t)
	if NewDPoPBinding(dpop.NewMemoryReplayCache(time.Minute), "off", bindingHTUBase, nil) != nil {
		t.Fatal("off must give no binding")
	}
	if rr := f.serve("off", "Bearer "+f.bound, "", nil, nil); rr.Code != http.StatusNoContent {
		t.Fatalf("off, bound token as bearer: %d", rr.Code)
	}
	if rr := f.serve("off", "DPoP "+f.bound, f.key.proof(t, dpop.AccessTokenHash(f.bound)), nil, nil); rr.Code != http.StatusUnauthorized {
		t.Fatalf("off, DPoP scheme: %d, want 401 (scheme not accepted)", rr.Code)
	}
}
