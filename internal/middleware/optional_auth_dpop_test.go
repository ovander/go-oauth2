package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ovander/go-oauth2/internal/shared/auth/dpop"
)

// /oauth/revoke and /oauth/logout read an optional bearer identity
// (OptionalAuthMiddlewareWithDPoP, the v1.14.2 audit's G-4 follow-up): under
// DPOP_MODE=enforce a bound token without a valid proof is ignored, so a
// stolen bound token does not act as its user there; under observe it is
// reported and accepted; off, nothing changes.

// serveOptional sends GET bindingPath through OptionalAuthMiddlewareWithDPoP
// in mode, and reports whether the request reached the handler as the user.
func (f bindingFixture) serveOptional(t *testing.T, mode, authorization, proof string, reports *[]bindingReport) (status int, asUser bool) {
	t.Helper()
	cache := dpop.NewMemoryReplayCache(time.Minute)
	t.Cleanup(cache.Stop)
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
	OptionalAuthMiddlewareWithDPoP(binding, f.ts, f.repo, nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, asUser = GetUserIDFromContext(r.Context())
		w.WriteHeader(http.StatusNoContent)
	})).ServeHTTP(rr, r)
	return rr.Code, asUser
}

func TestOptionalAuthDPoP_Enforce(t *testing.T) {
	f := newBindingFixture(t)
	ath := dpop.AccessTokenHash(f.bound)
	for name, tc := range map[string]struct {
		authorization, proof string
		asUser               bool
	}{
		"bound, valid proof, DPoP scheme":   {"DPoP " + f.bound, f.key.proof(t, ath), true},
		"bound, valid proof, Bearer scheme": {"Bearer " + f.bound, f.key.proof(t, ath), true},
		"bound, no proof":                   {"Bearer " + f.bound, "", false},
		"bound, proof of another key":       {"DPoP " + f.bound, newDPoPKey(t).proof(t, ath), false},
		"unbound, Bearer":                   {"Bearer " + f.unbound, "", true},
	} {
		var reports []bindingReport
		status, asUser := f.serveOptional(t, "enforce", tc.authorization, tc.proof, &reports)
		// Never a 401: an optional identity that does not hold is ignored.
		if status != http.StatusNoContent || asUser != tc.asUser {
			t.Errorf("%s: status %d, as the user %v; want 204, %v", name, status, asUser, tc.asUser)
		}
		if !tc.asUser && (len(reports) != 1 || !reports[0].blocked) {
			t.Errorf("%s: reports %+v, want one blocked failure", name, reports)
		}
	}
}

func TestOptionalAuthDPoP_ObserveReportsAndAccepts(t *testing.T) {
	f := newBindingFixture(t)
	var reports []bindingReport
	status, asUser := f.serveOptional(t, "observe", "Bearer "+f.bound, "", &reports)
	if status != http.StatusNoContent || !asUser {
		t.Fatalf("observe: status %d, as the user %v; want 204, true", status, asUser)
	}
	if len(reports) != 1 || reports[0].blocked {
		t.Errorf("observe: reports %+v, want one unblocked failure", reports)
	}
}

func TestOptionalAuthDPoP_OffIsUnchanged(t *testing.T) {
	f := newBindingFixture(t)
	// Off: no binding check, and only the Bearer scheme, as before.
	if _, asUser := f.serveOptional(t, "off", "Bearer "+f.bound, "", nil); !asUser {
		t.Error("off: a bound token without a proof is no longer accepted")
	}
	if _, asUser := f.serveOptional(t, "off", "DPoP "+f.bound, "", nil); asUser {
		t.Error("off: the DPoP scheme is accepted")
	}
}
