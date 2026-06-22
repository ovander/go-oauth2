package handler

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// Sensitive OAuth responses (userinfo, introspection, revocation) must be marked
// non-cacheable (RFC 6749 §5.1 / RFC 7662 §4 / OIDC Core §5.3.2). setNoStore runs
// first in each handler, so the header is present even on early error paths.
func TestSensitiveEndpoints_SetNoStore(t *testing.T) {
	h := newTestEndSessionHandler(&mockAppService{}, &mockOAuthService{})

	cases := []struct {
		name    string
		handler http.HandlerFunc
		req     *http.Request
	}{
		{"userinfo", h.UserInfo, httptest.NewRequest(http.MethodGet, "/oauth/userinfo", nil)},
		{"introspect", h.Introspect, httptest.NewRequest(http.MethodPost, "/oauth/introspect", strings.NewReader(""))},
		{"revoke", h.Revoke, httptest.NewRequest(http.MethodPost, "/oauth/revoke", strings.NewReader(""))},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			c.handler(rr, c.req)
			if got := rr.Header().Get("Cache-Control"); got != "no-store" {
				t.Errorf("%s: Cache-Control = %q, want no-store", c.name, got)
			}
			if got := rr.Header().Get("Pragma"); got != "no-cache" {
				t.Errorf("%s: Pragma = %q, want no-cache", c.name, got)
			}
		})
	}
}
