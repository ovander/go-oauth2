package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// P3-2 (GO-2026-5775 / GO-2026-5777): the ClientIP middleware replaces chi's
// RealIP. These tests pin the property that mattered — an untrusted peer can
// never choose the IP the server attributes the request to — and that a
// trusted proxy's X-Forwarded-For is still honoured.

func recordIP(t *testing.T, mw func(http.Handler) http.Handler, remoteAddr string, headers map[string]string) string {
	t.Helper()
	var got string
	h := mw(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got = GetClientIP(r)
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = remoteAddr
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	h.ServeHTTP(httptest.NewRecorder(), req)
	return got
}

func TestClientIP_UntrustedPeer_CannotSpoofViaAnyHeader(t *testing.T) {
	spoof := map[string]string{
		"True-Client-IP":  "198.51.100.77",
		"X-Real-IP":       "198.51.100.78",
		"X-Forwarded-For": "198.51.100.79, 10.0.0.1",
	}
	// No trusted proxies at all.
	if got := recordIP(t, ClientIP(nil), "203.0.113.9:4242", spoof); got != "203.0.113.9" {
		t.Fatalf("nil trusted CIDRs: attributed to %q, want RemoteAddr 203.0.113.9 (spoofable!)", got)
	}
	// Trusted proxies configured, but this peer is not one of them.
	trusted := mustParseCIDRs(t, "127.0.0.1/32,::1/128")
	if got := recordIP(t, ClientIP(trusted), "203.0.113.9:4242", spoof); got != "203.0.113.9" {
		t.Fatalf("untrusted peer: attributed to %q, want RemoteAddr 203.0.113.9 (spoofable!)", got)
	}
}

func TestClientIP_TrustedProxy_HonoursForwardedFor(t *testing.T) {
	trusted := mustParseCIDRs(t, "127.0.0.1/32,::1/128")
	got := recordIP(t, ClientIP(trusted), "127.0.0.1:55555", map[string]string{
		"X-Forwarded-For": "198.51.100.7",
		"True-Client-IP":  "198.51.100.77", // must be ignored even from a trusted proxy
	})
	if got != "198.51.100.7" {
		t.Fatalf("trusted loopback proxy: attributed to %q, want XFF 198.51.100.7", got)
	}
}

func TestClientIP_DoesNotMutateRemoteAddr(t *testing.T) {
	trusted := mustParseCIDRs(t, "127.0.0.1/32")
	var remote string
	h := ClientIP(trusted)(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		remote = r.RemoteAddr
	}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "127.0.0.1:1"
	req.Header.Set("X-Forwarded-For", "198.51.100.7")
	h.ServeHTTP(httptest.NewRecorder(), req)
	if remote != "127.0.0.1:1" {
		t.Fatalf("RemoteAddr was rewritten to %q; ClientIP must not mutate it", remote)
	}
}

func TestGetClientIP_WithoutMiddleware_FallsBackToRemoteAddrOnly(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "203.0.113.9:4242"
	req.Header.Set("X-Forwarded-For", "198.51.100.79")
	req.Header.Set("True-Client-IP", "198.51.100.77")
	if got := GetClientIP(req); got != "203.0.113.9" {
		t.Fatalf("GetClientIP without middleware = %q, want bare RemoteAddr", got)
	}
}
