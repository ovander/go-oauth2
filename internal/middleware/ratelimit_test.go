package middleware

import (
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// GetClientIPSafe
// ---------------------------------------------------------------------------

func TestGetClientIPSafe_NoTrustedCIDRs_UsesRemoteAddr(t *testing.T) {
	// When no trusted CIDRs are configured, proxy headers must be ignored
	// regardless of their content.  RemoteAddr is always authoritative.
	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		xri        string
		wantIP     string
	}{
		{
			name:       "ignores XFF when no trusted CIDRs",
			remoteAddr: "1.2.3.4:50001",
			xff:        "10.0.0.1",
			wantIP:     "1.2.3.4",
		},
		{
			name:       "ignores X-Real-IP when no trusted CIDRs",
			remoteAddr: "1.2.3.4:50001",
			xri:        "10.0.0.2",
			wantIP:     "1.2.3.4",
		},
		{
			name:       "returns RemoteAddr when no proxy headers at all",
			remoteAddr: "203.0.113.5:12345",
			wantIP:     "203.0.113.5",
		},
		{
			name:       "strips port from RemoteAddr",
			remoteAddr: "192.0.2.10:8080",
			wantIP:     "192.0.2.10",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tt.remoteAddr
			if tt.xff != "" {
				r.Header.Set("X-Forwarded-For", tt.xff)
			}
			if tt.xri != "" {
				r.Header.Set("X-Real-IP", tt.xri)
			}

			got := GetClientIPSafe(r, nil)
			if got != tt.wantIP {
				t.Errorf("GetClientIPSafe() = %q, want %q", got, tt.wantIP)
			}
		})
	}
}

func TestGetClientIPSafe_TrustedCIDR_HonoursProxyHeaders(t *testing.T) {
	// When RemoteAddr is inside the trusted CIDR list, the leftmost address in
	// X-Forwarded-For is used; X-Real-IP is the fallback.
	trusted := mustParseCIDRs(t, "10.0.0.0/8")

	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		xri        string
		wantIP     string
	}{
		{
			name:       "trusted proxy: uses leftmost XFF address",
			remoteAddr: "10.0.0.1:1234",
			xff:        "203.0.113.5, 10.0.0.1",
			wantIP:     "203.0.113.5",
		},
		{
			name:       "trusted proxy: single XFF address",
			remoteAddr: "10.1.2.3:1234",
			xff:        "198.51.100.7",
			wantIP:     "198.51.100.7",
		},
		{
			name:       "trusted proxy: falls back to X-Real-IP when no XFF",
			remoteAddr: "10.1.2.3:1234",
			xri:        "203.0.113.9",
			wantIP:     "203.0.113.9",
		},
		{
			name:       "trusted proxy: XFF takes precedence over X-Real-IP",
			remoteAddr: "10.1.2.3:1234",
			xff:        "198.51.100.1",
			xri:        "203.0.113.9",
			wantIP:     "198.51.100.1",
		},
		{
			name:       "trusted proxy: XFF with spaces trimmed",
			remoteAddr: "10.5.6.7:9999",
			xff:        "  203.0.113.22  ",
			wantIP:     "203.0.113.22",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tt.remoteAddr
			if tt.xff != "" {
				r.Header.Set("X-Forwarded-For", tt.xff)
			}
			if tt.xri != "" {
				r.Header.Set("X-Real-IP", tt.xri)
			}

			got := GetClientIPSafe(r, trusted)
			if got != tt.wantIP {
				t.Errorf("GetClientIPSafe() = %q, want %q", got, tt.wantIP)
			}
		})
	}
}

func TestGetClientIPSafe_UntrustedRemoteAddr_IgnoresProxyHeaders(t *testing.T) {
	// C-02: Even with trusted CIDRs configured, if the connecting peer is NOT
	// in the trusted list, its spoofed X-Forwarded-For must be ignored.
	trusted := mustParseCIDRs(t, "10.0.0.0/8")

	tests := []struct {
		name       string
		remoteAddr string
		xff        string
		wantIP     string
	}{
		{
			name:       "untrusted peer cannot spoof XFF",
			remoteAddr: "1.2.3.4:5678", // NOT in 10.0.0.0/8
			xff:        "10.0.0.1",      // attacker claims to be internal
			wantIP:     "1.2.3.4",       // must use RemoteAddr
		},
		{
			name:       "untrusted peer with multi-hop XFF",
			remoteAddr: "203.0.113.99:1234",
			xff:        "127.0.0.1, 10.0.0.5",
			wantIP:     "203.0.113.99",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			r := httptest.NewRequest(http.MethodGet, "/", nil)
			r.RemoteAddr = tt.remoteAddr
			r.Header.Set("X-Forwarded-For", tt.xff)

			got := GetClientIPSafe(r, trusted)
			if got != tt.wantIP {
				t.Errorf("GetClientIPSafe() = %q, want %q (IP spoofing not prevented)", got, tt.wantIP)
			}
		})
	}
}

func TestGetClientIPSafe_MultipleTrustedCIDRs(t *testing.T) {
	// Verify the trusted list is checked exhaustively (not just first entry).
	trusted := mustParseCIDRs(t, "10.0.0.0/8,172.16.0.0/12")

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "172.20.5.1:8888" // inside 172.16.0.0/12
	r.Header.Set("X-Forwarded-For", "203.0.113.42")

	got := GetClientIPSafe(r, trusted)
	if got != "203.0.113.42" {
		t.Errorf("GetClientIPSafe() = %q, want %q (second CIDR not matched)", got, "203.0.113.42")
	}
}

func TestGetClientIPSafe_IPv6RemoteAddr(t *testing.T) {
	// IPv6 peer that is not in any trusted list → RemoteAddr is used.
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "[2001:db8::1]:1234"
	r.Header.Set("X-Forwarded-For", "203.0.113.1")

	got := GetClientIPSafe(r, nil)
	if got != "2001:db8::1" {
		t.Errorf("GetClientIPSafe() = %q, want %q", got, "2001:db8::1")
	}
}

func TestGetClientIPSafe_NoProxyHeaders_TrustedPeer_FallsBackToRemoteAddr(t *testing.T) {
	// Trusted peer with no proxy headers at all → RemoteAddr is used.
	trusted := mustParseCIDRs(t, "10.0.0.0/8")

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "10.0.0.5:4321"

	got := GetClientIPSafe(r, trusted)
	if got != "10.0.0.5" {
		t.Errorf("GetClientIPSafe() = %q, want %q", got, "10.0.0.5")
	}
}

// ---------------------------------------------------------------------------
// GetClientIP (backward-compatible wrapper)
// ---------------------------------------------------------------------------

func TestGetClientIP_AlwaysUsesRemoteAddr(t *testing.T) {
	// GetClientIP must behave identically to GetClientIPSafe(r, nil).
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "5.6.7.8:9999"
	r.Header.Set("X-Forwarded-For", "1.1.1.1")

	got := GetClientIP(r)
	if got != "5.6.7.8" {
		t.Errorf("GetClientIP() = %q, want %q (should not trust XFF)", got, "5.6.7.8")
	}
}

// ---------------------------------------------------------------------------
// ParseTrustedProxyCIDRs
// ---------------------------------------------------------------------------

func TestParseTrustedProxyCIDRs_ValidInputs(t *testing.T) {
	tests := []struct {
		name      string
		raw       string
		wantCount int
	}{
		{
			name:      "empty string returns nil slice",
			raw:       "",
			wantCount: 0,
		},
		{
			name:      "single IPv4 CIDR",
			raw:       "10.0.0.0/8",
			wantCount: 1,
		},
		{
			name:      "single IPv4 host address",
			raw:       "192.168.1.1",
			wantCount: 1,
		},
		{
			name:      "multiple CIDRs comma-separated",
			raw:       "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16",
			wantCount: 3,
		},
		{
			name:      "CIDRs with spaces around commas",
			raw:       "10.0.0.0/8 , 172.16.0.0/12",
			wantCount: 2,
		},
		{
			name:      "IPv6 CIDR",
			raw:       "::1/128",
			wantCount: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cidrs, err := ParseTrustedProxyCIDRs(tt.raw)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(cidrs) != tt.wantCount {
				t.Errorf("ParseTrustedProxyCIDRs() returned %d CIDRs, want %d", len(cidrs), tt.wantCount)
			}
		})
	}
}

func TestParseTrustedProxyCIDRs_InvalidInputs(t *testing.T) {
	tests := []struct {
		name string
		raw  string
	}{
		{name: "invalid CIDR notation", raw: "not-an-ip"},
		{name: "bad prefix length", raw: "10.0.0.0/99"},
		{name: "mixed valid and invalid", raw: "10.0.0.0/8,bad-value"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := ParseTrustedProxyCIDRs(tt.raw)
			if err == nil {
				t.Errorf("ParseTrustedProxyCIDRs(%q) expected error, got nil", tt.raw)
			}
		})
	}
}

func TestParseTrustedProxyCIDRs_ReturnedCIDRsAreUsable(t *testing.T) {
	// Verify that the parsed *net.IPNet values are correct by spot-checking
	// containment of a known address.
	cidrs, err := ParseTrustedProxyCIDRs("10.0.0.0/8")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(cidrs) != 1 {
		t.Fatalf("expected 1 CIDR, got %d", len(cidrs))
	}

	inside := net.ParseIP("10.99.88.77")
	outside := net.ParseIP("192.168.1.1")

	if !cidrs[0].Contains(inside) {
		t.Errorf("10.0.0.0/8 should contain 10.99.88.77")
	}
	if cidrs[0].Contains(outside) {
		t.Errorf("10.0.0.0/8 should not contain 192.168.1.1")
	}
}

// ---------------------------------------------------------------------------
// RateLimitMiddleware wiring: trusted CIDRs are forwarded to the rate limiter
// ---------------------------------------------------------------------------

func TestRateLimitMiddleware_TrustedCIDR_RateLimitsOnRealClientIP(t *testing.T) {
	// When a trusted proxy forwards the real client IP via X-Forwarded-For,
	// the rate limiter must bucket by the *real* IP, not the proxy's address.
	// This test verifies the integration between the middleware and GetClientIPSafe.
	trusted := mustParseCIDRs(t, "10.0.0.1/32")
	limiter := NewRateLimiterWithConfig(RateLimiterConfig{
		Limit:      2,
		Window:     60 * time.Second,
		MaxEntries: 100,
	})
	defer limiter.Stop()

	handler := RateLimitMiddleware(limiter, trusted)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	// Three requests from real client 203.0.113.5, forwarded through trusted proxy 10.0.0.1
	for i := 1; i <= 3; i++ {
		r := httptest.NewRequest(http.MethodGet, "/", nil)
		r.RemoteAddr = "10.0.0.1:9000"
		r.Header.Set("X-Forwarded-For", "203.0.113.5")

		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)

		if i <= 2 && w.Code != http.StatusOK {
			t.Errorf("request %d: got %d, want 200", i, w.Code)
		}
		if i == 3 && w.Code != http.StatusTooManyRequests {
			t.Errorf("request %d: got %d, want 429 (rate limit should kick in)", i, w.Code)
		}
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func mustParseCIDRs(t *testing.T, raw string) []*net.IPNet {
	t.Helper()
	cidrs, err := ParseTrustedProxyCIDRs(raw)
	if err != nil {
		t.Fatalf("mustParseCIDRs(%q): %v", raw, err)
	}
	return cidrs
}
