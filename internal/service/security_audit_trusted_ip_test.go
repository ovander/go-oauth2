// Package service — LogFromRequest audits the client IP that middleware.ClientIP
// resolved (forwarding headers honoured only from TRUSTED_PROXIES), never a raw
// X-Forwarded-For that any peer can send.
package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"unicode/utf8"

	"github.com/ovander/go-oauth2/internal/middleware"
	"github.com/ovander/go-oauth2/internal/model"
)

func auditedIP(t *testing.T, remoteAddr, xff string, throughMiddleware bool) string {
	t.Helper()
	repo := &captureAuditRepo{}
	svc := NewSecurityAuditService(repo)

	var logged *http.Request
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		logged = r
		if err := svc.LogFromRequest(r.Context(), r, SecurityEvent{EventType: model.SecurityEventLoginSuccess, Success: true}); err != nil {
			t.Fatalf("LogFromRequest: %v", err)
		}
	})
	var handler http.Handler = h
	if throughMiddleware {
		trusted, err := middleware.ParseTrustedProxyCIDRs("127.0.0.1/32,::1/128")
		if err != nil {
			t.Fatal(err)
		}
		handler = middleware.ClientIP(trusted)(h)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/admin/apps", nil)
	req.RemoteAddr = remoteAddr
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
		req.Header.Set("X-Real-IP", "7.7.7.7")
	}
	handler.ServeHTTP(httptest.NewRecorder(), req)
	if logged == nil || repo.last == nil {
		t.Fatal("no audit row written")
	}
	return repo.last.IPAddress
}

func TestLogFromRequest_AuditsTheTrustedClientIP(t *testing.T) {
	for _, tc := range []struct {
		name       string
		remoteAddr string
		xff        string
		middleware bool
		want       string
	}{
		{"untrusted peer cannot choose its audited address", "198.51.100.9:4242", "6.6.6.6", true, "198.51.100.9"},
		{"trusted proxy (loopback) forwards the client", "127.0.0.1:55555", "203.0.113.7", true, "203.0.113.7"},
		{"without the middleware, the peer — never a header", "198.51.100.9:4242", "6.6.6.6", false, "198.51.100.9"},
		{"IPv6 peer without the middleware", "[2001:db8::5]:443", "6.6.6.6", false, "2001:db8::5"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := auditedIP(t, tc.remoteAddr, tc.xff, tc.middleware); got != tc.want {
				t.Errorf("audited IP = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestLogFromRequest_ExplicitIPWins(t *testing.T) {
	repo := &captureAuditRepo{}
	svc := NewSecurityAuditService(repo)
	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	req.RemoteAddr = "198.51.100.9:4242"
	if err := svc.LogFromRequest(context.Background(), req, SecurityEvent{EventType: model.SecurityEventLoginSuccess, IPAddress: "192.0.2.1"}); err != nil {
		t.Fatal(err)
	}
	if repo.last.IPAddress != "192.0.2.1" {
		t.Errorf("audited IP = %q, want the explicit 192.0.2.1", repo.last.IPAddress)
	}
}

func TestLogFromRequest_TruncatesUserAgentOnCharacterBoundary(t *testing.T) {
	repo := &captureAuditRepo{}
	svc := NewSecurityAuditService(repo)
	req := httptest.NewRequest(http.MethodPost, "/x", nil)
	req.Header.Set("User-Agent", strings.Repeat("a", maxUserAgentLen-1)+"é"+"tail")
	if err := svc.LogFromRequest(context.Background(), req, SecurityEvent{EventType: model.SecurityEventLoginSuccess}); err != nil {
		t.Fatal(err)
	}
	ua := repo.last.UserAgent
	if len(ua) > maxUserAgentLen || !utf8.ValidString(ua) {
		t.Errorf("UserAgent len=%d valid=%v, want <= %d bytes of valid UTF-8", len(ua), utf8.ValidString(ua), maxUserAgentLen)
	}
}
