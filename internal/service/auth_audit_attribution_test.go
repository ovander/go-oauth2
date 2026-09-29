// Package service — login audit rows carry the client IP and User-Agent that
// middleware.ClientIP resolved (they were written empty before: the service
// receives only the context, and never read the IP back out of it).
package service

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ovander/go-oauth2/internal/dto"
	"github.com/ovander/go-oauth2/internal/middleware"
	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/shared/auth"
)

func TestLogin_AuditRowCarriesClientIPAndUserAgent(t *testing.T) {
	pw := "Str0ng!Passw0rd"
	hash, err := auth.HashPassword(pw)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	trusted, err := middleware.ParseTrustedProxyCIDRs("127.0.0.1/32,::1/128")
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		name     string
		password string
		event    model.SecurityEventType
	}{
		{"success", pw, model.SecurityEventLoginSuccess},
		{"wrong password", "definitely-wrong-password", model.SecurityEventLoginFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// A global admin passes the app-membership check, so the right password succeeds.
			user := &model.User{ID: 42, Email: "admin@example.com", HashedPassword: hash, IsVerified: true, Role: model.UserRoleSuperadmin}
			svc := newLoginSvc(t, user)
			rec := &captureAuditRepo{}
			svc.auditRepo = rec

			// As in production: Caddy on loopback forwards the real client in X-Forwarded-For,
			// and the handler passes r.Context() to the service.
			h := middleware.ClientIP(trusted)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = svc.Login(r.Context(), dto.LoginRequest{
					Email: "admin@example.com", Password: tc.password, AppClientID: "admin-console-dev2",
				})
			}))
			req := httptest.NewRequest(http.MethodPost, "/oauth/login", nil)
			req.RemoteAddr = "127.0.0.1:55555"
			req.Header.Set("X-Forwarded-For", "198.51.100.23")
			req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh) attribution-test")
			h.ServeHTTP(httptest.NewRecorder(), req)

			if rec.last == nil {
				t.Fatal("no audit row written")
			}
			if rec.last.EventType != tc.event {
				t.Fatalf("event = %q, want %q", rec.last.EventType, tc.event)
			}
			if rec.last.IPAddress != "198.51.100.23" {
				t.Errorf("IPAddress = %q, want the forwarded client 198.51.100.23", rec.last.IPAddress)
			}
			if rec.last.UserAgent != "Mozilla/5.0 (Macintosh) attribution-test" {
				t.Errorf("UserAgent = %q, want the request's User-Agent", rec.last.UserAgent)
			}
		})
	}
}
