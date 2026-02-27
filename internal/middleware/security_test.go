// Package middleware — tests for H-04 (HSTS) and H-05 (CSP) security headers.
//
// SecurityHeaders() is applied globally to every router; these tests verify
// that the correct values are present on every response regardless of path.
package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// nopHandler is a trivial downstream handler used to isolate the middleware.
var nopHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
})

// recordHeaders drives a single request through SecurityHeaders() and returns
// the response headers.
func recordHeaders(t *testing.T, method, path string) http.Header {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, nil)
	SecurityHeaders()(nopHandler).ServeHTTP(rec, req)
	return rec.Header()
}

// ---------------------------------------------------------------------------
// H-04: Strict-Transport-Security
// ---------------------------------------------------------------------------

func TestSecurityHeaders_HSTS_Present(t *testing.T) {
	h := recordHeaders(t, "GET", "/")
	if got := h.Get("Strict-Transport-Security"); got == "" {
		t.Error("expected Strict-Transport-Security header to be set")
	}
}

func TestSecurityHeaders_HSTS_MaxAge_OneYear(t *testing.T) {
	// max-age=31536000 = 365 days (one year)
	h := recordHeaders(t, "GET", "/")
	got := h.Get("Strict-Transport-Security")
	if !strings.Contains(got, "max-age=31536000") {
		t.Errorf("HSTS max-age must be 31536000, got: %q", got)
	}
}

func TestSecurityHeaders_HSTS_IncludeSubDomains(t *testing.T) {
	h := recordHeaders(t, "GET", "/")
	got := h.Get("Strict-Transport-Security")
	if !strings.Contains(got, "includeSubDomains") {
		t.Errorf("HSTS header must include 'includeSubDomains', got: %q", got)
	}
}

func TestSecurityHeaders_HSTS_AppliedToAllPaths(t *testing.T) {
	paths := []string{"/", "/oauth/authorize", "/oauth/token", "/.well-known/openid-configuration", "/admin"}
	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			h := recordHeaders(t, "GET", p)
			if h.Get("Strict-Transport-Security") == "" {
				t.Errorf("expected HSTS header on path %s", p)
			}
		})
	}
}

func TestSecurityHeaders_HSTS_AppliedToPostRequests(t *testing.T) {
	h := recordHeaders(t, "POST", "/oauth/token")
	if h.Get("Strict-Transport-Security") == "" {
		t.Error("expected HSTS header on POST /oauth/token")
	}
}

// ---------------------------------------------------------------------------
// H-05: Content-Security-Policy
// ---------------------------------------------------------------------------

func TestSecurityHeaders_CSP_Present(t *testing.T) {
	h := recordHeaders(t, "GET", "/")
	if got := h.Get("Content-Security-Policy"); got == "" {
		t.Error("expected Content-Security-Policy header to be set")
	}
}

func TestSecurityHeaders_CSP_DefaultSrcSelf(t *testing.T) {
	got := recordHeaders(t, "GET", "/").Get("Content-Security-Policy")
	if !strings.Contains(got, "default-src 'self'") {
		t.Errorf("CSP must contain \"default-src 'self'\", got: %q", got)
	}
}

func TestSecurityHeaders_CSP_ScriptSrcSelf_NoUnsafeInline(t *testing.T) {
	got := recordHeaders(t, "GET", "/").Get("Content-Security-Policy")
	if !strings.Contains(got, "script-src 'self'") {
		t.Errorf("CSP script-src must be 'self', got: %q", got)
	}
	// 'unsafe-inline' in script-src allows inline script execution — XSS.
	// We must NOT have it in the script-src directive specifically.
	// (It IS allowed in style-src for form pages.)
	directives := strings.Split(got, ";")
	for _, d := range directives {
		d = strings.TrimSpace(d)
		if strings.HasPrefix(d, "script-src") && strings.Contains(d, "'unsafe-inline'") {
			t.Errorf("script-src must not contain 'unsafe-inline', got directive: %q", d)
		}
	}
}

func TestSecurityHeaders_CSP_FrameAncestorsNone(t *testing.T) {
	// frame-ancestors 'none' prevents the auth pages from being embedded in
	// iframes (click-jacking protection, superseding X-Frame-Options: DENY).
	got := recordHeaders(t, "GET", "/").Get("Content-Security-Policy")
	if !strings.Contains(got, "frame-ancestors 'none'") {
		t.Errorf("CSP must contain \"frame-ancestors 'none'\", got: %q", got)
	}
}

func TestSecurityHeaders_CSP_FormActionSelf(t *testing.T) {
	// form-action 'self' prevents forms from being submitted to attacker-
	// controlled endpoints even if a CSP bypass exists.
	got := recordHeaders(t, "GET", "/").Get("Content-Security-Policy")
	if !strings.Contains(got, "form-action 'self'") {
		t.Errorf("CSP must contain \"form-action 'self'\", got: %q", got)
	}
}

func TestSecurityHeaders_CSP_BaseURISelf(t *testing.T) {
	// base-uri 'self' prevents <base> tag injection (base URL hijacking).
	got := recordHeaders(t, "GET", "/").Get("Content-Security-Policy")
	if !strings.Contains(got, "base-uri 'self'") {
		t.Errorf("CSP must contain \"base-uri 'self'\", got: %q", got)
	}
}

func TestSecurityHeaders_CSP_ConnectSrcSelf(t *testing.T) {
	got := recordHeaders(t, "GET", "/").Get("Content-Security-Policy")
	if !strings.Contains(got, "connect-src 'self'") {
		t.Errorf("CSP must contain \"connect-src 'self'\", got: %q", got)
	}
}

func TestSecurityHeaders_CSP_AppliedToAllPaths(t *testing.T) {
	paths := []string{"/", "/oauth/authorize", "/oauth/token", "/.well-known/jwks.json"}
	for _, p := range paths {
		t.Run(p, func(t *testing.T) {
			h := recordHeaders(t, "GET", p)
			if h.Get("Content-Security-Policy") == "" {
				t.Errorf("expected CSP header on path %s", p)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Pre-existing headers: ensure they are not removed by H-04/H-05 changes
// ---------------------------------------------------------------------------

func TestSecurityHeaders_XFrameOptions_StillPresent(t *testing.T) {
	got := recordHeaders(t, "GET", "/").Get("X-Frame-Options")
	if got != "DENY" {
		t.Errorf("expected X-Frame-Options: DENY, got: %q", got)
	}
}

func TestSecurityHeaders_XContentTypeOptions_StillPresent(t *testing.T) {
	got := recordHeaders(t, "GET", "/").Get("X-Content-Type-Options")
	if got != "nosniff" {
		t.Errorf("expected X-Content-Type-Options: nosniff, got: %q", got)
	}
}

func TestSecurityHeaders_ReferrerPolicy_StillPresent(t *testing.T) {
	got := recordHeaders(t, "GET", "/").Get("Referrer-Policy")
	if got != "strict-origin-when-cross-origin" {
		t.Errorf("unexpected Referrer-Policy: %q", got)
	}
}

// ---------------------------------------------------------------------------
// Middleware chaining: downstream handler still receives the request
// ---------------------------------------------------------------------------

func TestSecurityHeaders_CallsNextHandler(t *testing.T) {
	called := false
	downstream := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusNoContent)
	})

	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	SecurityHeaders()(downstream).ServeHTTP(rec, req)

	if !called {
		t.Error("expected SecurityHeaders to call the next handler")
	}
	if rec.Code != http.StatusNoContent {
		t.Errorf("expected downstream status 204, got %d", rec.Code)
	}
}
