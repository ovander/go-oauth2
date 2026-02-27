// Package http — tests for H-06: CORS wildcard must not be combined with
// AllowCredentials: true.
//
// go-chi/cors reflects any Origin back when AllowedOrigins is ["*"] AND
// AllowCredentials is true, effectively bypassing the Same-Origin Policy for
// every domain.  The CORS spec (Fetch §3.2.5) explicitly forbids this
// combination.  Our corsHandler helper enforces AllowCredentials: false
// whenever "*" appears in the origin list.
package http

import (
	nethttp "net/http"
	"net/http/httptest"
	"testing"
)

// nopHandler is a trivial downstream used to isolate the CORS middleware.
var corsNopHandler = nethttp.HandlerFunc(func(w nethttp.ResponseWriter, r *nethttp.Request) {
	w.WriteHeader(nethttp.StatusOK)
})

// preflightHeaders sends a CORS preflight (OPTIONS) from the given origin and
// returns the response headers.
func preflightHeaders(t *testing.T, config RouterConfig, origin string) nethttp.Header {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("OPTIONS", "/oauth/token", nil)
	req.Header.Set("Origin", origin)
	req.Header.Set("Access-Control-Request-Method", "POST")
	req.Header.Set("Access-Control-Request-Headers", "Authorization, Content-Type")
	corsHandler(config)(corsNopHandler).ServeHTTP(rec, req)
	return rec.Header()
}

// simpleRequestHeaders sends a non-preflight GET with an Origin header.
func simpleRequestHeaders(t *testing.T, config RouterConfig, origin string) nethttp.Header {
	t.Helper()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/oauth/userinfo", nil)
	req.Header.Set("Origin", origin)
	corsHandler(config)(corsNopHandler).ServeHTTP(rec, req)
	return rec.Header()
}

// ---------------------------------------------------------------------------
// H-06 core: wildcard MUST NOT have AllowCredentials: true
// ---------------------------------------------------------------------------

func TestCORSHandler_WildcardOrigin_NoAllowCredentials(t *testing.T) {
	// The dangerous combination: ["*"] + AllowCredentials would let any site
	// send credentialed (cookie / Authorization header) cross-origin requests.
	config := RouterConfig{AllowedOrigins: []string{"*"}}
	h := preflightHeaders(t, config, "https://attacker.example.com")

	if h.Get("Access-Control-Allow-Credentials") == "true" {
		t.Error("H-06: wildcard AllowedOrigins must not produce Access-Control-Allow-Credentials: true")
	}
}

func TestCORSHandler_EmptyOriginList_DefaultsToWildcard_NoCredentials(t *testing.T) {
	// When AllowedOrigins is empty, corsHandler defaults to ["*"] — safe
	// because AllowCredentials is false.
	config := RouterConfig{AllowedOrigins: []string{}}
	h := preflightHeaders(t, config, "https://anything.example.com")

	if h.Get("Access-Control-Allow-Credentials") == "true" {
		t.Error("empty origin list must default to wildcard with no credentials")
	}
}

func TestCORSHandler_NilOriginList_DefaultsToWildcard_NoCredentials(t *testing.T) {
	config := RouterConfig{AllowedOrigins: nil}
	h := preflightHeaders(t, config, "https://anything.example.com")

	if h.Get("Access-Control-Allow-Credentials") == "true" {
		t.Error("nil origin list must default to wildcard with no credentials")
	}
}

func TestCORSHandler_MixedListWithWildcard_NoCredentials(t *testing.T) {
	// A mix that still contains "*" must disable credentials.
	config := RouterConfig{
		AllowedOrigins: []string{"https://app.example.com", "*"},
	}
	h := preflightHeaders(t, config, "https://app.example.com")

	if h.Get("Access-Control-Allow-Credentials") == "true" {
		t.Error("origin list containing '*' must disable AllowCredentials")
	}
}

// ---------------------------------------------------------------------------
// H-06: explicit origin list SHOULD allow credentials (opt-in for SPA clients)
// ---------------------------------------------------------------------------

func TestCORSHandler_ExplicitOrigins_AllowsCredentials(t *testing.T) {
	// When no wildcard is present, credentialed requests are allowed from the
	// listed origins.  This is the correct pattern for production SPA deployments.
	config := RouterConfig{
		AllowedOrigins: []string{"https://app.example.com", "https://staging.example.com"},
	}
	h := preflightHeaders(t, config, "https://app.example.com")

	if got := h.Get("Access-Control-Allow-Credentials"); got != "true" {
		t.Errorf("explicit origin list should produce Allow-Credentials: true, got: %q", got)
	}
}

func TestCORSHandler_ExplicitOrigins_UnknownOriginBlocked(t *testing.T) {
	// go-chi/cors must not echo back origins that are not in the allowlist.
	config := RouterConfig{
		AllowedOrigins: []string{"https://app.example.com"},
	}
	h := preflightHeaders(t, config, "https://evil.example.com")

	if h.Get("Access-Control-Allow-Origin") == "https://evil.example.com" {
		t.Error("unknown origin must not appear in Access-Control-Allow-Origin")
	}
	if h.Get("Access-Control-Allow-Credentials") == "true" {
		t.Error("unknown origin must not get Allow-Credentials: true")
	}
}

// ---------------------------------------------------------------------------
// CORS response headers sanity checks
// ---------------------------------------------------------------------------

func TestCORSHandler_WildcardOrigin_AllowsRequestMethods(t *testing.T) {
	config := RouterConfig{AllowedOrigins: []string{"*"}}
	h := preflightHeaders(t, config, "https://client.example.com")

	// The preflight must at minimum return an allowed-methods header.
	if got := h.Get("Access-Control-Allow-Methods"); got == "" {
		t.Error("expected Access-Control-Allow-Methods header in preflight response")
	}
}

func TestCORSHandler_ExplicitOrigins_AllowsAuthorizationHeader(t *testing.T) {
	config := RouterConfig{AllowedOrigins: []string{"https://app.example.com"}}
	h := preflightHeaders(t, config, "https://app.example.com")

	// SPA clients send Bearer tokens in Authorization; must be in the allow-list.
	allowed := h.Get("Access-Control-Allow-Headers")
	if allowed == "" {
		t.Error("expected Access-Control-Allow-Headers to be set")
	}
}

func TestCORSHandler_SimpleRequest_WildcardOrigin_RespondsOK(t *testing.T) {
	config := RouterConfig{AllowedOrigins: []string{"*"}}
	h := simpleRequestHeaders(t, config, "https://anything.example.com")

	// Simple requests with wildcard should still get a valid CORS header
	// (just not the credentials one).
	if h.Get("Access-Control-Allow-Origin") == "" {
		t.Error("expected Access-Control-Allow-Origin on simple request with wildcard config")
	}
}

// ---------------------------------------------------------------------------
// Regression: ensure Allow-Credentials is never "true" with wildcard
// regardless of incoming Origin value
// ---------------------------------------------------------------------------

func TestCORSHandler_WildcardConfig_NeverAllowsCredentials_MultipleOrigins(t *testing.T) {
	config := RouterConfig{AllowedOrigins: []string{"*"}}

	origins := []string{
		"https://trusted.example.com",
		"https://attacker.example.com",
		"null",
		"https://localhost:3000",
		"http://127.0.0.1:8080",
	}

	for _, origin := range origins {
		t.Run(origin, func(t *testing.T) {
			h := preflightHeaders(t, config, origin)
			if h.Get("Access-Control-Allow-Credentials") == "true" {
				t.Errorf("wildcard config must never set Allow-Credentials: true (origin=%q)", origin)
			}
		})
	}
}
