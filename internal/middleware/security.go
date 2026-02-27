package middleware

import (
	"net/http"
)

// SecurityHeaders adds security headers to all responses.
//
// H-04 fix: Strict-Transport-Security instructs browsers to only connect over
// HTTPS for the next year (includeSubDomains + preload-ready max-age).
//
// H-05 fix: Content-Security-Policy provides defence-in-depth against XSS on
// the server-rendered auth pages.  The policy is intentionally restrictive:
//   - default-src 'self'      — block all cross-origin fetches by default
//   - script-src 'self'       — no inline scripts, no eval
//   - style-src 'self' 'unsafe-inline' — inline styles needed for form pages
//   - img-src 'self' data:    — data URIs used by embedded icons
//   - font-src 'self'         — web fonts from same origin only
//   - connect-src 'self'      — XHR/fetch/WebSocket to same origin only
//   - frame-ancestors 'none'  — equivalent to X-Frame-Options: DENY
//   - base-uri 'self'         — prevent <base> tag injection
//   - form-action 'self'      — forms may only submit to same origin
func SecurityHeaders() func(http.Handler) http.Handler {
	const csp = "default-src 'self'; " +
		"script-src 'self'; " +
		"style-src 'self' 'unsafe-inline'; " +
		"img-src 'self' data:; " +
		"font-src 'self'; " +
		"connect-src 'self'; " +
		"frame-ancestors 'none'; " +
		"base-uri 'self'; " +
		"form-action 'self'"

	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Legacy click-jacking / sniff / XSS headers
			w.Header().Set("X-Frame-Options", "DENY")
			w.Header().Set("X-Content-Type-Options", "nosniff")
			w.Header().Set("X-XSS-Protection", "1; mode=block")
			w.Header().Set("Referrer-Policy", "strict-origin-when-cross-origin")
			w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

			// H-04: HSTS — tells browsers to enforce HTTPS for 1 year
			w.Header().Set("Strict-Transport-Security", "max-age=31536000; includeSubDomains")

			// H-05: Content Security Policy
			w.Header().Set("Content-Security-Policy", csp)

			next.ServeHTTP(w, r)
		})
	}
}

// NoCacheHeaders adds no-cache headers (for sensitive endpoints like token endpoints)
func NoCacheHeaders() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Cache-Control", "no-store")
			w.Header().Set("Pragma", "no-cache")

			next.ServeHTTP(w, r)
		})
	}
}

// JSONContentType sets the Content-Type header to application/json
func JSONContentType() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			next.ServeHTTP(w, r)
		})
	}
}
