package middleware

import (
	"context"
	"net"
	"net/http"

	"github.com/ovander/go-oauth2/internal/contextkeys"
)

// ClientIP resolves the caller's IP address once per request, in a
// spoofing-resistant way, and stores it in the request context under
// contextkeys.IPAddressKey for GetClientIP to read.
//
// It replaces chi's middleware.RealIP (P3-2 / GO-2026-5775, GO-2026-5777),
// which rewrote r.RemoteAddr from True-Client-IP / X-Real-IP / X-Forwarded-For
// for ANY peer — letting any client pick the IP that rate limiting, IP
// blocking, auto-defense and audit attribution saw. ClientIP never mutates
// r.RemoteAddr and honours proxy headers only when the immediate peer is in
// trustedCIDRs (see GetClientIPSafe). It must run before any middleware or
// handler that attributes the request to an IP.
func ClientIP(trustedCIDRs []*net.IPNet) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ip := GetClientIPSafe(r, trustedCIDRs)
			ctx := context.WithValue(r.Context(), contextkeys.IPAddressKey, ip)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// GetClientIP returns the client IP resolved by the ClientIP middleware. When
// the middleware is not installed it falls back to the bare RemoteAddr and
// NEVER consults proxy headers — an unconfigured deployment therefore fails
// safe (attribution may collapse onto the proxy's address, but it cannot be
// spoofed). Security-sensitive callers that need explicit control over which
// proxies are trusted should call GetClientIPSafe directly.
func GetClientIP(r *http.Request) string {
	if ip, ok := r.Context().Value(contextkeys.IPAddressKey).(string); ok && ip != "" {
		return ip
	}
	return GetClientIPSafe(r, nil)
}
