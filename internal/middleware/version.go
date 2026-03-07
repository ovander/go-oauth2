package middleware

import (
	"net/http"

	"github.com/ovandermoten/go-oauth2/internal/version"
)

// AppVersion injects the build version into every response as X-App-Version.
// Useful during development and for ops to confirm which build is deployed.
func AppVersion(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-App-Version", version.Version)
		next.ServeHTTP(w, r)
	})
}
