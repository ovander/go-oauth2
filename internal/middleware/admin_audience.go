package middleware

import (
	"net/http"

	"github.com/ovander/go-oauth2/internal/contextkeys"
	"github.com/ovander/go-oauth2/internal/shared/auth"
)

// Admin API audience modes (ADMIN_API_AUDIENCE_MODE, M-03).
const (
	AdminAudienceOff     = "off"
	AdminAudienceObserve = "observe"
	AdminAudienceEnforce = "enforce"
)

// AdminAudienceFunc is told about an admin API call whose token was not issued
// to an accepted client: clientID is the token's aud[0] (empty when absent),
// refused is true under enforce.
type AdminAudienceFunc func(r *http.Request, clientID string, refused bool)

// RequireAdminAudience confines the admin API to tokens issued to the operator
// consoles (M-03). AuthMiddleware only proves that the token is a valid Socrate
// access token of a global admin; without this gate a token the same admin got
// from any application — held by that application's backend — is a full
// admin-API credential. The token's client is aud[0] (the token contract), and
// accepted lists the console client_ids plus Socrate's own admin-portal
// audience.
//
// "off" passes every request; "observe" passes it but reports a mismatch;
// "enforce" refuses a mismatch with 403 invalid_audience. Under enforce a
// request without claims is refused too (fail closed). Must run after
// AuthMiddleware, which stores the claims under contextkeys.JWTClaimsKey.
func RequireAdminAudience(mode string, accepted []string, onMismatch AdminAudienceFunc) func(http.Handler) http.Handler {
	allowed := make(map[string]struct{}, len(accepted))
	for _, id := range accepted {
		if id != "" {
			allowed[id] = struct{}{}
		}
	}
	return func(next http.Handler) http.Handler {
		if mode != AdminAudienceObserve && mode != AdminAudienceEnforce {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			clientID := ""
			if claims, ok := r.Context().Value(contextkeys.JWTClaimsKey).(*auth.AccessTokenClaims); ok && claims != nil && len(claims.Audience) > 0 {
				clientID = claims.Audience[0]
			}
			if _, ok := allowed[clientID]; ok && clientID != "" {
				next.ServeHTTP(w, r)
				return
			}
			refused := mode == AdminAudienceEnforce
			if onMismatch != nil {
				onMismatch(r, clientID, refused)
			}
			if refused {
				writeAuthError(w, "invalid_audience", http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
