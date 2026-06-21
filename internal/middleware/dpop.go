package middleware

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/ovandermoten/go-oauth2/internal/contextkeys"
	"github.com/ovandermoten/go-oauth2/internal/shared/auth/dpop"
	"github.com/ovandermoten/go-oauth2/pkg/logger"
)

// DPoPObserve verifies a DPoP proof (RFC 9449) carried in the `DPoP` request
// header and emits telemetry, without affecting the response — the "observe"
// step of the sender-constraint rollout (RFC-003). It never rejects a request:
// a missing, malformed, or replayed proof is logged and the request proceeds
// unchanged. Enforcement (rejecting unbound/invalid requests) and binding the
// issued token to the proof's key are later slices.
//
// mode is "off" (middleware is a pass-through), "observe", or "enforce"
// (currently treated as observe — telemetry only). htuBase is the canonical
// scheme://host of the server (the OAuth issuer); the verified htu is
// htuBase + the request path, which matches the published token-endpoint URL a
// client signs over, independent of proxy scheme rewriting.
func DPoPObserve(cache dpop.ReplayCache, mode, htuBase string) func(http.Handler) http.Handler {
	enabled := (mode == "observe" || mode == "enforce") && cache != nil
	base := strings.TrimRight(htuBase, "/")

	return func(next http.Handler) http.Handler {
		if !enabled {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if proofHdr := r.Header.Get("DPoP"); proofHdr != "" {
				htu := base + r.URL.Path
				proof, err := dpop.VerifyOnce(proofHdr, r.Method, htu, time.Now(), cache)
				if err != nil {
					logger.WithFields(logger.Fields{
						"event":  "dpop_proof_rejected",
						"mode":   mode,
						"path":   r.URL.Path,
						"reason": err.Error(),
					}).Warn("dpop: proof rejected (observe)")
				} else {
					logger.WithFields(logger.Fields{
						"event":   "dpop_proof_valid",
						"mode":    mode,
						"path":    r.URL.Path,
						"jkt":     jktPrefix(proof.Thumbprint),
						"jti_set": proof.JTI != "",
					}).Info("dpop: valid proof (observe)")
					// Make the verified thumbprint available to the token endpoint
					// so it can opportunistically sender-constrain the issued
					// access token (cnf.jkt). This never rejects the request.
					r = r.WithContext(context.WithValue(r.Context(), contextkeys.DPoPJKTKey, proof.Thumbprint))
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// jktPrefix returns a short, non-sensitive prefix of a JWK thumbprint for logs
// (the full value identifies a specific client key).
func jktPrefix(jkt string) string {
	if len(jkt) <= 8 {
		return jkt
	}
	return jkt[:8] + "…"
}
