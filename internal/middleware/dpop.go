package middleware

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/ovandermoten/go-oauth2/internal/contextkeys"
	"github.com/ovandermoten/go-oauth2/internal/shared/auth/dpop"
	"github.com/ovandermoten/go-oauth2/pkg/logger"
)

// DPoP verifies a DPoP proof (RFC 9449) carried in the `DPoP` request header and
// applies the configured sender-constraint behaviour:
//
//   - "off": pass-through (the middleware does nothing).
//   - "observe": verify any proof and emit telemetry; a valid proof binds the
//     issued token (its thumbprint is placed on the request context), an
//     invalid proof is logged but the request still proceeds — nothing is ever
//     rejected.
//   - "enforce": same as observe, but a proof that is *present and invalid* is
//     rejected with `400 invalid_dpop_proof` (RFC 9449 §5). A request with no
//     proof still proceeds (requiring DPoP per client is a later slice), so
//     existing non-DPoP clients are unaffected.
//
// htuBase is the canonical scheme://host of the server (the OAuth issuer); the
// verified htu is htuBase + the request path, which matches the published
// token-endpoint URL a client signs over, independent of proxy scheme rewriting.
func DPoP(cache dpop.ReplayCache, mode, htuBase string) func(http.Handler) http.Handler {
	enabled := (mode == "observe" || mode == "enforce") && cache != nil
	enforce := mode == "enforce"
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
						"event":   "dpop_proof_rejected",
						"mode":    mode,
						"path":    r.URL.Path,
						"reason":  err.Error(),
						"blocked": enforce,
					}).Warn("dpop: proof rejected")
					if enforce {
						writeDPoPError(w)
						return
					}
				} else {
					logger.WithFields(logger.Fields{
						"event":   "dpop_proof_valid",
						"mode":    mode,
						"path":    r.URL.Path,
						"jkt":     jktPrefix(proof.Thumbprint),
						"jti_set": proof.JTI != "",
					}).Info("dpop: valid proof")
					// Make the verified thumbprint available to the token endpoint
					// so it can sender-constrain the issued access token (cnf.jkt).
					r = r.WithContext(context.WithValue(r.Context(), contextkeys.DPoPJKTKey, proof.Thumbprint))
				}
			}
			next.ServeHTTP(w, r)
		})
	}
}

// writeDPoPError writes the RFC 9449 §5 token-endpoint error for an invalid
// proof. The specific failure reason is logged, never returned to the client
// (consistent with the token endpoint's no-leak policy).
func writeDPoPError(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error":             "invalid_dpop_proof",
		"error_description": "the DPoP proof is missing or invalid",
	})
}

// jktPrefix returns a short, non-sensitive prefix of a JWK thumbprint for logs
// (the full value identifies a specific client key).
func jktPrefix(jkt string) string {
	if len(jkt) <= 8 {
		return jkt
	}
	return jkt[:8] + "…"
}
