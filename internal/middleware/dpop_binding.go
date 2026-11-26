package middleware

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/ovander/go-oauth2/internal/shared/auth"
	"github.com/ovander/go-oauth2/internal/shared/auth/dpop"
	"github.com/ovander/go-oauth2/pkg/logger"
)

// DPoPBinding checks DPoP-bound access tokens (cnf.jkt) presented to
// Socrate's own APIs (RFC 9449 §7.1). A bound token must come with a DPoP
// proof for the request, signed by the key the token is bound to and carrying
// ath, the token's hash; the proof is single use. An unbound token is not
// affected. The token may be sent with the DPoP or the Bearer scheme: the
// token endpoint answers token_type "Bearer" for bound tokens too (the token
// contract), so a client may well use that scheme, and the proof, not the
// scheme name, is what shows possession of the key.
//
// It follows DPOP_MODE: "observe" reports a failed check (log and onFail) and
// lets the request through; "enforce" also refuses it with 401 and a
// WWW-Authenticate: DPoP challenge. Any other mode, or no replay cache, gives a
// nil *DPoPBinding, which checks nothing and does not accept the DPoP scheme
// (unchanged behaviour).
//
// The proof's htu is checked against htuBase (the issuer's scheme://host) plus
// the request path, as at the token endpoint.
type DPoPBinding struct {
	enforce bool
	cache   dpop.ReplayCache
	base    string
	onFail  DPoPRejectFunc
}

// NewDPoPBinding returns the check for mode, or nil when the mode is neither
// "observe" nor "enforce" or cache is nil.
func NewDPoPBinding(cache dpop.ReplayCache, mode, htuBase string, onFail DPoPRejectFunc) *DPoPBinding {
	if (mode != "observe" && mode != "enforce") || cache == nil {
		return nil
	}
	return &DPoPBinding{enforce: mode == "enforce", cache: cache, base: strings.TrimRight(htuBase, "/"), onFail: onFail}
}

// tokenFromAuthorization returns the token of an Authorization header with the
// Bearer scheme, or the DPoP scheme when binding is enabled (b != nil). ok is
// false for any other form.
func (b *DPoPBinding) tokenFromAuthorization(header string) (token string, ok bool) {
	scheme, token, found := strings.Cut(header, " ")
	if !found || token == "" {
		return "", false
	}
	if scheme == "Bearer" || (b != nil && strings.EqualFold(scheme, "DPoP")) {
		return token, true
	}
	return "", false
}

// failure says why the request's token fails its binding, or "" when the
// token is unbound or the proof is valid.
func (b *DPoPBinding) failure(r *http.Request, token string, claims *auth.AccessTokenClaims) string {
	if claims == nil || claims.Cnf == nil || claims.Cnf.JKT == "" {
		return ""
	}
	proofs := r.Header.Values("DPoP")
	if len(proofs) != 1 || proofs[0] == "" {
		return "missing or repeated DPoP proof"
	}
	if _, err := dpop.VerifyForResource(proofs[0], r.Method, b.base+r.URL.Path, token, claims.Cnf.JKT, time.Now(), b.cache); err != nil {
		return err.Error()
	}
	return ""
}

// allow checks the binding of a verified token. It returns false, having
// written the 401, when the request must stop (enforce); a failure in
// observe mode is reported and allowed. A nil b allows everything.
func (b *DPoPBinding) allow(w http.ResponseWriter, r *http.Request, token string, claims *auth.AccessTokenClaims) bool {
	if b.accepts(r, token, claims) {
		return true
	}
	writeDPoPChallenge(w)
	return false
}

// accepts reports whether a verified token may be used for r: true when it is
// unbound, its proof is valid, or the mode is observe (the failure is then
// reported). A failure is logged and reported to onFail. A nil b accepts
// everything.
func (b *DPoPBinding) accepts(r *http.Request, token string, claims *auth.AccessTokenClaims) bool {
	if b == nil {
		return true
	}
	reason := b.failure(r, token, claims)
	if reason == "" {
		return true
	}
	logger.WithFields(logger.Fields{
		"event":   "dpop_binding_failed",
		"path":    r.URL.Path,
		"reason":  reason,
		"blocked": b.enforce,
	}).Warn("dpop: bound token used without a valid proof")
	if b.onFail != nil {
		b.onFail(r, reason, b.enforce)
	}
	return !b.enforce
}

// writeDPoPChallenge answers 401 with the RFC 9449 §7.1 challenge for a bound
// token without a valid proof. It does not use writeAuthError, which sets a
// Bearer challenge.
func writeDPoPChallenge(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("WWW-Authenticate", `DPoP error="invalid_token", error_description="a DPoP-bound token needs a valid DPoP proof", algs="ES256"`)
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(struct {
		Error string `json:"error"`
	}{Error: "a DPoP-bound token needs a valid DPoP proof"})
}
