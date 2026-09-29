package auth

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/pkg/logger"
)

// DefaultClaimsNamespace is the prefix applied to every mapped claim name when
// CLAIMS_NAMESPACE is not set. Namespacing is what makes custom claims safe:
// a mapping named `role` becomes `https://socrate/role`, so it can never be
// confused with — or overwrite — the registered `role` claim.
const DefaultClaimsNamespace = "https://socrate/"

// MaxCustomClaimsBytes caps the serialized size of the custom claims added to a
// single token. Tokens travel in Authorization headers and cookies, and a proxy
// that rejects oversized headers turns a bloated token into a hard outage; the
// cap keeps a client's mapping policy from doing that. On overflow the whole
// custom set is dropped (see MappingEnricher.CustomClaims) — the token is still
// issued and still valid, it simply carries the standard claim set.
const MaxCustomClaimsBytes = 2048

// ClaimsEnricher produces the custom (non-registered) claims for a token.
// TokenService calls it for the access and ID tokens; a nil enricher means no
// custom claims, which is the behaviour when no client declares a mapping.
type ClaimsEnricher interface {
	// CustomClaims returns the claims to merge into the token, already
	// namespaced and ready to serialize. target is model.ClaimTargetAccess or
	// model.ClaimTargetID. Returning nil adds nothing.
	CustomClaims(user *model.User, app *model.App, role string, target string) map[string]any
}

// MappingEnricher resolves a client's model.ClaimMappings against the user and
// app being issued for. It is stateless and safe for concurrent use.
type MappingEnricher struct {
	namespace string
	maxBytes  int
}

// NewMappingEnricher builds an enricher that namespaces mapped claims with
// namespace. An empty namespace falls back to DefaultClaimsNamespace; a
// namespace that does not end in a separator gets a trailing "/" so the claim
// name is always delimited.
func NewMappingEnricher(namespace string) *MappingEnricher {
	return &MappingEnricher{namespace: NormalizeClaimsNamespace(namespace), maxBytes: MaxCustomClaimsBytes}
}

// NormalizeClaimsNamespace trims, defaults and delimits a configured namespace.
func NormalizeClaimsNamespace(namespace string) string {
	ns := strings.TrimSpace(namespace)
	if ns == "" {
		return DefaultClaimsNamespace
	}
	if !strings.HasSuffix(ns, "/") && !strings.HasSuffix(ns, "#") && !strings.HasSuffix(ns, ":") {
		ns += "/"
	}
	return ns
}

// Namespace returns the prefix this enricher applies to mapped claim names.
func (e *MappingEnricher) Namespace() string {
	if e == nil {
		return DefaultClaimsNamespace
	}
	return e.namespace
}

// CustomClaims implements ClaimsEnricher. Mappings are walked in a stable order;
// a mapping whose source resolves to nothing is skipped (an absent attribute
// yields an absent claim rather than a null one). If the resulting set exceeds
// the size cap it is dropped entirely and the event is logged at error level —
// a truncated, non-deterministic claim set would be worse than none.
func (e *MappingEnricher) CustomClaims(user *model.User, app *model.App, role string, target string) map[string]any {
	if e == nil || app == nil || len(app.ClaimMappings) == 0 {
		return nil
	}

	out := make(map[string]any, len(app.ClaimMappings))
	for _, name := range app.ClaimMappings.Names() {
		mapping := app.ClaimMappings[name]
		if !mapping.WritesTo(target) {
			continue
		}
		value, ok := resolveClaimSource(mapping.Source, user, app, role)
		if !ok {
			continue
		}
		out[e.namespace+name] = value
	}

	if len(out) == 0 {
		return nil
	}

	if size, err := claimsSize(out); err != nil || size > e.maxBytes {
		logger.WithFields(logger.Fields{
			"client_id": app.ClientID,
			"target":    target,
			"claims":    len(out),
			"max_bytes": e.maxBytes,
		}).Error("A2: custom claims dropped — mapped claim set is oversized or not serializable")
		return nil
	}

	return out
}

// claimsSize reports the serialized size of the custom claim set.
func claimsSize(claims map[string]any) (int, error) {
	b, err := json.Marshal(claims)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

// resolveClaimSource reads one mapping source. The second return value is false
// when the source resolves to nothing (unknown attribute, empty role, …), which
// omits the claim entirely.
func resolveClaimSource(source string, user *model.User, app *model.App, role string) (any, bool) {
	switch {
	case strings.HasPrefix(source, model.ClaimSourceLiteralPrefix):
		return strings.TrimPrefix(source, model.ClaimSourceLiteralPrefix), true

	case strings.HasPrefix(source, model.ClaimSourceUserAttrPrefix):
		if user == nil || len(user.Attributes) == 0 {
			return nil, false
		}
		key := strings.TrimPrefix(source, model.ClaimSourceUserAttrPrefix)
		v, ok := user.Attributes[key]
		if !ok || v == nil {
			return nil, false
		}
		return v, true

	case source == model.ClaimSourceUserEmail:
		if user == nil || user.Email == "" {
			return nil, false
		}
		return user.Email, true

	case source == model.ClaimSourceUserName:
		if user == nil || user.Name == "" {
			return nil, false
		}
		return user.Name, true

	case source == model.ClaimSourceUserID:
		if user == nil || user.ID == 0 {
			return nil, false
		}
		return strconv.FormatUint(uint64(user.ID), 10), true

	case source == model.ClaimSourceAppRole:
		if role == "" {
			return nil, false
		}
		return role, true

	case source == model.ClaimSourceAppID:
		if app == nil || app.ID == 0 {
			return nil, false
		}
		return strconv.FormatUint(uint64(app.ID), 10), true

	case source == model.ClaimSourceAppClientID:
		if app == nil || app.ClientID == "" {
			return nil, false
		}
		return app.ClientID, true

	default:
		// Unknown sources are refused at write time (model.ValidateClaimMappings);
		// a policy stored before a source was retired simply yields no claim.
		return nil, false
	}
}
