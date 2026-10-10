package model

import (
	"strings"
	"time"
)

type App struct {
	ID               uint        `gorm:"primaryKey" json:"id"`
	Name             string      `gorm:"not null" json:"name"`
	ClientID         string      `gorm:"column:client_id;uniqueIndex;not null" json:"client_id"`
	ClientSecretHash string      `gorm:"column:client_secret_hash" json:"-"`
	Active           bool        `gorm:"default:true" json:"active"`
	URL              *string     `json:"url,omitempty"`
	RedirectURIs     StringArray `gorm:"type:text[];column:redirect_uris" json:"redirect_uris"`
	OwnerID          *uint       `gorm:"column:owner_id" json:"owner_id,omitempty"`
	Owner            *User       `gorm:"foreignKey:OwnerID" json:"owner,omitempty"`
	CreatedAt        time.Time   `gorm:"column:inserted_at" json:"created_at"`
	UpdatedAt        time.Time   `json:"updated_at"`

	// MED-02: RequirePKCE forces PKCE (RFC 7636) on every authorization
	// request for this client.  Set to true for public clients (SPAs, mobile
	// apps) that cannot keep a client secret.  Per OAuth 2.1, PKCE MUST be
	// required for all public clients.
	RequirePKCE bool `gorm:"column:require_pkce;default:false" json:"require_pkce"`

	// IsPublic marks this client as a public client (SPA, mobile app) that
	// cannot keep a client secret (RFC 6749 §2.1).  When true, no client
	// secret is generated or stored at creation time (ClientSecretHash is
	// empty) and the token endpoint never requires one.  PKCE is always
	// enforced for public clients regardless of the RequirePKCE flag.
	IsPublic bool `gorm:"column:is_public;default:false" json:"is_public"`

	// RequireDPoP forces DPoP sender-constrained tokens (RFC 9449) for this
	// client: a token request that does not carry a valid DPoP proof is
	// rejected. Requires DPoP to be enabled globally (DPOP_MODE != off) for the
	// proof to be verified; with DPoP disabled, a require_dpop client cannot
	// obtain tokens.
	RequireDPoP bool `gorm:"column:require_dpop;default:false" json:"require_dpop"`

	// AllowTokenExchange permits this client to use the RFC 8693 token-exchange
	// grant (delegation). Default false (the grant is denied). Even when true,
	// every exchange is still subject to the downscope/audience policy and is
	// audited. EPIC-16 / RFC-019.
	AllowTokenExchange bool `gorm:"column:allow_token_exchange;default:false" json:"allow_token_exchange"`

	// AllowImpersonation permits this client to perform impersonation (a token
	// exchange with no actor_token, where the actor assumes the subject's
	// identity) — the higher-risk case. Default false. Requires
	// AllowTokenExchange; delegation (actor present) does not need this flag.
	AllowImpersonation bool `gorm:"column:allow_impersonation;default:false" json:"allow_impersonation"`

	// Audiences are the resource identifiers (e.g. API URIs) that tokens issued
	// for this client are intended for — the canonical `aud` claim per RFC-001 /
	// EPIC-7. Empty means none registered (the current behaviour, where `aud`
	// carries the client_id). This is registration only; token issuance and
	// resource-server enforcement are layered in later (warn → enforce) slices.
	Audiences StringArray `gorm:"type:text[];column:audiences" json:"audiences"`

	// AllowedScopes is the per-client scope policy (A1 / P3-8): the only scopes
	// this client may request at /oauth/authorize and at every token grant.
	// Empty means "every supported scope" so existing registrations keep
	// working; SCOPE_POLICY_MODE decides whether a violation is ignored (off),
	// audited (observe) or refused with invalid_scope (enforce). It also
	// registers application-defined scopes (#336, "<namespace>:<name>"), which
	// are valid only for the clients that list them, in every mode.
	AllowedScopes StringArray `gorm:"type:text[];column:allowed_scopes" json:"allowed_scopes"`

	// ClaimMappings is the per-client custom-claim policy (A2): which
	// server-held values are projected into this client's tokens, and under
	// which claim name. Names are namespaced with CLAIMS_NAMESPACE at issuance
	// so a mapping can never shadow a registered claim. Empty (the default)
	// means the client's tokens carry exactly the standard claim set.
	ClaimMappings ClaimMappings `gorm:"type:jsonb;column:claim_mappings" json:"claim_mappings"`

	// MagicLinkURL is the app's own page that a magic-link email opens (with
	// token and client_id added to its query); that page posts the token to
	// POST /api/auth/magic-link/verify, which is POST-only so that mail
	// scanners following links cannot consume it. It must share an origin with
	// one of RedirectURIs. Nil means magic links are not configured for this
	// app, and a request for one is refused instead of emailing a dead link.
	MagicLinkURL *string `gorm:"column:magic_link_url" json:"magic_link_url,omitempty"`

	// AccessTokenTTLSeconds shortens the lifetime of the access tokens issued
	// to this client (user tokens and client_credentials tokens alike). It can
	// only shorten: the server-wide ACCESS_TOKEN_TTL stays the maximum. Nil
	// means the server-wide value.
	AccessTokenTTLSeconds *int `gorm:"column:access_token_ttl_seconds" json:"access_token_ttl_seconds,omitempty"`
}

// ScopeAllowed reports whether the client may request scope under its
// AllowedScopes policy. An empty policy allows everything (registration-time
// default; validation of the scope name itself happens elsewhere).
func (a *App) ScopeAllowed(scope string) bool {
	if len(a.AllowedScopes) == 0 {
		return true
	}
	for _, s := range a.AllowedScopes {
		if s == scope {
			return true
		}
	}
	return false
}

// RegistersScope reports whether scope is listed, verbatim, in the client's
// AllowedScopes. Unlike ScopeAllowed, an empty policy registers nothing: an
// application-defined scope (#336) is valid only for a client that lists it.
func (a *App) RegistersScope(scope string) bool {
	for _, s := range a.AllowedScopes {
		if s == scope {
			return true
		}
	}
	return false
}

// DeniedScopes returns the space-separated scopes in requested that the
// policy does not allow, in request order.
func (a *App) DeniedScopes(requested string) []string {
	var denied []string
	for _, s := range strings.Fields(requested) {
		if !a.ScopeAllowed(s) {
			denied = append(denied, s)
		}
	}
	return denied
}

// IsConfidential returns true when the client has a stored secret hash,
// i.e. it is a confidential client that must authenticate at the token endpoint.
func (a *App) IsConfidential() bool {
	return !a.IsPublic && a.ClientSecretHash != ""
}

// PKCERequired reports whether PKCE (RFC 7636) must be used for this client.
// It is true when the client opted in (RequirePKCE) OR is a public client —
// OAuth 2.1 mandates PKCE for public clients, so this enforces that invariant at
// the point of use rather than relying solely on the create-time default (so a
// public client can never authorize without PKCE even if its RequirePKCE flag
// were somehow cleared).
func (a *App) PKCERequired() bool {
	return a.RequirePKCE || a.IsPublic
}

func (App) TableName() string {
	return "apps"
}

func (a *App) HasRedirectURI(uri string) bool {
	needle := strings.TrimSpace(uri)
	for _, u := range a.RedirectURIs {
		if strings.TrimSpace(u) == needle {
			return true
		}
	}
	return false
}
