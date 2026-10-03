package dto

import (
	"time"

	"github.com/ovander/go-oauth2/internal/model"
)

// Request DTOs

type CreateAppRequest struct {
	Name         string   `json:"name"`
	URL          *string  `json:"url,omitempty"`
	RedirectURIs []string `json:"redirect_uris"`
	// IsPublic marks this as a public client (SPA / mobile app).
	// No client_secret is generated; PKCE is automatically enforced.
	IsPublic    bool `json:"is_public"`
	RequirePKCE bool `json:"require_pkce"`
	// RequireDPoP mandates DPoP sender-constrained tokens (RFC 9449) for this
	// client at the token endpoint. Requires DPoP enabled globally (DPOP_MODE).
	RequireDPoP bool `json:"require_dpop"`
	// AllowTokenExchange / AllowImpersonation gate the RFC 8693 grant for this
	// client (delegation, and the higher-risk impersonation, respectively).
	AllowTokenExchange bool `json:"allow_token_exchange"`
	AllowImpersonation bool `json:"allow_impersonation"`
	// Audiences are the resource identifiers tokens for this client are intended
	// for — the canonical `aud` claim (RFC-001 / EPIC-7). Optional; empty means
	// none registered.
	Audiences []string `json:"audiences,omitempty"`
	// AllowedScopes restricts which scopes this client may request (A1 / P3-8).
	// Every entry must be a supported scope. Empty = no restriction.
	AllowedScopes []string `json:"allowed_scopes,omitempty"`
	// ClaimMappings declares the custom claims this client's tokens carry (A2),
	// keyed by the unqualified claim name. Each value is either a source string
	// ("user.attributes.tier") or an object ({"source":…,"target":"both"}).
	// Empty = the standard claim set only.
	ClaimMappings model.ClaimMappings `json:"claim_mappings,omitempty"`
	// MagicLinkURL is the app's page that magic-link emails open (token and
	// client_id are added to its query). Absolute https URL (http only for
	// localhost), no fragment, same origin as one of redirect_uris. Optional;
	// without it the app cannot send magic links.
	MagicLinkURL *string `json:"magic_link_url,omitempty"`
	// AccessTokenTTLSeconds shortens the access tokens issued to this client,
	// 60 to 86400 seconds; the server-wide ACCESS_TOKEN_TTL stays the maximum.
	// Optional; without it the server-wide value applies.
	AccessTokenTTLSeconds *int `json:"access_token_ttl_seconds,omitempty"`
}

type UpdateAppRequest struct {
	Name         *string  `json:"name,omitempty"`
	URL          *string  `json:"url,omitempty"`
	RedirectURIs []string `json:"redirect_uris,omitempty"`
	Active       *bool    `json:"active,omitempty"`
	// RequireDPoP toggles the per-client DPoP requirement (RFC 9449). Omitted =
	// unchanged.
	RequireDPoP *bool `json:"require_dpop,omitempty"`
	// AllowTokenExchange / AllowImpersonation toggle the RFC 8693 grant for this
	// client. Omitted = unchanged.
	AllowTokenExchange *bool `json:"allow_token_exchange,omitempty"`
	AllowImpersonation *bool `json:"allow_impersonation,omitempty"`
	// Audiences replaces the client's registered resource identifiers (RFC-001 /
	// EPIC-7). Omitted (nil) = unchanged; a non-nil value (including an empty
	// array) replaces the set.
	Audiences *[]string `json:"audiences,omitempty"`
	// AllowedScopes replaces the client's scope policy (A1). Omitted (nil) =
	// unchanged; an empty array clears the restriction.
	AllowedScopes *[]string `json:"allowed_scopes,omitempty"`
	// ClaimMappings replaces the client's custom-claim policy (A2). Omitted
	// (nil) = unchanged; an empty object clears every mapping.
	ClaimMappings *model.ClaimMappings `json:"claim_mappings,omitempty"`
	// MagicLinkURL replaces the page magic-link emails open. Omitted (nil) =
	// unchanged; an empty string clears it (magic links are then refused).
	MagicLinkURL *string `json:"magic_link_url,omitempty"`
	// AccessTokenTTLSeconds replaces the client's access-token lifetime, 60 to
	// 86400 seconds. Omitted (nil) = unchanged; 0 clears it (the server-wide
	// ACCESS_TOKEN_TTL applies again).
	AccessTokenTTLSeconds *int `json:"access_token_ttl_seconds,omitempty"`
}

type AddAppUserRequest struct {
	Email string `json:"email"`
	Name  string `json:"name,omitempty"`
	Role  string `json:"role"`
}

type UpdateAppUserRoleRequest struct {
	Role string `json:"role"`
}

// Response DTOs

type AppResponse struct {
	ID                 uint     `json:"id"`
	Name               string   `json:"name"`
	ClientID           string   `json:"client_id"`
	Active             bool     `json:"active"`
	IsPublic           bool     `json:"is_public"`
	RequirePKCE        bool     `json:"require_pkce"`
	RequireDPoP        bool     `json:"require_dpop"`
	AllowTokenExchange bool     `json:"allow_token_exchange"`
	AllowImpersonation bool     `json:"allow_impersonation"`
	Audiences          []string `json:"audiences"`
	AllowedScopes      []string `json:"allowed_scopes"`
	// ClaimMappings is the client's custom-claim policy (A2).
	ClaimMappings model.ClaimMappings `json:"claim_mappings"`
	URL           *string             `json:"url,omitempty"`
	RedirectURIs  []string            `json:"redirect_uris"`
	// MagicLinkURL is the page magic-link emails open; absent when not configured.
	MagicLinkURL *string   `json:"magic_link_url,omitempty"`
	OwnerID      *uint     `json:"owner_id,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	// AccessTokenTTLSeconds is the client's own access-token lifetime; absent
	// when the server-wide ACCESS_TOKEN_TTL applies. A value above it has no
	// effect: tokens never outlive the server-wide maximum.
	AccessTokenTTLSeconds *int `json:"access_token_ttl_seconds,omitempty"`
}

type AppWithSecretResponse struct {
	AppResponse
	ClientSecret string `json:"client_secret"` // Only returned once on creation/rotation
}

type AppUserResponse struct {
	ID         uint       `json:"id"`
	Email      string     `json:"email"`
	Name       string     `json:"name"`
	Role       string     `json:"role"`
	IsVerified bool       `json:"is_verified"`
	InviteSent bool       `json:"invite_sent"`
	AvatarURL  *string    `json:"avatar_url,omitempty"`
	LastLogin  *time.Time `json:"last_login,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`

	// TokenVersion and Locked are set by the single-member look-up only
	// (omitted from lists). A token whose token_version claim is lower than
	// TokenVersion was revoked (logout, password change, block); a resource
	// server can compare the two with its service-account token instead of
	// introspecting every user token.
	TokenVersion *int  `json:"token_version,omitempty"`
	Locked       *bool `json:"locked,omitempty"`
}

type AppUserListResponse struct {
	Users      []AppUserResponse `json:"users"`
	TotalCount int64             `json:"total_count"`
	Page       int               `json:"page"`
	PageSize   int               `json:"page_size"`
}

type AppListResponse struct {
	Apps       []AppResponse `json:"apps"`
	TotalCount int64         `json:"total_count"`
}

// Admin Log DTOs

type AdminLogResponse struct {
	ID           uint                   `json:"id"`
	AdminID      uint                   `json:"admin_id"`
	AppID        *uint                  `json:"app_id,omitempty"`
	TargetUserID *uint                  `json:"target_user_id,omitempty"`
	Action       string                 `json:"action"`
	Details      map[string]interface{} `json:"details"`
	CreatedAt    time.Time              `json:"created_at"`
}

type AdminLogListResponse struct {
	Logs       []AdminLogResponse `json:"logs"`
	TotalCount int64              `json:"total_count"`
	Page       int                `json:"page"`
	PageSize   int                `json:"page_size"`
}

// App Activity Log DTOs

type AppActivityLogResponse struct {
	ID            uint                   `json:"id"`
	AppID         uint                   `json:"app_id"`
	UserID        *uint                  `json:"user_id,omitempty"`
	EventType     string                 `json:"event_type"`
	EventCategory string                 `json:"event_category"`
	Metadata      map[string]interface{} `json:"metadata"`
	IPAddress     *string                `json:"ip_address,omitempty"`
	UserAgent     *string                `json:"user_agent,omitempty"`
	Success       bool                   `json:"success"`
	CreatedAt     time.Time              `json:"created_at"`
}

type AppActivityLogListResponse struct {
	Logs       []AppActivityLogResponse `json:"logs"`
	TotalCount int64                    `json:"total_count"`
	Page       int                      `json:"page"`
	PageSize   int                      `json:"page_size"`
}
