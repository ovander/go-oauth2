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
}

// IsConfidential returns true when the client has a stored secret hash,
// i.e. it is a confidential client that must authenticate at the token endpoint.
func (a *App) IsConfidential() bool {
	return !a.IsPublic && a.ClientSecretHash != ""
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
