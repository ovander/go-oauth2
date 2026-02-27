package model

import (
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
}

func (App) TableName() string {
	return "apps"
}

func (a *App) HasRedirectURI(uri string) bool {
	for _, u := range a.RedirectURIs {
		if u == uri {
			return true
		}
	}
	return false
}
