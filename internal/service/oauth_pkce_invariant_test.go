// Package service — tests for the public-client PKCE invariant (OAuth 2.1):
// a public client (IsPublic=true) must require PKCE at the point of use even if
// its RequirePKCE flag is somehow false, via App.PKCERequired().
package service

import (
	"context"
	"errors"
	"testing"

	"github.com/ovander/go-oauth2/internal/dto"
	"github.com/ovander/go-oauth2/internal/model"
)

// A public client with RequirePKCE=false must still be rejected at the
// authorization endpoint when no code_challenge is supplied.
func TestPKCEInvariant_PublicClient_RequirePKCEFalse_StillRejected(t *testing.T) {
	user := &model.User{ID: 21, Email: "pub@example.com", TokenVersion: 1}
	app := &model.App{
		ID:           12,
		ClientID:     "public-no-flag",
		Active:       true,
		IsPublic:     true,  // public client
		RequirePKCE:  false, // flag somehow cleared
		RedirectURIs: model.StringArray{"https://app.example.com/cb"},
	}
	svc, _ := newMedSvc(t, newMemUsedTokenRepo(), app, user)

	req := dto.AuthorizeRequest{
		ResponseType: "code",
		ClientID:     "public-no-flag",
		RedirectURI:  "https://app.example.com/cb",
		Scope:        "openid",
		State:        "s",
		// CodeChallenge intentionally empty
	}
	_, err := svc.Authorize(context.Background(), req, user.ID)
	if !errors.Is(err, ErrPKCERequired) {
		t.Fatalf("public client must require PKCE regardless of the flag, got %v", err)
	}
}

func TestApp_PKCERequired(t *testing.T) {
	cases := []struct {
		name        string
		requirePKCE bool
		isPublic    bool
		secretHash  string
		want        bool
	}{
		{"explicit flag", true, false, "h", true},
		{"public client", false, true, "", true},
		{"public and flag", true, true, "", true},
		{"confidential, no flag", false, false, "h", false},
		// Not flagged public, but no secret to authenticate with (#366): PKCE
		// is the only proof the code is redeemed by whoever asked for it.
		{"non-public without a secret", false, false, "", true},
	}
	for _, c := range cases {
		a := &model.App{RequirePKCE: c.requirePKCE, IsPublic: c.isPublic, ClientSecretHash: c.secretHash}
		if got := a.PKCERequired(); got != c.want {
			t.Errorf("%s: PKCERequired() = %v, want %v", c.name, got, c.want)
		}
	}
}

// A client not flagged public but stored without a secret cannot authenticate
// at the token endpoint, so it must use PKCE (#366): without a challenge its
// authorization request is refused. With a secret it may omit PKCE.
func TestPKCEInvariant_ClientWithoutASecret_MustUsePKCE(t *testing.T) {
	for name, tc := range map[string]struct {
		secretHash string
		wantPKCE   bool
	}{
		"no secret":   {"", true},
		"with secret": {"$2a$12$placeholderplaceholderplaceholderplaceholderplaceho", false},
	} {
		t.Run(name, func(t *testing.T) {
			user := &model.User{ID: 22, Email: "c@example.com", TokenVersion: 1}
			app := &model.App{
				ID: 13, ClientID: "no-secret", Active: true, IsPublic: false, RequirePKCE: false,
				ClientSecretHash: tc.secretHash, RedirectURIs: model.StringArray{"https://app.example.com/cb"},
			}
			svc, _ := newMedSvc(t, newMemUsedTokenRepo(), app, user)
			req := dto.AuthorizeRequest{ResponseType: "code", ClientID: "no-secret", RedirectURI: "https://app.example.com/cb", Scope: "openid", State: "s"}
			_, err := svc.Authorize(context.Background(), req, user.ID)
			if tc.wantPKCE {
				if !errors.Is(err, ErrPKCERequired) {
					t.Fatalf("Authorize without a challenge = %v, want ErrPKCERequired", err)
				}
				return
			}
			// With a secret, the request without a challenge is accepted.
			if err != nil {
				t.Fatalf("Authorize without a challenge for a client with a secret = %v, want a code", err)
			}
		})
	}
}
