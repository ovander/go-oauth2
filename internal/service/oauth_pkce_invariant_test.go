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
		want        bool
	}{
		{"explicit flag", true, false, true},
		{"public client", false, true, true},
		{"public and flag", true, true, true},
		{"confidential, no flag", false, false, false},
	}
	for _, c := range cases {
		a := &model.App{RequirePKCE: c.requirePKCE, IsPublic: c.isPublic}
		if got := a.PKCERequired(); got != c.want {
			t.Errorf("%s: PKCERequired() = %v, want %v", c.name, got, c.want)
		}
	}
}
