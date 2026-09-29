// Package service — tests for EnsureAdminConsoleClient (Tier-0 admin session
// hardening, PR5). It idempotently registers the first-party admin console as a
// public, PKCE-mandatory client and is a no-op when disabled or already present.
package service

import (
	"context"
	"errors"
	"testing"

	"github.com/ovander/go-oauth2/internal/model"
)

type seedStore struct {
	existing *model.App
	created  *model.App
	findErr  error
}

func (s *seedStore) FindByClientID(_ context.Context, clientID string) (*model.App, error) {
	if s.existing != nil && s.existing.ClientID == clientID {
		return s.existing, nil
	}
	if s.findErr != nil {
		return nil, s.findErr
	}
	return nil, errors.New("not found")
}

func (s *seedStore) Create(_ context.Context, app *model.App) error {
	s.created = app
	return nil
}

func TestEnsureAdminConsoleClient_CreatesPublicPKCEClient(t *testing.T) {
	store := &seedStore{}
	created, err := EnsureAdminConsoleClient(context.Background(), store, "admin-console", []string{"https://admin.example.com/callback"})
	if err != nil || !created {
		t.Fatalf("expected creation, got created=%v err=%v", created, err)
	}
	c := store.created
	if c == nil {
		t.Fatal("no client was created")
	}
	if c.ClientID != "admin-console" || !c.IsPublic || !c.RequirePKCE || !c.Active {
		t.Errorf("seeded client must be public + PKCE + active, got %+v", c)
	}
	if c.ClientSecretHash != "" {
		t.Error("public client must have no secret")
	}
	if len(c.RedirectURIs) != 1 || c.RedirectURIs[0] != "https://admin.example.com/callback" {
		t.Errorf("redirect URIs not set from config: %v", c.RedirectURIs)
	}
}

func TestEnsureAdminConsoleClient_NoopWhenDisabled(t *testing.T) {
	store := &seedStore{}
	// No client id.
	if created, err := EnsureAdminConsoleClient(context.Background(), store, "", []string{"https://x/cb"}); created || err != nil {
		t.Errorf("empty client id must be a no-op, got created=%v err=%v", created, err)
	}
	// No redirect URIs.
	if created, err := EnsureAdminConsoleClient(context.Background(), store, "admin-console", nil); created || err != nil {
		t.Errorf("empty redirect URIs must be a no-op, got created=%v err=%v", created, err)
	}
	if store.created != nil {
		t.Error("nothing should have been created when disabled")
	}
}

func TestEnsureAdminConsoleClient_IdempotentWhenExists(t *testing.T) {
	store := &seedStore{existing: &model.App{ClientID: "admin-console", IsPublic: true}}
	created, err := EnsureAdminConsoleClient(context.Background(), store, "admin-console", []string{"https://admin.example.com/callback"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if created {
		t.Error("must not create when the client already exists")
	}
	if store.created != nil {
		t.Error("existing client must be left untouched (no re-create)")
	}
}
