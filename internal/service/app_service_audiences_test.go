package service

import (
	"context"
	"testing"

	"github.com/ovander/go-oauth2/internal/dto"
)

func TestCreate_Audiences_Persisted(t *testing.T) {
	svc := newAppSvc()

	app, _, err := svc.Create(context.Background(), dto.CreateAppRequest{
		Name:         "Audience App",
		RedirectURIs: []string{"https://app.example.com/cb"},
		Audiences:    []string{"https://api.example.com", "https://reports.example.com"},
	}, 1)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if len(app.Audiences) != 2 || app.Audiences[0] != "https://api.example.com" {
		t.Fatalf("expected registered audiences persisted, got %v", app.Audiences)
	}
}

func TestCreate_Audiences_DefaultEmpty(t *testing.T) {
	svc := newAppSvc()

	app, _, err := svc.Create(context.Background(), dto.CreateAppRequest{
		Name:         "Plain App",
		RedirectURIs: []string{"https://app.example.com/cb"},
	}, 1)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if len(app.Audiences) != 0 {
		t.Fatalf("expected no audiences by default, got %v", app.Audiences)
	}
}

func TestUpdate_Audiences_OmittedUnchanged_NonNilReplaces(t *testing.T) {
	svc := newAppSvc()
	app, _, err := svc.Create(context.Background(), dto.CreateAppRequest{
		Name:         "App",
		RedirectURIs: []string{"https://app.example.com/cb"},
		Audiences:    []string{"https://api.example.com"},
	}, 1)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Omitted (nil) -> unchanged.
	updated, err := svc.Update(context.Background(), app.ID, dto.UpdateAppRequest{})
	if err != nil {
		t.Fatalf("Update (omitted): %v", err)
	}
	if len(updated.Audiences) != 1 || updated.Audiences[0] != "https://api.example.com" {
		t.Fatalf("omitted audiences must be unchanged, got %v", updated.Audiences)
	}

	// Non-nil -> replaces.
	repl := []string{"https://new.example.com"}
	updated, err = svc.Update(context.Background(), app.ID, dto.UpdateAppRequest{Audiences: &repl})
	if err != nil {
		t.Fatalf("Update (replace): %v", err)
	}
	if len(updated.Audiences) != 1 || updated.Audiences[0] != "https://new.example.com" {
		t.Fatalf("expected audiences replaced, got %v", updated.Audiences)
	}

	// Explicit empty -> cleared.
	empty := []string{}
	updated, err = svc.Update(context.Background(), app.ID, dto.UpdateAppRequest{Audiences: &empty})
	if err != nil {
		t.Fatalf("Update (clear): %v", err)
	}
	if len(updated.Audiences) != 0 {
		t.Fatalf("expected audiences cleared, got %v", updated.Audiences)
	}
}
