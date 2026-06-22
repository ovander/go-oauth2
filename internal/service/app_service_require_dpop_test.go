package service

import (
	"context"
	"testing"

	"github.com/ovandermoten/go-oauth2/internal/dto"
)

func TestCreate_RequireDPoP_PersistedFromRequest(t *testing.T) {
	svc := newAppSvc()

	app, _, err := svc.Create(context.Background(), dto.CreateAppRequest{
		Name:         "DPoP App",
		RedirectURIs: []string{"https://app.example.com/cb"},
		RequireDPoP:  true,
	}, 1)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if !app.RequireDPoP {
		t.Fatal("expected RequireDPoP persisted on the created app")
	}
}

func TestCreate_RequireDPoP_DefaultsFalse(t *testing.T) {
	svc := newAppSvc()

	app, _, err := svc.Create(context.Background(), dto.CreateAppRequest{
		Name:         "Plain App",
		RedirectURIs: []string{"https://app.example.com/cb"},
	}, 1)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if app.RequireDPoP {
		t.Fatal("expected RequireDPoP false by default")
	}
}

func TestUpdate_RequireDPoP_TogglesWhenProvidedOnly(t *testing.T) {
	svc := newAppSvc()
	app, _, err := svc.Create(context.Background(), dto.CreateAppRequest{
		Name:         "App",
		RedirectURIs: []string{"https://app.example.com/cb"},
	}, 1)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Omitted -> unchanged.
	updated, err := svc.Update(context.Background(), app.ID, dto.UpdateAppRequest{})
	if err != nil {
		t.Fatalf("Update (omitted): %v", err)
	}
	if updated.RequireDPoP {
		t.Fatal("omitted require_dpop must leave the flag unchanged (false)")
	}

	// Set true.
	on := true
	updated, err = svc.Update(context.Background(), app.ID, dto.UpdateAppRequest{RequireDPoP: &on})
	if err != nil {
		t.Fatalf("Update (true): %v", err)
	}
	if !updated.RequireDPoP {
		t.Fatal("expected require_dpop enabled")
	}

	// Set false.
	off := false
	updated, err = svc.Update(context.Background(), app.ID, dto.UpdateAppRequest{RequireDPoP: &off})
	if err != nil {
		t.Fatalf("Update (false): %v", err)
	}
	if updated.RequireDPoP {
		t.Fatal("expected require_dpop disabled")
	}
}
