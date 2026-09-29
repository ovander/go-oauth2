package service

import (
	"context"
	"testing"

	"github.com/ovander/go-oauth2/internal/dto"
)

func TestCreate_TokenExchangeFlags_Persisted(t *testing.T) {
	svc := newAppSvc()

	app, _, err := svc.Create(context.Background(), dto.CreateAppRequest{
		Name:               "Exchange App",
		RedirectURIs:       []string{"https://app.example.com/cb"},
		AllowTokenExchange: true,
		AllowImpersonation: true,
	}, 1)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if !app.AllowTokenExchange || !app.AllowImpersonation {
		t.Fatalf("expected both exchange flags persisted, got te=%v imp=%v", app.AllowTokenExchange, app.AllowImpersonation)
	}
}

func TestCreate_TokenExchangeFlags_DefaultFalse(t *testing.T) {
	svc := newAppSvc()

	app, _, err := svc.Create(context.Background(), dto.CreateAppRequest{
		Name:         "Plain App",
		RedirectURIs: []string{"https://app.example.com/cb"},
	}, 1)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if app.AllowTokenExchange || app.AllowImpersonation {
		t.Fatal("expected exchange flags false by default")
	}
}

func TestUpdate_TokenExchangeFlags_ToggleWhenProvidedOnly(t *testing.T) {
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
	if updated.AllowTokenExchange || updated.AllowImpersonation {
		t.Fatal("omitted flags must leave state unchanged (false)")
	}

	// Enable token exchange only.
	on := true
	updated, err = svc.Update(context.Background(), app.ID, dto.UpdateAppRequest{AllowTokenExchange: &on})
	if err != nil {
		t.Fatalf("Update (te on): %v", err)
	}
	if !updated.AllowTokenExchange || updated.AllowImpersonation {
		t.Fatalf("expected te=true imp=false, got te=%v imp=%v", updated.AllowTokenExchange, updated.AllowImpersonation)
	}

	// Enable impersonation, disable token exchange.
	off := false
	updated, err = svc.Update(context.Background(), app.ID, dto.UpdateAppRequest{
		AllowTokenExchange: &off,
		AllowImpersonation: &on,
	})
	if err != nil {
		t.Fatalf("Update (toggle): %v", err)
	}
	if updated.AllowTokenExchange || !updated.AllowImpersonation {
		t.Fatalf("expected te=false imp=true, got te=%v imp=%v", updated.AllowTokenExchange, updated.AllowImpersonation)
	}
}
