package service

import (
	"context"
	"errors"
	"testing"

	"github.com/ovandermoten/go-oauth2/internal/dto"
	"github.com/ovandermoten/go-oauth2/internal/model"
)

func TestCreate_ClaimMappings_Persisted(t *testing.T) {
	svc := newAppSvc()

	app, _, err := svc.Create(context.Background(), dto.CreateAppRequest{
		Name:         "Claims App",
		RedirectURIs: []string{"https://app.example.com/cb"},
		ClaimMappings: model.ClaimMappings{
			"tier": {Source: "user.attributes.tier", Target: model.ClaimTargetBoth},
		},
	}, 1)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if app.ClaimMappings["tier"].Source != "user.attributes.tier" {
		t.Fatalf("expected the mapping persisted, got %#v", app.ClaimMappings)
	}
}

func TestCreate_ClaimMappings_DefaultEmpty(t *testing.T) {
	svc := newAppSvc()

	app, _, err := svc.Create(context.Background(), dto.CreateAppRequest{
		Name:         "Plain App",
		RedirectURIs: []string{"https://app.example.com/cb"},
	}, 1)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	if len(app.ClaimMappings) != 0 {
		t.Fatalf("expected no mappings by default, got %v", app.ClaimMappings)
	}
}

// A bad mapping is refused at registration, not silently dropped at issuance.
func TestCreate_ClaimMappings_UnsupportedSourceRefused(t *testing.T) {
	svc := newAppSvc()

	_, _, err := svc.Create(context.Background(), dto.CreateAppRequest{
		Name:          "Bad App",
		RedirectURIs:  []string{"https://app.example.com/cb"},
		ClaimMappings: model.ClaimMappings{"secret": {Source: "user.hashed_password"}},
	}, 1)
	if !errors.Is(err, ErrInvalidClaimMapping) {
		t.Fatalf("Create with an unsupported source: err = %v, want ErrInvalidClaimMapping", err)
	}
}

func TestUpdate_ClaimMappings_OmittedUnchanged_NonNilReplaces(t *testing.T) {
	svc := newAppSvc()
	app, _, err := svc.Create(context.Background(), dto.CreateAppRequest{
		Name:          "App",
		RedirectURIs:  []string{"https://app.example.com/cb"},
		ClaimMappings: model.ClaimMappings{"tier": {Source: "user.attributes.tier"}},
	}, 1)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	// Omitted (nil) -> unchanged.
	updated, err := svc.Update(context.Background(), app.ID, dto.UpdateAppRequest{})
	if err != nil {
		t.Fatalf("Update (omitted): %v", err)
	}
	if len(updated.ClaimMappings) != 1 {
		t.Fatalf("omitted mappings must be unchanged, got %v", updated.ClaimMappings)
	}

	// Non-nil -> replaces.
	repl := model.ClaimMappings{"dept": {Source: "user.attributes.dept", Target: model.ClaimTargetID}}
	updated, err = svc.Update(context.Background(), app.ID, dto.UpdateAppRequest{ClaimMappings: &repl})
	if err != nil {
		t.Fatalf("Update (replace): %v", err)
	}
	if len(updated.ClaimMappings) != 1 || updated.ClaimMappings["dept"].Target != model.ClaimTargetID {
		t.Fatalf("expected the mappings replaced, got %v", updated.ClaimMappings)
	}

	// Explicit empty -> cleared.
	empty := model.ClaimMappings{}
	updated, err = svc.Update(context.Background(), app.ID, dto.UpdateAppRequest{ClaimMappings: &empty})
	if err != nil {
		t.Fatalf("Update (clear): %v", err)
	}
	if len(updated.ClaimMappings) != 0 {
		t.Fatalf("expected the mappings cleared, got %v", updated.ClaimMappings)
	}

	// And an invalid replacement is refused, leaving the stored policy alone.
	bad := model.ClaimMappings{"x": {Source: "user.email", Target: "refresh"}}
	if _, err := svc.Update(context.Background(), app.ID, dto.UpdateAppRequest{ClaimMappings: &bad}); !errors.Is(err, ErrInvalidClaimMapping) {
		t.Fatalf("Update with an unknown target: err = %v, want ErrInvalidClaimMapping", err)
	}
}
