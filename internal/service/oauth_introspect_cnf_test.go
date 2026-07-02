package service

import (
	"context"
	"testing"

	"github.com/ovandermoten/go-oauth2/internal/model"
)

// Introspection must surface the DPoP confirmation (cnf.jkt) for a
// sender-constrained access token (RFC 7662 §2.2 / RFC 9449 §7), and omit it
// for an ordinary bearer token.
func TestIntrospect_SurfacesDPoPConfirmation(t *testing.T) {
	user := &model.User{ID: 100, Email: "alice@example.com", TokenVersion: 1}
	app := &model.App{ID: 1, ClientID: "app-cnf"}
	svc := newNew03Svc(t, user)
	ts := svc.tokenService

	bound, err := ts.GenerateBoundAccessToken(user, app, "user", "openid", nil, "jkt-xyz")
	if err != nil {
		t.Fatalf("GenerateBoundAccessToken: %v", err)
	}
	resp, err := svc.Introspect(context.Background(), bound, "app-cnf")
	if err != nil {
		t.Fatalf("Introspect: %v", err)
	}
	if !resp.Active {
		t.Fatal("expected active token")
	}
	if resp.Cnf == nil || resp.Cnf.JKT != "jkt-xyz" {
		t.Fatalf("expected cnf.jkt surfaced, got %+v", resp.Cnf)
	}
}

func TestIntrospect_NoConfirmationForBearerToken(t *testing.T) {
	user := &model.User{ID: 100, Email: "alice@example.com", TokenVersion: 1}
	app := &model.App{ID: 1, ClientID: "app-cnf"}
	svc := newNew03Svc(t, user)
	ts := svc.tokenService

	set, err := ts.GenerateTokenSet(user, app, "user", "openid", nil, "", 0)
	if err != nil {
		t.Fatalf("GenerateTokenSet: %v", err)
	}
	resp, err := svc.Introspect(context.Background(), set.AccessToken, "app-cnf")
	if err != nil {
		t.Fatalf("Introspect: %v", err)
	}
	if resp.Cnf != nil {
		t.Fatalf("ordinary token must not carry cnf, got %+v", resp.Cnf)
	}
}
