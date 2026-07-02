package service

import (
	"context"
	"testing"

	"github.com/ovandermoten/go-oauth2/internal/model"
	"github.com/ovandermoten/go-oauth2/internal/shared/auth"
)

// Introspection must surface the actor (act) chain for a token minted via token
// exchange (RFC 8693 §4.1), and omit it for an ordinary token.
func TestIntrospect_SurfacesActorChain(t *testing.T) {
	user := &model.User{ID: 100, Email: "alice@example.com", TokenVersion: 1}
	svc := newNew03Svc(t, user)
	ts := svc.tokenService

	// Exchanged token for subject 100, acted on by 200 (who was reached via 300).
	exchanged, _, err := ts.GenerateExchangedToken(
		"100", []string{"https://api"}, "read", 1,
		&auth.ActClaim{Sub: "200", Act: &auth.ActClaim{Sub: "300"}}, "",
	)
	if err != nil {
		t.Fatalf("GenerateExchangedToken: %v", err)
	}
	resp, err := svc.Introspect(context.Background(), exchanged, "https://api")
	if err != nil {
		t.Fatalf("Introspect: %v", err)
	}
	if !resp.Active {
		t.Fatal("expected active token")
	}
	if resp.Act == nil || resp.Act.Sub != "200" {
		t.Fatalf("expected act.sub=200, got %+v", resp.Act)
	}
	if resp.Act.Act == nil || resp.Act.Act.Sub != "300" {
		t.Fatalf("expected nested act.act.sub=300, got %+v", resp.Act)
	}
}

func TestIntrospect_NoActorForOrdinaryToken(t *testing.T) {
	user := &model.User{ID: 100, Email: "alice@example.com", TokenVersion: 1}
	app := &model.App{ID: 1, ClientID: "app"}
	svc := newNew03Svc(t, user)
	ts := svc.tokenService

	set, err := ts.GenerateTokenSet(user, app, "user", "openid", nil, "", 0)
	if err != nil {
		t.Fatalf("GenerateTokenSet: %v", err)
	}
	resp, err := svc.Introspect(context.Background(), set.AccessToken, "app")
	if err != nil {
		t.Fatalf("Introspect: %v", err)
	}
	if resp.Act != nil {
		t.Fatalf("ordinary token must not carry act, got %+v", resp.Act)
	}
}
