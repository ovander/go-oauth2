package service

import (
	"context"
	"testing"

	"github.com/ovandermoten/go-oauth2/internal/model"
)

// Introspection surfaces the token's aud (RFC 7662 §2.2) so a resource server
// can verify its own identifier appears there (RFC-001 / EPIC-7).
func TestIntrospect_SurfacesAudience(t *testing.T) {
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
	if len(resp.Aud) != 1 || resp.Aud[0] != "app" {
		t.Fatalf("aud = %v, want [app]", resp.Aud)
	}
	// client_id stays the first audience entry.
	if resp.ClientID != "app" {
		t.Errorf("client_id = %q, want app", resp.ClientID)
	}
}
