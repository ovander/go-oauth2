package service

import (
	"context"
	"testing"
	"time"

	"github.com/ovandermoten/go-oauth2/internal/model"
)

// Introspection surfaces auth_time (RFC 7662 / RFC 9068 §2.2.1) so a resource
// server introspecting a token can make its own freshness/step-up decisions.
func TestIntrospect_SurfacesAuthTime(t *testing.T) {
	user := &model.User{ID: 100, Email: "alice@example.com", TokenVersion: 1}
	app := &model.App{ID: 1, ClientID: "app"}
	svc := newNew03Svc(t, user)
	ts := svc.tokenService

	authTime := time.Now().Add(-20 * time.Minute).Unix()
	set, err := ts.GenerateTokenSet(user, app, "user", "openid", nil, "", authTime)
	if err != nil {
		t.Fatalf("GenerateTokenSet: %v", err)
	}
	resp, err := svc.Introspect(context.Background(), set.AccessToken, "app")
	if err != nil {
		t.Fatalf("Introspect: %v", err)
	}
	if resp.AuthTime != authTime {
		t.Errorf("introspection auth_time = %d, want %d", resp.AuthTime, authTime)
	}
}
