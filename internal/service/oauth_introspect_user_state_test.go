package service

import (
	"context"
	"testing"
	"time"

	"github.com/ovander/go-oauth2/internal/model"
)

// #366: a user's token introspects as active only while the user exists, is
// readable and is not locked — what Socrate's own API requires. A
// service-account token has no user and stays active.

func introspectFor(t *testing.T, svc *oauthService, user *model.User) bool {
	t.Helper()
	set, err := svc.tokenService.GenerateTokenSet(user, &model.App{ID: 1, ClientID: "app"}, "user", "openid", nil, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := svc.Introspect(context.Background(), set.AccessToken, "app")
	if err != nil {
		t.Fatalf("Introspect: %v", err)
	}
	return resp.Active
}

func TestIntrospect_LockedUserIsInactive(t *testing.T) {
	user := &model.User{ID: 100, Email: "alice@example.com", TokenVersion: 1}
	svc := newNew03Svc(t, user)
	if !introspectFor(t, svc, user) {
		t.Fatal("an unlocked user's token must be active")
	}
	until := time.Now().Add(time.Hour)
	user.LockedUntil = &until
	if introspectFor(t, svc, user) {
		t.Fatal("a locked user's token must be inactive")
	}
}

func TestIntrospect_MissingUserIsInactive(t *testing.T) {
	user := &model.User{ID: 100, Email: "alice@example.com", TokenVersion: 1}
	svc := newNew03Svc(t, user)
	set, err := svc.tokenService.GenerateTokenSet(user, &model.App{ID: 1, ClientID: "app"}, "user", "openid", nil, "", 0)
	if err != nil {
		t.Fatal(err)
	}
	svc.userRepo = &new03UserRepo{user: nil} // deleted, or unreadable
	resp, err := svc.Introspect(context.Background(), set.AccessToken, "app")
	if err != nil || resp.Active {
		t.Fatalf("deleted user: (%+v, %v), want inactive", resp, err)
	}
}

func TestIntrospect_RevocationStoreErrorIsInactive(t *testing.T) {
	user := &model.User{ID: 100, Email: "alice@example.com", TokenVersion: 1}
	svc := newNew03Svc(t, user)
	used := newMemUsedTokenRepo()
	used.forceIsUsedErr = true
	svc.usedTokenRepo = used
	if introspectFor(t, svc, user) {
		t.Fatal("a token whose revocation cannot be read must be inactive")
	}
}

func TestIntrospect_ServiceAccountTokenStaysActive(t *testing.T) {
	svc := newNew03Svc(t, nil) // no user at all
	token, err := svc.tokenService.GenerateClientCredentialsToken(&model.App{ID: 7, ClientID: "app"}, "api")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := svc.Introspect(context.Background(), token, "app")
	if err != nil || !resp.Active || resp.Sub != "app:7" {
		t.Fatalf("service-account token: (%+v, %v), want active with sub app:7", resp, err)
	}
}
