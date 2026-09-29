package service

import (
	"context"
	"errors"
	"testing"

	"github.com/ovander/go-oauth2/internal/hooks"
	"github.com/ovander/go-oauth2/internal/shared/auth"
)

// A6: a BeforeTokenIssue hook can veto every grant; the service surfaces
// ErrTokenVetoed (→ access_denied at the token endpoint).
func TestA6_BeforeTokenIssue_VetoesRefreshAndClientCredentials(t *testing.T) {
	hooks.Reset()
	t.Cleanup(hooks.Reset)
	var seen []string
	hooks.OnBeforeTokenIssue(func(_ context.Context, e *hooks.TokenIssue) error {
		seen = append(seen, e.Grant)
		if e.App == nil || e.App.ClientID != "test-client" {
			return errors.New("unexpected app")
		}
		if e.Grant == "refresh_token" && e.User == nil {
			return errors.New("refresh must carry the user")
		}
		return errors.New("blocked by policy")
	})

	svc, rt := newHigh04Service(t, newMemUsedTokenRepo())
	if _, err := svc.Token(context.Background(), refreshReq(rt), "test-client", ""); !errors.Is(err, ErrTokenVetoed) {
		t.Fatalf("refresh: got %v, want ErrTokenVetoed", err)
	}

	app := svc.appRepo.(*crit02AppRepo).app
	hash, _ := auth.HashClientSecret("correct-secret")
	app.ClientSecretHash = hash
	if _, err := svc.Token(context.Background(), ccReq(""), "test-client", "correct-secret"); !errors.Is(err, ErrTokenVetoed) {
		t.Fatalf("client_credentials: got %v, want ErrTokenVetoed", err)
	}
	if len(seen) != 2 || seen[0] != "refresh_token" || seen[1] != "client_credentials" {
		t.Fatalf("hook saw %v", seen)
	}
}

func TestA6_NoHooks_GrantsUnchanged(t *testing.T) {
	hooks.Reset()
	svc, rt := newHigh04Service(t, newMemUsedTokenRepo())
	if _, err := svc.Token(context.Background(), refreshReq(rt), "test-client", ""); err != nil {
		t.Fatalf("refresh without hooks: %v", err)
	}
}
