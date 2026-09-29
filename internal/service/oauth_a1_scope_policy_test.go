package service

import (
	"context"
	"errors"
	"testing"

	"github.com/ovander/go-oauth2/internal/dto"
	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/shared/auth"
)

// A1 / P3-8: per-client allowed_scopes policy, off / observe / enforce.

func a1Service(t *testing.T, mode string, allowed ...string) (*oauthService, string) {
	t.Helper()
	svc, rt := newHigh04Service(t, newMemUsedTokenRepo())
	svc.scopePolicyMode = mode
	app := svc.appRepo.(*crit02AppRepo).app
	app.AllowedScopes = model.StringArray(allowed)
	app.RedirectURIs = []string{"https://app.example/cb"}
	return svc, rt
}

func a1Authorize(svc *oauthService, scope string) error {
	_, err := svc.Authorize(context.Background(), dto.AuthorizeRequest{
		ClientID: "test-client", RedirectURI: "https://app.example/cb",
		ResponseType: "code", Scope: scope, State: "s",
		CodeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", CodeChallengeMethod: "S256",
		MaxAge: -1,
	}, 42)
	return err
}

func TestA1_ModelScopeAllowed(t *testing.T) {
	app := &model.App{}
	if !app.ScopeAllowed("admin") || len(app.DeniedScopes("openid admin")) != 0 {
		t.Fatal("an empty policy must allow every scope")
	}
	app.AllowedScopes = model.StringArray{"openid", "profile"}
	if got := app.DeniedScopes("openid email admin profile"); len(got) != 2 || got[0] != "email" || got[1] != "admin" {
		t.Fatalf("denied = %v, want [email admin]", got)
	}
}

func TestA1_Authorize_ModesAndEmptyPolicy(t *testing.T) {
	// off: policy stored but ignored.
	svc, _ := a1Service(t, "off", "openid")
	if err := a1Authorize(svc, "openid admin"); err != nil {
		t.Fatalf("off mode must not refuse: %v", err)
	}
	// observe: allowed, audited.
	svc, _ = a1Service(t, "observe", "openid")
	if err := a1Authorize(svc, "openid admin"); err != nil {
		t.Fatalf("observe mode must not refuse: %v", err)
	}
	// enforce: refused with an ErrInvalidScope (→ invalid_scope at the edge).
	svc, _ = a1Service(t, "enforce", "openid")
	err := a1Authorize(svc, "openid admin")
	if !errors.Is(err, ErrScopeNotAllowed) || !errors.Is(err, ErrInvalidScope) {
		t.Fatalf("enforce: got %v, want ErrScopeNotAllowed (wrapping ErrInvalidScope)", err)
	}
	// enforce with a compliant request, and with an empty policy.
	if err := a1Authorize(svc, "openid"); err != nil {
		t.Fatalf("enforce with allowed scope: %v", err)
	}
	svc, _ = a1Service(t, "enforce")
	if err := a1Authorize(svc, "openid admin monitoring:write"); err != nil {
		t.Fatalf("enforce with an empty policy must allow everything: %v", err)
	}
}

func TestA1_ClientCredentials_EffectiveScopeIsChecked(t *testing.T) {
	svc, _ := a1Service(t, "enforce", "openid")
	app := svc.appRepo.(*crit02AppRepo).app
	hash, err := auth.HashClientSecret("correct-secret")
	if err != nil {
		t.Fatal(err)
	}
	app.ClientSecretHash = hash

	// No scope → effective "api", which the policy does not allow.
	_, err = svc.Token(context.Background(), ccReq(""), "test-client", "correct-secret")
	if !errors.Is(err, ErrScopeNotAllowed) {
		t.Fatalf("client_credentials default scope: got %v, want ErrScopeNotAllowed", err)
	}
	app.AllowedScopes = model.StringArray{"api"}
	if _, err := svc.Token(context.Background(), ccReq(""), "test-client", "correct-secret"); err != nil {
		t.Fatalf("client_credentials with api allowed: %v", err)
	}
}

func TestA1_Refresh_CannotKeepAWithdrawnScope(t *testing.T) {
	// The high04 refresh token carries scope "openid profile email".
	svc, rt := a1Service(t, "enforce", "openid")
	_, err := svc.Token(context.Background(), refreshReq(rt), "test-client", "")
	if !errors.Is(err, ErrScopeNotAllowed) {
		t.Fatalf("refresh with a withdrawn scope: got %v, want ErrScopeNotAllowed", err)
	}
	svc, rt = a1Service(t, "observe", "openid")
	if _, err := svc.Token(context.Background(), refreshReq(rt), "test-client", ""); err != nil {
		t.Fatalf("observe mode refresh: %v", err)
	}
}

func TestA1_PolicyNamesMustBeSupportedScopes(t *testing.T) {
	if err := validateScopeNames([]string{"openid", "monitoring:read"}); err != nil {
		t.Fatalf("valid names rejected: %v", err)
	}
	if err := validateScopeNames([]string{"openid", "bogus"}); !errors.Is(err, ErrInvalidScope) {
		t.Fatalf("bogus name accepted: %v", err)
	}
	if err := validateScopeNames([]string{""}); !errors.Is(err, ErrInvalidScope) {
		t.Fatalf("empty name accepted: %v", err)
	}
}
