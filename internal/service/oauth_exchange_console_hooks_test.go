package service

import (
	"context"
	"errors"
	"testing"

	"github.com/ovander/go-oauth2/internal/dto"
	"github.com/ovander/go-oauth2/internal/hooks"
	"github.com/ovander/go-oauth2/internal/model"
)

// The v1.14.2 audit's token-exchange leftovers: T-1, an exchanged token never
// targets an operator console, even one an operator registered as the
// client's audience; T-3, the issuance hooks apply to an exchange, and a client
// without a secret is never allowed to exchange.

func TestExchangeToken_RefusesAConsoleAudience(t *testing.T) {
	for _, mode := range []string{TokenExchangeModeShadow, TokenExchangeModeEnforce} {
		for _, aud := range []string{"admin-console", AdminPortalClientID} {
			app := &model.App{ID: 7, ClientID: "c", AllowTokenExchange: true, AllowImpersonation: true,
				Audiences: model.StringArray{"https://api", "admin-console", AdminPortalClientID}}
			svc, audit, ts := newShadowExchangeSvc(t, app)
			svc.tokenExchangeMode = mode
			svc.SetPrivilegedScopePolicy("off", []string{"admin-console"})
			resp, err := svc.ExchangeToken(context.Background(), exForm(mintToken(t, ts, 100, "read"), "", "read", aud), "c", exchangeTestSecret)
			// Shadow never issues and always answers invalid_grant; enforce
			// says why.
			want := ErrAudienceNotAllowed
			if mode == TokenExchangeModeShadow {
				want = ErrInvalidGrantType
			}
			if !errors.Is(err, want) || resp != nil {
				t.Errorf("%s, audience %s: %v, %+v; want %v", mode, aud, err, resp, want)
			}
			if audit.last == nil || audit.last.Details["deny_reason"] != "console_audience" {
				t.Errorf("%s, audience %s: audit %+v, want deny_reason console_audience", mode, aud, audit.last)
			}
		}
	}
	// Another registered audience is still exchanged.
	app := &model.App{ID: 7, ClientID: "c", AllowTokenExchange: true, AllowImpersonation: true, Audiences: model.StringArray{"https://api", "admin-console"}}
	svc, _, ts := newShadowExchangeSvc(t, app)
	svc.tokenExchangeMode = TokenExchangeModeEnforce
	svc.SetPrivilegedScopePolicy("off", []string{"admin-console"})
	if _, err := svc.ExchangeToken(context.Background(), exForm(mintToken(t, ts, 100, "read"), "", "read", "https://api"), "c", exchangeTestSecret); err != nil {
		t.Fatalf("a registered API audience: %v", err)
	}
}

func TestExchangeToken_RunsTheIssuanceHooks(t *testing.T) {
	hooks.Reset()
	t.Cleanup(hooks.Reset)
	var seen *hooks.TokenIssue
	veto := errors.New("not today")
	hooks.OnBeforeTokenIssue(func(_ context.Context, e *hooks.TokenIssue) error {
		cp := *e
		seen = &cp
		if e.Scope == "write" {
			return veto
		}
		return nil
	})
	app := &model.App{ID: 7, ClientID: "c", AllowTokenExchange: true, AllowImpersonation: true}
	svc, audit, ts := newShadowExchangeSvc(t, app)
	svc.tokenExchangeMode = TokenExchangeModeEnforce

	resp, err := svc.ExchangeToken(context.Background(), exForm(mintToken(t, ts, 100, "read"), "", "read", "https://api"), "c", exchangeTestSecret)
	if err != nil || resp == nil {
		t.Fatalf("an allowed exchange: %v", err)
	}
	if seen == nil || seen.Grant != "token_exchange" || seen.App == nil || seen.App.ClientID != "c" ||
		seen.User == nil || seen.User.ID != 100 || seen.Scope != "read" {
		t.Fatalf("hook saw %+v, want token_exchange for user 100 at client c, scope read", seen)
	}

	resp, err = svc.ExchangeToken(context.Background(), exForm(mintToken(t, ts, 100, "write"), "", "write", "https://api"), "c", exchangeTestSecret)
	if !errors.Is(err, hooks.ErrVetoed) || resp != nil {
		t.Fatalf("a vetoed exchange: %v, %+v; want ErrVetoed and no token", err, resp)
	}
	if audit.last == nil || audit.last.Details["deny_reason"] != "hook_veto" {
		t.Errorf("audit %+v, want deny_reason hook_veto", audit.last)
	}
}

func TestAppService_NoTokenExchangeWithoutASecret(t *testing.T) {
	svc := newAppSvc()
	if _, _, err := svc.Create(context.Background(), dto.CreateAppRequest{
		Name: "SPA", RedirectURIs: []string{"https://spa.example.com/cb"}, IsPublic: true, AllowTokenExchange: true,
	}, 1); !errors.Is(err, ErrPublicClientTokenExchange) {
		t.Fatalf("public client with token exchange: %v, want ErrPublicClientTokenExchange", err)
	}
	pub, _, err := svc.Create(context.Background(), dto.CreateAppRequest{
		Name: "SPA", RedirectURIs: []string{"https://spa.example.com/cb"}, IsPublic: true,
	}, 1)
	if err != nil {
		t.Fatal(err)
	}
	on := true
	if _, err := svc.Update(context.Background(), pub.ID, dto.UpdateAppRequest{AllowTokenExchange: &on}); !errors.Is(err, ErrPublicClientTokenExchange) {
		t.Fatalf("turning token exchange on for a public client: %v, want ErrPublicClientTokenExchange", err)
	}
	// A public client given the flag before v1.16.1 can still be updated
	// otherwise, and can clear it; it cannot turn it back on.
	legacy, _, err := svc.Create(context.Background(), dto.CreateAppRequest{
		Name: "Legacy SPA", RedirectURIs: []string{"https://legacy.example.com/cb"}, IsPublic: true,
	}, 1)
	if err != nil {
		t.Fatal(err)
	}
	legacy.AllowTokenExchange = true
	if err := svc.repo.Update(context.Background(), legacy); err != nil {
		t.Fatal(err)
	}
	name := "Legacy SPA, renamed"
	if got, err := svc.Update(context.Background(), legacy.ID, dto.UpdateAppRequest{Name: &name}); err != nil || got.Name != name {
		t.Fatalf("an unrelated update of a legacy public client: %v, %+v", err, got)
	}
	off := false
	if got, err := svc.Update(context.Background(), legacy.ID, dto.UpdateAppRequest{AllowTokenExchange: &off}); err != nil || got.AllowTokenExchange {
		t.Fatalf("clearing the flag on a legacy public client: %v, %+v", err, got)
	}
	conf, _, err := svc.Create(context.Background(), dto.CreateAppRequest{
		Name: "API", RedirectURIs: []string{"https://api.example.com/cb"}, AllowTokenExchange: true,
	}, 1)
	if err != nil || !conf.AllowTokenExchange {
		t.Fatalf("a confidential client with token exchange: %v", err)
	}
}
