package service

import (
	"context"
	"errors"
	"testing"

	"github.com/ovander/go-oauth2/internal/contextkeys"
	"github.com/ovander/go-oauth2/internal/model"
)

// Token exchange authenticates the requesting client before it looks at any
// presented token, and only an active, confidential client that meets its own
// DPoP requirement may exchange.

func TestExchangeToken_ClientChecks(t *testing.T) {
	for name, tc := range map[string]struct {
		setup      func(app *model.App)
		secret     string
		wantErr    error
		denyReason string
	}{
		"public client": {func(a *model.App) { a.ClientSecretHash = "" }, "", ErrExchangeNotAllowed, "public_client"},
		"wrong secret":  {nil, "wrong-secret", ErrInvalidCredentials, "invalid_client"},
		"no secret":     {nil, "", ErrInvalidCredentials, "invalid_client"},
		"inactive":      {func(a *model.App) { a.Active = false }, exchangeTestSecret, ErrAppInactive, "inactive_client"},
		"dpop required": {func(a *model.App) { a.RequireDPoP = true }, exchangeTestSecret, ErrDPoPRequired, "dpop_required"},
	} {
		t.Run(name, func(t *testing.T) {
			app := &model.App{ID: 7, ClientID: "c", AllowTokenExchange: true, AllowImpersonation: true}
			svc, audit, ts := newShadowExchangeSvc(t, app)
			svc.tokenExchangeMode = TokenExchangeModeEnforce
			if tc.setup != nil {
				tc.setup(app)
			}
			ctx := context.Background()
			form := exForm(mintToken(t, ts, 100, "read"), "", "read", "https://api")
			if _, err := svc.ExchangeToken(ctx, form, "c", tc.secret); !errors.Is(err, tc.wantErr) {
				t.Fatalf("enforce: %v, want %v", err, tc.wantErr)
			}
			if audit.last == nil {
				t.Fatal("no audit row")
			}
			if audit.last.Details["deny_reason"] != tc.denyReason || audit.last.Details["outcome"] != "denied" {
				t.Fatalf("audit: outcome %v deny_reason %v, want denied %s",
					audit.last.Details["outcome"], audit.last.Details["deny_reason"], tc.denyReason)
			}
			// The subject token was not examined.
			if _, seen := audit.last.Details["subject_sub"]; seen {
				t.Error("the subject token was verified before the client was accepted")
			}

			// Shadow mode reports every refusal as an unsupported grant.
			svc.tokenExchangeMode = TokenExchangeModeShadow
			if _, err := svc.ExchangeToken(ctx, form, "c", tc.secret); !errors.Is(err, ErrInvalidGrantType) {
				t.Fatalf("shadow: %v, want ErrInvalidGrantType", err)
			}
		})
	}
}

// A client that requires DPoP may exchange when the request carries a proof.
func TestExchangeToken_DPoPRequiredClientWithProof(t *testing.T) {
	app := &model.App{ID: 7, ClientID: "c", AllowTokenExchange: true, AllowImpersonation: true, RequireDPoP: true}
	svc, _, ts := newShadowExchangeSvc(t, app)
	svc.tokenExchangeMode = TokenExchangeModeEnforce
	ctx := context.WithValue(context.Background(), contextkeys.DPoPJKTKey, "jkt-1")
	form := exForm(mintToken(t, ts, 100, "read"), "", "read", "https://api")
	if _, err := svc.ExchangeToken(ctx, form, "c", exchangeTestSecret); err != nil {
		t.Fatalf("DPoP-bound exchange: %v", err)
	}
}

// A wrong secret with an invalid subject token is a client-authentication
// failure, not an invalid token: the endpoint does not tell an unauthenticated
// caller whether a token is valid.
func TestExchangeToken_ClientAuthComesBeforeTokenValidity(t *testing.T) {
	svc, audit, _ := newShadowExchangeSvc(t, &model.App{ID: 7, ClientID: "c", AllowTokenExchange: true})
	svc.tokenExchangeMode = TokenExchangeModeEnforce
	form := exForm("not-a-jwt", "", "read", "https://api")
	if _, err := svc.ExchangeToken(context.Background(), form, "c", "wrong-secret"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("%v, want ErrInvalidCredentials", err)
	}
	if audit.last == nil {
		t.Fatal("no audit row")
	}
	if audit.last.Details["deny_reason"] != "invalid_client" {
		t.Fatalf("deny_reason %v, want invalid_client", audit.last.Details["deny_reason"])
	}
}
