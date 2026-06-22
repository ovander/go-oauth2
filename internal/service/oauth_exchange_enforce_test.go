package service

import (
	"context"
	"errors"
	"testing"

	"github.com/ovandermoten/go-oauth2/internal/contextkeys"
	"github.com/ovandermoten/go-oauth2/internal/model"
	"github.com/ovandermoten/go-oauth2/internal/shared/auth"
)

func TestExchangeToken_EnforceDelegationIssuesScopedActorBoundToken(t *testing.T) {
	svc, audit, ts := newShadowExchangeSvc(t, &model.App{ID: 7, ClientID: "c", AllowTokenExchange: true})
	svc.tokenExchangeMode = TokenExchangeModeEnforce

	subj := mintToken(t, ts, 100, "read write")
	actor := mintToken(t, ts, 200, "read")
	form := exForm(subj, actor, "read", "https://api.example.com")

	resp, err := svc.ExchangeToken(context.Background(), form, "c", "")
	if err != nil {
		t.Fatalf("enforce delegation: %v", err)
	}
	if resp == nil || resp.AccessToken == "" {
		t.Fatal("expected an issued access token")
	}
	if resp.IssuedTokenType == "" || resp.Scope != "read" || resp.TokenType != "Bearer" {
		t.Fatalf("unexpected response: %+v", resp)
	}

	claims, err := ts.VerifyAccessToken(resp.AccessToken)
	if err != nil {
		t.Fatalf("issued token does not verify: %v", err)
	}
	if claims.Subject != "100" {
		t.Errorf("subject = %q, want 100 (the exchange subject)", claims.Subject)
	}
	if claims.Scope != "read" {
		t.Errorf("scope = %q, want downscoped read", claims.Scope)
	}
	if len(claims.Audience) != 1 || claims.Audience[0] != "https://api.example.com" {
		t.Errorf("audience = %v, want the requested target", claims.Audience)
	}
	if claims.Act == nil || claims.Act.Sub != "200" {
		t.Errorf("act = %+v, want the actor (200)", claims.Act)
	}
	if claims.TokenVersion != 1 {
		t.Errorf("token_version = %d, want the subject's (1) for revocation", claims.TokenVersion)
	}
	if audit.last.Details["outcome"] != "issued" {
		t.Errorf("audit outcome = %v, want issued", audit.last.Details["outcome"])
	}
}

func TestExchangeToken_EnforceDPoPBindsWhenProofPresent(t *testing.T) {
	svc, audit, ts := newShadowExchangeSvc(t, &model.App{ID: 7, ClientID: "c", AllowTokenExchange: true})
	svc.tokenExchangeMode = TokenExchangeModeEnforce

	// The token-endpoint middleware would have verified a DPoP proof and stashed
	// its thumbprint on the context.
	ctx := context.WithValue(context.Background(), contextkeys.DPoPJKTKey, "jkt-exch")
	form := exForm(mintToken(t, ts, 100, "read write"), mintToken(t, ts, 200, "read"), "read", "https://api")

	resp, err := svc.ExchangeToken(ctx, form, "c", "")
	if err != nil {
		t.Fatalf("enforce dpop: %v", err)
	}
	claims, err := ts.VerifyAccessToken(resp.AccessToken)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.Cnf == nil || claims.Cnf.JKT != "jkt-exch" {
		t.Fatalf("expected exchanged token bound to jkt, got %+v", claims.Cnf)
	}
	if audit.last.Details["dpop_bound"] != true {
		t.Fatalf("audit dpop_bound = %v, want true", audit.last.Details["dpop_bound"])
	}
}

func TestExchangeToken_EnforceUnboundWhenNoProof(t *testing.T) {
	svc, _, ts := newShadowExchangeSvc(t, &model.App{ID: 7, ClientID: "c", AllowTokenExchange: true})
	svc.tokenExchangeMode = TokenExchangeModeEnforce

	form := exForm(mintToken(t, ts, 100, "read write"), mintToken(t, ts, 200, "read"), "read", "https://api")
	resp, err := svc.ExchangeToken(context.Background(), form, "c", "")
	if err != nil {
		t.Fatalf("enforce: %v", err)
	}
	claims, _ := ts.VerifyAccessToken(resp.AccessToken)
	if claims.Cnf != nil {
		t.Fatalf("expected an unbound token without a proof, got %+v", claims.Cnf)
	}
}

func TestExchangeToken_EnforceImpersonationActorIsClient(t *testing.T) {
	svc, _, ts := newShadowExchangeSvc(t, &model.App{ID: 7, ClientID: "c", AllowTokenExchange: true, AllowImpersonation: true})
	svc.tokenExchangeMode = TokenExchangeModeEnforce

	form := exForm(mintToken(t, ts, 100, "read write"), "", "read", "https://api")
	resp, err := svc.ExchangeToken(context.Background(), form, "c", "")
	if err != nil {
		t.Fatalf("enforce impersonation: %v", err)
	}
	claims, err := ts.VerifyAccessToken(resp.AccessToken)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if claims.Act == nil || claims.Act.Sub != "client:c" {
		t.Fatalf("impersonation act = %+v, want client:c", claims.Act)
	}
}

func TestExchangeToken_EnforceImpersonationDeniedSurfacesError(t *testing.T) {
	svc, _, ts := newShadowExchangeSvc(t, &model.App{ID: 7, ClientID: "c", AllowTokenExchange: true, AllowImpersonation: false})
	svc.tokenExchangeMode = TokenExchangeModeEnforce

	form := exForm(mintToken(t, ts, 100, "read write"), "", "read", "https://api")
	if _, err := svc.ExchangeToken(context.Background(), form, "c", ""); !errors.Is(err, ErrImpersonationNotAllowed) {
		t.Fatalf("enforce must surface the policy error, got %v", err)
	}
}

func TestExchangeToken_EnforceScopeEscalationSurfacesError(t *testing.T) {
	svc, _, ts := newShadowExchangeSvc(t, &model.App{ID: 7, ClientID: "c", AllowTokenExchange: true})
	svc.tokenExchangeMode = TokenExchangeModeEnforce

	form := exForm(mintToken(t, ts, 100, "read"), mintToken(t, ts, 200, "read"), "admin", "https://api")
	if _, err := svc.ExchangeToken(context.Background(), form, "c", ""); !errors.Is(err, ErrScopeNotSubset) {
		t.Fatalf("want ErrScopeNotSubset, got %v", err)
	}
}

func TestExchangeToken_EnforceInvalidSubjectTokenSurfacesError(t *testing.T) {
	svc, _, _ := newShadowExchangeSvc(t, &model.App{ID: 7, ClientID: "c", AllowTokenExchange: true})
	svc.tokenExchangeMode = TokenExchangeModeEnforce

	form := exForm("not-a-jwt", "", "read", "https://api")
	if _, err := svc.ExchangeToken(context.Background(), form, "c", ""); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("want ErrInvalidToken, got %v", err)
	}
}

func TestExchangeToken_EnforceConfidentialClientBadSecret(t *testing.T) {
	hash, err := auth.HashClientSecret("right-secret")
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	svc, _, ts := newShadowExchangeSvc(t, &model.App{ID: 7, ClientID: "c", AllowTokenExchange: true, ClientSecretHash: hash})
	svc.tokenExchangeMode = TokenExchangeModeEnforce

	form := exForm(mintToken(t, ts, 100, "read write"), mintToken(t, ts, 200, "read"), "read", "https://api")
	if _, err := svc.ExchangeToken(context.Background(), form, "c", "wrong-secret"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("want ErrInvalidCredentials for a bad client secret, got %v", err)
	}
	// With the right secret it proceeds to issue.
	if _, err := svc.ExchangeToken(context.Background(), form, "c", "right-secret"); err != nil {
		t.Fatalf("right secret should succeed: %v", err)
	}
}

func TestExchangeToken_EnforceParseErrorSurfacesError(t *testing.T) {
	svc, _, _ := newShadowExchangeSvc(t, &model.App{ID: 7, ClientID: "c", AllowTokenExchange: true})
	svc.tokenExchangeMode = TokenExchangeModeEnforce

	bad := exForm("", "", "", "") // missing subject_token etc.
	if _, err := svc.ExchangeToken(context.Background(), bad, "c", ""); !errors.Is(err, ErrInvalidExchangeRequest) {
		t.Fatalf("want ErrInvalidExchangeRequest, got %v", err)
	}
}
