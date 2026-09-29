package service

import (
	"context"
	"testing"
	"time"

	"github.com/ovander/go-oauth2/internal/model"
)

// Impersonation is time-boxed (EPIC-17): an impersonated token auto-expires on
// the configured short lifetime, well before a normal access token, while
// delegation keeps the standard access-token TTL.
func TestExchangeToken_ImpersonationTokenIsTimeBoxed(t *testing.T) {
	svc, audit, ts := newShadowExchangeSvc(t, &model.App{ID: 7, ClientID: "c", AllowTokenExchange: true, AllowImpersonation: true})
	svc.tokenExchangeMode = TokenExchangeModeEnforce
	svc.impersonationTokenTTL = 5 * time.Minute // access TTL in the harness is 1h

	form := exForm(mintToken(t, ts, 100, "read write"), "", "read", "https://api")
	resp, err := svc.ExchangeToken(context.Background(), form, "c", "")
	if err != nil {
		t.Fatalf("enforce impersonation: %v", err)
	}
	if resp.ExpiresIn != int((5 * time.Minute).Seconds()) {
		t.Errorf("expires_in = %d, want the 300s impersonation time-box", resp.ExpiresIn)
	}

	claims, err := ts.VerifyAccessToken(resp.AccessToken)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	lifetime := claims.ExpiresAt.Sub(claims.IssuedAt.Time)
	if lifetime > 6*time.Minute {
		t.Errorf("token lifetime = %s, want it time-boxed near 5m", lifetime)
	}
	if d := audit.last.Details; d["impersonation"] != true || d["token_ttl_seconds"] != 300 {
		t.Errorf("audit should record the time-box, got impersonation=%v ttl=%v", d["impersonation"], d["token_ttl_seconds"])
	}
}

// Delegation is unaffected by the impersonation time-box: it keeps the standard
// access-token TTL.
func TestExchangeToken_DelegationKeepsAccessTTL(t *testing.T) {
	svc, _, ts := newShadowExchangeSvc(t, &model.App{ID: 7, ClientID: "c", AllowTokenExchange: true})
	svc.tokenExchangeMode = TokenExchangeModeEnforce
	svc.impersonationTokenTTL = 5 * time.Minute

	form := exForm(mintToken(t, ts, 100, "read write"), mintToken(t, ts, 200, "read"), "read", "https://api")
	resp, err := svc.ExchangeToken(context.Background(), form, "c", "")
	if err != nil {
		t.Fatalf("enforce delegation: %v", err)
	}
	if resp.ExpiresIn != int(time.Hour.Seconds()) {
		t.Errorf("delegation expires_in = %d, want the full access TTL (3600s)", resp.ExpiresIn)
	}
}

// The impersonation time-box never exceeds the access-token TTL: a misconfigured
// longer value is capped so an impersonated token is never longer-lived than a
// normal one.
func TestExchangeToken_ImpersonationTTLCappedAtAccessTTL(t *testing.T) {
	svc, _, ts := newShadowExchangeSvc(t, &model.App{ID: 7, ClientID: "c", AllowTokenExchange: true, AllowImpersonation: true})
	svc.tokenExchangeMode = TokenExchangeModeEnforce
	svc.impersonationTokenTTL = 24 * time.Hour // larger than the 1h access TTL

	form := exForm(mintToken(t, ts, 100, "read write"), "", "read", "https://api")
	resp, err := svc.ExchangeToken(context.Background(), form, "c", "")
	if err != nil {
		t.Fatalf("enforce impersonation: %v", err)
	}
	if resp.ExpiresIn != int(time.Hour.Seconds()) {
		t.Errorf("expires_in = %d, want it capped at the 3600s access TTL", resp.ExpiresIn)
	}
}

// With no impersonation time-box configured (zero), impersonation falls back to
// the standard access-token TTL — unchanged behaviour.
func TestExchangeToken_ImpersonationNoTimeBoxFallsBackToAccessTTL(t *testing.T) {
	svc, _, ts := newShadowExchangeSvc(t, &model.App{ID: 7, ClientID: "c", AllowTokenExchange: true, AllowImpersonation: true})
	svc.tokenExchangeMode = TokenExchangeModeEnforce
	// impersonationTokenTTL left at zero.

	form := exForm(mintToken(t, ts, 100, "read write"), "", "read", "https://api")
	resp, err := svc.ExchangeToken(context.Background(), form, "c", "")
	if err != nil {
		t.Fatalf("enforce impersonation: %v", err)
	}
	if resp.ExpiresIn != int(time.Hour.Seconds()) {
		t.Errorf("expires_in = %d, want the full access TTL when no time-box set", resp.ExpiresIn)
	}
}
