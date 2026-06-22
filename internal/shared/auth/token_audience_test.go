package auth

import (
	"testing"
	"time"

	"github.com/ovandermoten/go-oauth2/internal/model"
)

func audienceTokenService(t *testing.T, mode string) *TokenService {
	t.Helper()
	km := newTestKeyManager(t)
	return NewTokenServiceWithSigner(km, NewLocalSigner(km), TokenConfig{
		Issuer:          "https://test.example.com",
		AccessTokenTTL:  time.Hour,
		RefreshTokenTTL: 24 * time.Hour,
		AudienceMode:    mode,
	})
}

func contains(s []string, want string) bool {
	for _, x := range s {
		if x == want {
			return true
		}
	}
	return false
}

// In dual mode the access token's aud is the client_id plus the client's
// registered audiences (RFC-001 / EPIC-7), so audience-aware resource servers
// can verify their resource id while client_id verifiers keep working.
func TestAccessToken_DualModeAddsRegisteredAudiences(t *testing.T) {
	ts := audienceTokenService(t, AudienceModeDual)
	user := &model.User{ID: 5, TokenVersion: 1}
	app := &model.App{ClientID: "client", Audiences: model.StringArray{"https://api.example.com", "https://reports.example.com"}}

	set, err := ts.GenerateTokenSet(user, app, "user", "openid", nil, "", 0)
	if err != nil {
		t.Fatalf("GenerateTokenSet: %v", err)
	}
	claims, err := ts.VerifyAccessToken(set.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}
	aud := []string(claims.Audience)
	if !contains(aud, "client") || !contains(aud, "https://api.example.com") || !contains(aud, "https://reports.example.com") {
		t.Fatalf("aud = %v, want client_id + registered audiences", aud)
	}
	if len(aud) != 3 {
		t.Errorf("aud = %v, want exactly 3 entries (no dupes)", aud)
	}
}

// Off mode (the default) leaves aud as the client_id even when audiences are
// registered — no behaviour change.
func TestAccessToken_OffModeKeepsClientIDOnly(t *testing.T) {
	ts := audienceTokenService(t, AudienceModeOff)
	user := &model.User{ID: 5, TokenVersion: 1}
	app := &model.App{ClientID: "client", Audiences: model.StringArray{"https://api.example.com"}}

	set, err := ts.GenerateTokenSet(user, app, "user", "openid", nil, "", 0)
	if err != nil {
		t.Fatalf("GenerateTokenSet: %v", err)
	}
	claims, err := ts.VerifyAccessToken(set.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}
	aud := []string(claims.Audience)
	if len(aud) != 1 || aud[0] != "client" {
		t.Fatalf("aud = %v, want [client] only in off mode", aud)
	}
}

// Dual mode with no registered audiences is identical to off — just the
// client_id — and de-dupes if the client_id is also listed as an audience.
func TestAccessToken_DualModeNoAudiencesAndDedup(t *testing.T) {
	ts := audienceTokenService(t, AudienceModeDual)
	user := &model.User{ID: 5, TokenVersion: 1}

	none := &model.App{ClientID: "client"}
	set, err := ts.GenerateTokenSet(user, none, "user", "openid", nil, "", 0)
	if err != nil {
		t.Fatalf("GenerateTokenSet: %v", err)
	}
	claims, _ := ts.VerifyAccessToken(set.AccessToken)
	if aud := []string(claims.Audience); len(aud) != 1 || aud[0] != "client" {
		t.Fatalf("aud = %v, want [client] when no audiences registered", aud)
	}

	dup := &model.App{ClientID: "client", Audiences: model.StringArray{"client", "https://api.example.com"}}
	set, err = ts.GenerateTokenSet(user, dup, "user", "openid", nil, "", 0)
	if err != nil {
		t.Fatalf("GenerateTokenSet: %v", err)
	}
	claims, _ = ts.VerifyAccessToken(set.AccessToken)
	if aud := []string(claims.Audience); len(aud) != 2 {
		t.Fatalf("aud = %v, want client_id de-duplicated against audiences", aud)
	}
}
