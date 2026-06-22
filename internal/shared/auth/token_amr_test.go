package auth

import (
	"testing"

	"github.com/ovandermoten/go-oauth2/internal/model"
)

// GenerateTokenSetWithAuth stamps amr/acr (RFC 8176) on both the access and ID
// tokens; GenerateTokenSet omits them (byte-compatible).
func TestGenerateTokenSetWithAuth_StampsAmrAcr(t *testing.T) {
	ts := newDPoPTokenService(t)
	user := &model.User{ID: 5, TokenVersion: 1}
	app := &model.App{ClientID: "client"}

	set, err := ts.GenerateTokenSetWithAuth(user, app, "user", "openid", nil, "", 0, []string{"pwd", "otp", "mfa"}, "mfa")
	if err != nil {
		t.Fatalf("GenerateTokenSetWithAuth: %v", err)
	}
	ac, err := ts.VerifyAccessToken(set.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}
	if ac.Acr != "mfa" || len(ac.Amr) != 3 || ac.Amr[0] != "pwd" {
		t.Fatalf("access amr/acr = %v / %q, want [pwd otp mfa] / mfa", ac.Amr, ac.Acr)
	}
	id, err := ts.VerifyIDToken(set.IDToken)
	if err != nil {
		t.Fatalf("VerifyIDToken: %v", err)
	}
	if id.Acr != "mfa" || len(id.Amr) != 3 {
		t.Fatalf("id amr/acr = %v / %q, want [pwd otp mfa] / mfa", id.Amr, id.Acr)
	}
}

func TestGenerateTokenSet_OmitsAmrAcr(t *testing.T) {
	ts := newDPoPTokenService(t)
	user := &model.User{ID: 5, TokenVersion: 1}
	app := &model.App{ClientID: "client"}

	set, err := ts.GenerateTokenSet(user, app, "user", "openid", nil, "", 0)
	if err != nil {
		t.Fatalf("GenerateTokenSet: %v", err)
	}
	ac, err := ts.VerifyAccessToken(set.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}
	if len(ac.Amr) != 0 || ac.Acr != "" {
		t.Fatalf("plain token must omit amr/acr, got %v / %q", ac.Amr, ac.Acr)
	}
}
