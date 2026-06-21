package auth

import (
	"testing"
	"time"

	"github.com/ovandermoten/go-oauth2/internal/model"
)

func newDPoPTokenService(t *testing.T) *TokenService {
	t.Helper()
	km := newTestKeyManager(t)
	return NewTokenServiceWithSigner(km, NewLocalSigner(km), TokenConfig{
		Issuer:         "https://test.example.com",
		AccessTokenTTL: time.Hour,
	})
}

func TestGenerateBoundAccessToken_SetsCnfJKT(t *testing.T) {
	ts := newDPoPTokenService(t)
	user := &model.User{ID: 5, TokenVersion: 1}
	app := &model.App{ClientID: "client-dpop"}

	token, err := ts.GenerateBoundAccessToken(user, app, "user", "openid", nil, "thumb-abc123")
	if err != nil {
		t.Fatalf("GenerateBoundAccessToken: %v", err)
	}
	claims, err := ts.VerifyAccessToken(token)
	if err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}
	if claims.Cnf == nil || claims.Cnf.JKT != "thumb-abc123" {
		t.Fatalf("expected cnf.jkt bound, got %+v", claims.Cnf)
	}
	if claims.Type != "access" {
		t.Errorf("Type = %q, want access", claims.Type)
	}
}

func TestGenerateBoundAccessToken_EmptyJKTIsUnbound(t *testing.T) {
	ts := newDPoPTokenService(t)
	user := &model.User{ID: 5, TokenVersion: 1}
	app := &model.App{ClientID: "client-dpop"}

	token, err := ts.GenerateBoundAccessToken(user, app, "user", "openid", nil, "")
	if err != nil {
		t.Fatalf("GenerateBoundAccessToken: %v", err)
	}
	claims, err := ts.VerifyAccessToken(token)
	if err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}
	if claims.Cnf != nil {
		t.Fatalf("expected no cnf for an empty jkt, got %+v", claims.Cnf)
	}
}

func TestGenerateTokenSetWithDPoP_BindsAccessToken(t *testing.T) {
	ts := newDPoPTokenService(t)
	user := &model.User{ID: 5, TokenVersion: 1}
	app := &model.App{ClientID: "client-dpop"}

	set, err := ts.GenerateTokenSetWithDPoP(user, app, "user", "openid", nil, "", time.Now().Unix(), "jkt-bound")
	if err != nil {
		t.Fatalf("GenerateTokenSetWithDPoP: %v", err)
	}
	claims, err := ts.VerifyAccessToken(set.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}
	if claims.Cnf == nil || claims.Cnf.JKT != "jkt-bound" {
		t.Fatalf("expected access token bound to jkt, got %+v", claims.Cnf)
	}
}

func TestGenerateTokenSetWithDPoP_EmptyJKTMatchesPlainSet(t *testing.T) {
	ts := newDPoPTokenService(t)
	user := &model.User{ID: 5, TokenVersion: 1}
	app := &model.App{ClientID: "client-dpop"}

	set, err := ts.GenerateTokenSetWithDPoP(user, app, "user", "openid", nil, "", time.Now().Unix(), "")
	if err != nil {
		t.Fatalf("GenerateTokenSetWithDPoP: %v", err)
	}
	claims, err := ts.VerifyAccessToken(set.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}
	if claims.Cnf != nil {
		t.Fatalf("empty jkt must yield an unbound token, got %+v", claims.Cnf)
	}
}

func TestGenerateTokenSet_HasNoCnf(t *testing.T) {
	// The ordinary token path must remain unbound (backward compatible).
	ts := newDPoPTokenService(t)
	user := &model.User{ID: 5, TokenVersion: 1}
	app := &model.App{ClientID: "client-dpop"}

	set, err := ts.GenerateTokenSet(user, app, "user", "openid", nil, "", time.Now().Unix())
	if err != nil {
		t.Fatalf("GenerateTokenSet: %v", err)
	}
	claims, err := ts.VerifyAccessToken(set.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}
	if claims.Cnf != nil {
		t.Fatalf("ordinary access token must not carry cnf, got %+v", claims.Cnf)
	}
}
