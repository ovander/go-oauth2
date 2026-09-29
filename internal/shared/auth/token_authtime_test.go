package auth

import (
	"testing"
	"time"

	"github.com/ovander/go-oauth2/internal/model"
)

// The access token issued by GenerateTokenSet carries the same auth_time as the
// refresh/ID tokens (RFC 9068 §2.2.1), so a resource server can make its own
// freshness/step-up decisions from the access token alone.
func TestGenerateTokenSet_AccessTokenCarriesAuthTime(t *testing.T) {
	ts := newDPoPTokenService(t)
	user := &model.User{ID: 5, TokenVersion: 1}
	app := &model.App{ClientID: "client"}

	authTime := time.Now().Add(-30 * time.Minute).Unix()
	set, err := ts.GenerateTokenSet(user, app, "user", "openid", nil, "", authTime)
	if err != nil {
		t.Fatalf("GenerateTokenSet: %v", err)
	}
	claims, err := ts.VerifyAccessToken(set.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}
	if claims.AuthTime != authTime {
		t.Errorf("access token auth_time = %d, want %d (matching the session)", claims.AuthTime, authTime)
	}
}

// When the caller passes no auth_time, GenerateTokenSet stamps "now" on the
// access token (matching the refresh/ID-token behaviour) rather than omitting it.
func TestGenerateTokenSet_AuthTimeDefaultsToNow(t *testing.T) {
	ts := newDPoPTokenService(t)
	user := &model.User{ID: 5, TokenVersion: 1}
	app := &model.App{ClientID: "client"}

	before := time.Now().Unix()
	set, err := ts.GenerateTokenSet(user, app, "user", "openid", nil, "", 0)
	if err != nil {
		t.Fatalf("GenerateTokenSet: %v", err)
	}
	claims, err := ts.VerifyAccessToken(set.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}
	if claims.AuthTime < before || claims.AuthTime > time.Now().Unix()+1 {
		t.Errorf("access token auth_time = %d, want ~now (>= %d)", claims.AuthTime, before)
	}
}

// GenerateBoundAccessToken (used outside the login flow) stays byte-compatible:
// it omits auth_time, so no consumer that relied on its absence breaks.
func TestGenerateBoundAccessToken_OmitsAuthTime(t *testing.T) {
	ts := newDPoPTokenService(t)
	user := &model.User{ID: 5, TokenVersion: 1}
	app := &model.App{ClientID: "client"}

	token, err := ts.GenerateBoundAccessToken(user, app, "user", "openid", nil, "")
	if err != nil {
		t.Fatalf("GenerateBoundAccessToken: %v", err)
	}
	claims, err := ts.VerifyAccessToken(token)
	if err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}
	if claims.AuthTime != 0 {
		t.Errorf("auth_time = %d, want 0 (omitted) for the plain bound-token helper", claims.AuthTime)
	}
}
