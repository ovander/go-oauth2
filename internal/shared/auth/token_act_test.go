package auth

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/ovander/go-oauth2/internal/model"
)

// The act (actor) claim must survive signing + verification, including a nested
// delegation chain. This is the inert claim-model slice — no issuance path sets
// `act` yet; the test signs claims directly.
func TestAccessTokenClaims_ActClaimRoundTrips(t *testing.T) {
	ts := newDPoPTokenService(t)

	claims := AccessTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://test.example.com",
			Subject:   "100", // the subject being acted upon
			Audience:  jwt.ClaimStrings{"client-x"},
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
			ID:        "jti-act",
		},
		Type: "access",
		// Most recent actor (200) acting on behalf of the subject, who themselves
		// was reached via an earlier actor (300) — a two-link delegation chain.
		Act: &ActClaim{Sub: "200", Act: &ActClaim{Sub: "300"}},
	}

	signed, err := ts.signToken(claims)
	if err != nil {
		t.Fatalf("signToken: %v", err)
	}
	got, err := ts.VerifyAccessToken(signed)
	if err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}
	if got.Act == nil || got.Act.Sub != "200" {
		t.Fatalf("expected outer act.sub=200, got %+v", got.Act)
	}
	if got.Act.Act == nil || got.Act.Act.Sub != "300" {
		t.Fatalf("expected nested act.act.sub=300, got %+v", got.Act)
	}
}

// An ordinary token carries no act claim, and the field is omitted from the JSON.
func TestAccessTokenClaims_NoActByDefault(t *testing.T) {
	ts := newDPoPTokenService(t)
	user := &model.User{ID: 5, TokenVersion: 1}
	app := &model.App{ClientID: "client-x"}

	token, err := ts.GenerateBoundAccessToken(user, app, "user", "openid", nil, "")
	if err != nil {
		t.Fatalf("GenerateBoundAccessToken: %v", err)
	}
	claims, err := ts.VerifyAccessToken(token)
	if err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}
	if claims.Act != nil {
		t.Fatalf("ordinary token must not carry act, got %+v", claims.Act)
	}
	// The raw JWT payload must not contain an "act" key.
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("malformed token")
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode payload: %v", err)
	}
	if strings.Contains(string(payload), `"act"`) {
		t.Fatal("act key must be omitted from an ordinary token")
	}
}
