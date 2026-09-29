package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ovander/go-oauth2/internal/dto"
	"github.com/ovander/go-oauth2/internal/shared/auth"
)

// P3-3: the refresh grant honoured token version and role but not the
// account's lock state — an admin-blocked user kept minting access tokens
// (valid at every external resource server) until the refresh TTL.
func TestP33_RefreshGrant_RejectsLockedAccount(t *testing.T) {
	svc, rt := newHigh04Service(t, newMemUsedTokenRepo())
	until := time.Now().Add(time.Hour)
	svc.userRepo.(*high04UserRepo).user.LockedUntil = &until

	_, err := svc.Token(context.Background(), refreshReq(rt), "test-client", "")
	if !errors.Is(err, ErrAccountLocked) {
		t.Fatalf("locked account refresh: got %v, want ErrAccountLocked", err)
	}
}

// P3-3: a deactivated client's outstanding refresh tokens must stop working.
func TestP33_RefreshGrant_RejectsInactiveClient(t *testing.T) {
	svc, rt := newHigh04Service(t, newMemUsedTokenRepo())
	svc.appRepo.(*crit02AppRepo).app.Active = false

	_, err := svc.Token(context.Background(), refreshReq(rt), "test-client", "")
	if !errors.Is(err, ErrAppInactive) {
		t.Fatalf("inactive client refresh: got %v, want ErrAppInactive", err)
	}
}

// Sanity: the same refresh token succeeds when neither condition applies, so
// the two tests above are not passing for an unrelated reason.
func TestP33_RefreshGrant_StillWorksForHealthyAccountAndClient(t *testing.T) {
	svc, rt := newHigh04Service(t, newMemUsedTokenRepo())
	if _, err := svc.Token(context.Background(), refreshReq(rt), "test-client", ""); err != nil {
		t.Fatalf("healthy refresh: %v", err)
	}
}

// P3-3: Authorize refuses locked users and inactive clients before issuing a
// code.
func TestP33_Authorize_RejectsLockedUserAndInactiveClient(t *testing.T) {
	authorizeReq := dto.AuthorizeRequest{
		ClientID: "test-client", RedirectURI: "https://app.example/cb",
		ResponseType: "code", Scope: "openid", State: "s",
		CodeChallenge: "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM", CodeChallengeMethod: "S256",
		MaxAge: -1,
	}

	svc, _ := newHigh04Service(t, newMemUsedTokenRepo())
	svc.appRepo.(*crit02AppRepo).app.RedirectURIs = []string{"https://app.example/cb"}
	if _, err := svc.Authorize(context.Background(), authorizeReq, 42); err != nil {
		t.Fatalf("baseline authorize should succeed: %v", err)
	}

	until := time.Now().Add(time.Hour)
	svc.userRepo.(*high04UserRepo).user.LockedUntil = &until
	if _, err := svc.Authorize(context.Background(), authorizeReq, 42); !errors.Is(err, ErrAccountLocked) {
		t.Fatalf("locked user authorize: got %v, want ErrAccountLocked", err)
	}
	svc.userRepo.(*high04UserRepo).user.LockedUntil = nil

	svc.appRepo.(*crit02AppRepo).app.Active = false
	if _, err := svc.Authorize(context.Background(), authorizeReq, 42); !errors.Is(err, ErrAppInactive) {
		t.Fatalf("inactive client authorize: got %v, want ErrAppInactive", err)
	}
}

func ccReq(scope string) dto.TokenRequest {
	return dto.TokenRequest{GrantType: "client_credentials", Scope: scope}
}

// P2-5: client_credentials skipped validateScope and requireDPoP.
func TestP25_ClientCredentials_ValidatesScopeAndDPoP(t *testing.T) {
	svc, _ := newHigh04Service(t, newMemUsedTokenRepo())
	app := svc.appRepo.(*crit02AppRepo).app
	hash, err := auth.HashClientSecret("correct-secret")
	if err != nil {
		t.Fatal(err)
	}
	app.ClientSecretHash = hash

	// Baseline: default scope, no DPoP requirement → token.
	if _, err := svc.Token(context.Background(), ccReq(""), "test-client", "correct-secret"); err != nil {
		t.Fatalf("baseline client_credentials: %v", err)
	}

	// Unknown scope must be rejected, not minted verbatim into the token.
	_, err = svc.Token(context.Background(), ccReq("openid bogus-scope"), "test-client", "correct-secret")
	if !errors.Is(err, ErrInvalidScope) {
		t.Fatalf("unknown scope: got %v, want ErrInvalidScope", err)
	}

	// A DPoP-required client with no proof on the context must be refused.
	app.RequireDPoP = true
	_, err = svc.Token(context.Background(), ccReq(""), "test-client", "correct-secret")
	if !errors.Is(err, ErrDPoPRequired) {
		t.Fatalf("DPoP-required client without proof: got %v, want ErrDPoPRequired", err)
	}
	app.RequireDPoP = false

	// P3-3: and a deactivated client gets nothing.
	app.Active = false
	_, err = svc.Token(context.Background(), ccReq(""), "test-client", "correct-secret")
	if !errors.Is(err, ErrAppInactive) {
		t.Fatalf("inactive client client_credentials: got %v, want ErrAppInactive", err)
	}
}
