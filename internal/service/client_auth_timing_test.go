// Package service — a client whose secret cannot be checked (unknown, public
// or inactive) pays the cost of a secret check, so that the response time of
// the token, introspection and revocation endpoints does not tell which
// client_ids exist (#366).
package service

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ovander/go-oauth2/internal/dto"
	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/shared/auth"
	"gorm.io/gorm"
)

func countingDummy() (func() bool, *atomic.Int32) {
	var n atomic.Int32
	return func() bool { n.Add(1); return false }, &n
}

// The token endpoint pays a secret check for an unknown client: the client
// lookup every grant goes through, and the client_credentials grant end to
// end.
func TestTokenGrants_UnknownClientPaysASecretCheck(t *testing.T) {
	ghost := &model.App{ID: 9, ClientID: "ghost", Active: true, RedirectURIs: model.StringArray{"https://app.example.com/cb"}}
	newSvc := func(lookupErr error) (*oauthService, *atomic.Int32) {
		dummy, n := countingDummy()
		svc := newCrit02Service(t, ghost)
		svc.appRepo = &lookupErrAppRepo{err: lookupErr}
		svc.dummyClientSecret = dummy
		return svc, n
	}
	svc, n := newSvc(gorm.ErrRecordNotFound)
	if _, err := svc.lookupTokenClient(context.Background(), "ghost"); !errors.Is(err, ErrAppNotFound) || n.Load() != 1 {
		t.Fatalf("lookup of an unknown client = %v after %d secret checks, want ErrAppNotFound after 1", err, n.Load())
	}
	svc, n = newSvc(gorm.ErrRecordNotFound)
	if _, err := svc.handleClientCredentialsGrant(context.Background(), dto.TokenRequest{Scope: "api"}, "ghost", "any-secret"); !errors.Is(err, ErrAppNotFound) || n.Load() != 1 {
		t.Fatalf("client_credentials for an unknown client = %v after %d secret checks", err, n.Load())
	}
	// A database failure is not an unknown client: it is an internal error,
	// answered as such, without a dummy check.
	svc, n = newSvc(errors.New("db down"))
	_, _ = svc.lookupTokenClient(context.Background(), "ghost")
	if n.Load() != 0 {
		t.Errorf("a lookup failure paid %d dummy checks", n.Load())
	}
}

// The token exchange pays a secret check for an unknown and a public client.
func TestExchangeToken_UnknownOrPublicClientPaysASecretCheck(t *testing.T) {
	for name, setup := range map[string]func(*oauthService, *model.App){
		"unknown client": func(s *oauthService, _ *model.App) { s.appRepo = &lookupErrAppRepo{err: gorm.ErrRecordNotFound} },
		"public client":  func(_ *oauthService, a *model.App) { a.ClientSecretHash = "" },
	} {
		t.Run(name, func(t *testing.T) {
			app := &model.App{ID: 7, ClientID: "c", AllowTokenExchange: true}
			svc, _, ts := newShadowExchangeSvc(t, app)
			svc.tokenExchangeMode = TokenExchangeModeEnforce
			setup(svc, app)
			dummy, n := countingDummy()
			svc.dummyClientSecret = dummy
			form := exForm(mintToken(t, ts, 100, "read"), "", "read", "https://api")
			if _, err := svc.ExchangeToken(context.Background(), form, "c", ""); err == nil {
				t.Fatal("the exchange was allowed")
			}
			if n.Load() != 1 {
				t.Fatalf("paid %d secret checks, want 1", n.Load())
			}
		})
	}
}

// Introspection and revocation authenticate clients with
// ValidateClientCredentials: an unknown or inactive client pays a secret check.
func TestValidateClientCredentials_UnknownOrInactivePaysASecretCheck(t *testing.T) {
	repo := newMemAppRepo()
	hash, err := auth.HashClientSecret("s3cret-for-the-test")
	if err != nil {
		t.Fatal(err)
	}
	_ = repo.Create(context.Background(), &model.App{ClientID: "active", Active: true, ClientSecretHash: hash})
	_ = repo.Create(context.Background(), &model.App{ClientID: "inactive", Active: false, ClientSecretHash: hash})
	for _, clientID := range []string{"nobody", "inactive"} {
		dummy, n := countingDummy()
		svc := &appService{repo: repo, dummyClientSecret: dummy}
		if _, err := svc.ValidateClientCredentials(context.Background(), clientID, "s3cret-for-the-test"); err == nil {
			t.Fatalf("%s: credentials accepted", clientID)
		}
		if n.Load() != 1 {
			t.Errorf("%s: paid %d secret checks, want 1", clientID, n.Load())
		}
	}
	// A known, active client pays the real check only.
	dummy, n := countingDummy()
	svc := &appService{repo: repo, dummyClientSecret: dummy}
	if _, err := svc.ValidateClientCredentials(context.Background(), "active", "s3cret-for-the-test"); err != nil {
		t.Fatalf("active client: %v", err)
	}
	if n.Load() != 0 {
		t.Errorf("a known client paid %d dummy checks", n.Load())
	}
}

// CheckClientSecret against no hash (a public client) refuses, after a check
// of the same cost as a client secret's.
func TestCheckClientSecret_NoHashCostsACheck(t *testing.T) {
	auth.CheckDummyClientSecret() // compute the dummy hash outside the timing
	start := time.Now()
	if auth.CheckClientSecret("anything", "") {
		t.Fatal("a secret matched an empty hash")
	}
	if elapsed := time.Since(start); elapsed < 20*time.Millisecond {
		t.Errorf("an empty hash was refused in %v: no bcrypt-cost check was made", elapsed)
	}
}
