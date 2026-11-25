// Package service — a client whose secret cannot be checked (unknown, public
// or inactive) pays the cost of a secret check, so that the response time of
// the token, introspection and revocation endpoints does not tell which
// client_ids exist (#366).
package service

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
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
	if _, err := svc.lookupTokenClient(context.Background(), "ghost"); err == nil || errors.Is(err, ErrAppNotFound) || n.Load() != 0 {
		t.Errorf("a lookup failure = %v after %d dummy checks, want an internal error and none", err, n.Load())
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
// notFoundAppRepo answers an unknown client_id as the GORM repository does.
type notFoundAppRepo struct{ *memAppRepo }

func (r notFoundAppRepo) FindByClientID(ctx context.Context, clientID string) (*model.App, error) {
	app, err := r.memAppRepo.FindByClientID(ctx, clientID)
	if err != nil {
		return nil, gorm.ErrRecordNotFound
	}
	return app, nil
}

// failingAppRepo fails every lookup, as a database outage does.
type failingAppRepo struct{ *memAppRepo }

func (failingAppRepo) FindByClientID(context.Context, string) (*model.App, error) {
	return nil, errors.New("db down")
}

func TestValidateClientCredentials_UnknownOrInactivePaysASecretCheck(t *testing.T) {
	mem := newMemAppRepo()
	repo := notFoundAppRepo{mem}
	hash, err := auth.HashClientSecret("s3cret-for-the-test")
	if err != nil {
		t.Fatal(err)
	}
	for _, a := range []*model.App{
		{ClientID: "active", Active: true, ClientSecretHash: hash},
		{ClientID: "inactive", Active: false, ClientSecretHash: hash},
	} {
		if err := mem.Create(context.Background(), a); err != nil {
			t.Fatalf("create %s: %v", a.ClientID, err)
		}
	}
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
	// A database failure is an error, without the cost.
	dummy, n = countingDummy()
	svc = &appService{repo: failingAppRepo{mem}, dummyClientSecret: dummy}
	if _, err := svc.ValidateClientCredentials(context.Background(), "active", "s3cret-for-the-test"); err == nil || errors.Is(err, ErrAppNotFound) || n.Load() != 0 {
		t.Errorf("a lookup failure = %v after %d dummy checks, want an internal error and none", err, n.Load())
	}
}

// A client whose secret is still a legacy SHA-256 hash answers a wrong secret
// after a check of the same cost as a bcrypt one, and still accepts its own.
func TestCheckClientSecret_LegacyHashCostsACheck(t *testing.T) {
	auth.CheckDummyClientSecret() // compute the dummy hash outside the timing
	sum := sha256.Sum256([]byte("legacy-secret"))
	legacy := hex.EncodeToString(sum[:])
	if !auth.CheckClientSecret("legacy-secret", legacy) {
		t.Fatal("a legacy hash no longer accepts its secret")
	}
	start := time.Now()
	if auth.CheckClientSecret("wrong", legacy) {
		t.Fatal("a wrong secret matched a legacy hash")
	}
	if elapsed := time.Since(start); elapsed < 20*time.Millisecond {
		t.Errorf("a legacy hash refused a wrong secret in %v: no bcrypt-cost check was made", elapsed)
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

// A failed client lookup in the token exchange is an internal error, not an
// unknown client: refused, without a dummy check, and audited as such.
func TestExchangeToken_ClientLookupFailureIsInternal(t *testing.T) {
	app := &model.App{ID: 7, ClientID: "c", AllowTokenExchange: true}
	svc, audit, ts := newShadowExchangeSvc(t, app)
	svc.tokenExchangeMode = TokenExchangeModeEnforce
	dbDown := errors.New("db down")
	svc.appRepo = &lookupErrAppRepo{err: dbDown}
	dummy, n := countingDummy()
	svc.dummyClientSecret = dummy
	form := exForm(mintToken(t, ts, 100, "read"), "", "read", "https://api")
	_, err := svc.ExchangeToken(context.Background(), form, "c", "any")
	if !errors.Is(err, dbDown) || errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("exchange with a failed lookup = %v, want the lookup error, not invalid credentials", err)
	}
	if n.Load() != 0 {
		t.Errorf("a lookup failure paid %d dummy checks", n.Load())
	}
	if audit.last == nil || audit.last.Details["deny_reason"] != "client_lookup_failed" {
		t.Errorf("audit = %+v, want deny_reason client_lookup_failed", audit.last)
	}
}
