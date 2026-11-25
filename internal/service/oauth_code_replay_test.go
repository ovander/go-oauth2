// Package service — a replayed authorization code (RFC 6749 §4.1.2,
// CODE_REPLAY_MODE). The code is always refused; observe audits the replay,
// enforce also revokes the tokens the code was redeemed for: its refresh-token
// family and its access token.
package service

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ovander/go-oauth2/internal/dto"
	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/repository"
	"github.com/ovander/go-oauth2/internal/shared/auth"
)

// copyCodeRepo stores codes by value, as the database does: what the code
// store changes on a code it read is not stored unless it writes it.
type copyCodeRepo struct {
	mu    sync.Mutex
	codes map[string]model.AuthorizationCode
	// staleReads makes the next FindByCode calls return the code as unused,
	// as a read that raced with another redemption does.
	staleReads int
}

func newCopyCodeRepo() *copyCodeRepo {
	return &copyCodeRepo{codes: map[string]model.AuthorizationCode{}}
}

func (r *copyCodeRepo) Create(_ context.Context, c *model.AuthorizationCode) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.codes[c.Code] = *c
	return nil
}

func (r *copyCodeRepo) FindByCode(_ context.Context, code string) (*model.AuthorizationCode, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.codes[code]
	if !ok {
		return nil, errors.New("not found")
	}
	if r.staleReads > 0 {
		r.staleReads--
		c.Used, c.TokenFamily, c.AccessJTI = false, "", ""
	}
	return &c, nil
}

// get returns a stored code.
func (r *copyCodeRepo) get(t *testing.T, code string) model.AuthorizationCode {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.codes[code]
	if !ok {
		t.Fatalf("code %q is not stored", code)
	}
	return c
}

func (r *copyCodeRepo) MarkAsUsed(ctx context.Context, code string) error {
	return r.markUsed(code, func(*model.AuthorizationCode) {})
}

func (r *copyCodeRepo) markUsed(code string, set func(*model.AuthorizationCode)) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.codes[code]
	if !ok || c.Used {
		return errors.New("not found")
	}
	c.Used = true
	set(&c)
	r.codes[code] = c
	return nil
}

func (r *copyCodeRepo) Delete(_ context.Context, code string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.codes, code)
	return nil
}

func (r *copyCodeRepo) DeleteExpired(_ context.Context) (int64, error) { return 0, nil }
func (r *copyCodeRepo) DeleteByUserID(_ context.Context, _ uint) error { return nil }

// expire moves a stored code's expiry into the past.
func (r *copyCodeRepo) expire(t *testing.T, code string) {
	t.Helper()
	c := r.get(t, code)
	c.ExpiresAt = time.Now().Add(-time.Minute)
	r.mu.Lock()
	r.codes[code] = c
	r.mu.Unlock()
}

// recordingCodeRepo also records the tokens a code is redeemed for, as the
// GORM repository does.
type recordingCodeRepo struct{ *copyCodeRepo }

func (r recordingCodeRepo) MarkAsUsedWithTokens(_ context.Context, code, family, jti string, keepUntil time.Time) error {
	return r.markUsed(code, func(c *model.AuthorizationCode) {
		c.TokenFamily, c.AccessJTI = family, jti
		if keepUntil.After(c.ExpiresAt) {
			c.ExpiresAt = keepUntil
		}
	})
}

func (r recordingCodeRepo) KeepFamilyUntil(_ context.Context, family string, keepUntil time.Time) error {
	if family == "" {
		return nil // as the GORM repository: no family, no code to keep
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	for k, c := range r.codes {
		if c.Used && c.TokenFamily == family && keepUntil.After(c.ExpiresAt) {
			c.ExpiresAt = keepUntil
			r.codes[k] = c
		}
	}
	return nil
}

// stored says whether a code is still stored.
func (r *copyCodeRepo) stored(code string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.codes[code]
	return ok
}

// setExpiry sets a stored code's expiry.
func (r *copyCodeRepo) setExpiry(t *testing.T, code string, at time.Time) {
	t.Helper()
	c := r.get(t, code)
	c.ExpiresAt = at
	r.mu.Lock()
	r.codes[code] = c
	r.mu.Unlock()
}

var (
	_ repository.AuthorizationCodeRedeemer       = recordingCodeRepo{}
	_ repository.AuthorizationCodeFamilyRetainer = recordingCodeRepo{}
)

type replayFixture struct {
	svc   *oauthService
	codes *copyCodeRepo
	used  *memUsedTokenRepo
	audit *captureAuditRepo
	code  string
	resp  *dto.TokenResponse
}

// newReplayFixture redeems one code under mode; record says whether the code
// repository records the tokens a code is redeemed for.
func newReplayFixture(t *testing.T, mode string, record bool) *replayFixture {
	t.Helper()
	return newReplayFixtureWith(t, mode, record, auth.CodeStoreConfig{TTL: 10 * time.Minute})
}

func newReplayFixtureWith(t *testing.T, mode string, record bool, cfg auth.CodeStoreConfig) *replayFixture {
	t.Helper()
	return newReplayFixtureRepo(t, mode, cfg, func(codes *copyCodeRepo) repository.AuthorizationCodeRepository {
		if record {
			return recordingCodeRepo{codes}
		}
		return codes
	})
}

// newReplayFixtureRepo redeems one code under mode, with the code repository
// repo builds over the fixture's codes.
func newReplayFixtureRepo(t *testing.T, mode string, cfg auth.CodeStoreConfig,
	repo func(*copyCodeRepo) repository.AuthorizationCodeRepository) *replayFixture {
	t.Helper()
	user := &model.User{ID: 42, Email: "op@example.test", IsVerified: true, Role: model.UserRoleSuperadmin}
	svc := newAuthorizeSvc(t, user)
	f := &replayFixture{svc: svc, codes: newCopyCodeRepo(), used: newMemUsedTokenRepo(), audit: &captureAuditRepo{}}
	cs := auth.NewCodeStore(repo(f.codes), cfg)
	t.Cleanup(cs.Stop)
	svc.codeStore, svc.usedTokenRepo, svc.auditRepo = cs, f.used, f.audit
	svc.SetCodeReplayMode(mode)

	code, err := svc.Authorize(context.Background(), authnAuthorizeReq(), user.ID)
	if err != nil {
		t.Fatalf("Authorize: %v", err)
	}
	f.code = code
	if f.resp, err = f.exchange(); err != nil {
		t.Fatalf("first redemption: %v", err)
	}
	return f
}

func (f *replayFixture) exchange() (*dto.TokenResponse, error) {
	return f.exchangeAs("admin-console-dev2", authnVerifier)
}

func (f *replayFixture) exchangeAs(clientID, verifier string) (*dto.TokenResponse, error) {
	return f.svc.handleAuthorizationCodeGrant(context.Background(), dto.TokenRequest{
		GrantType:    "authorization_code",
		Code:         f.code,
		RedirectURI:  authnAuthorizeReq().RedirectURI,
		CodeVerifier: verifier,
	}, clientID, "")
}

func (f *replayFixture) refresh(token string) (*dto.TokenResponse, error) {
	return f.svc.handleRefreshTokenGrant(context.Background(), refreshReq(token), "admin-console-dev2", "")
}

func (f *replayFixture) accessRevoked(t *testing.T) bool {
	t.Helper()
	c, err := f.svc.tokenService.VerifyAccessToken(f.resp.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}
	revoked, err := f.used.IsUsed(context.Background(), c.ID)
	if err != nil {
		t.Fatalf("IsUsed: %v", err)
	}
	return revoked
}

func TestCodeReplay_EnforceRevokesWhatTheCodeWasRedeemedFor(t *testing.T) {
	f := newReplayFixture(t, codeReplayModeEnforce, true)

	if _, err := f.exchange(); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("replay = %v, want ErrInvalidCode", err)
	}
	ev := f.audit.last
	if ev == nil || ev.EventType != model.SecurityEventAuthCodeFailed || ev.Details["reason"] != "code_replayed" ||
		ev.Details["revoked"] != "tokens" || ev.UserID == nil || *ev.UserID != 42 {
		t.Fatalf("replay not audited as a revoking code_replayed: %+v", ev)
	}
	if !f.accessRevoked(t) {
		t.Error("the access token the code was redeemed for is not revoked")
	}
	if _, err := f.refresh(f.resp.RefreshToken); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("refresh after the replay = %v, want ErrInvalidToken (family revoked)", err)
	}

	// The code store reports a code once: a second replay is refused as an
	// unknown code, without signalling again.
	if _, err := f.exchange(); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("second replay = %v", err)
	}
	if f.audit.last.Details["reason"] != "invalid_or_used_code" {
		t.Errorf("second replay signalled again: %+v", f.audit.last)
	}
}

// The family revoked is the code's: a refresh token rotated from it before
// the replay is revoked too.
func TestCodeReplay_EnforceRevokesTheRotatedFamily(t *testing.T) {
	f := newReplayFixture(t, codeReplayModeEnforce, true)
	rotated, err := f.refresh(f.resp.RefreshToken)
	if err != nil {
		t.Fatalf("refresh before the replay: %v", err)
	}
	if _, err := f.exchange(); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("replay = %v", err)
	}
	if _, err := f.refresh(rotated.RefreshToken); !errors.Is(err, ErrInvalidToken) {
		t.Errorf("rotated refresh token after the replay = %v, want ErrInvalidToken", err)
	}
}

// A code used and then expired is still a replay: its tokens may be valid.
func TestCodeReplay_DetectedAfterExpiry(t *testing.T) {
	f := newReplayFixture(t, codeReplayModeEnforce, true)
	f.codes.expire(t, f.code)
	if _, err := f.exchange(); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("replay = %v", err)
	}
	if f.audit.last.Details["reason"] != "code_replayed" || !f.accessRevoked(t) {
		t.Errorf("replay of an expired code not handled: %+v", f.audit.last)
	}
}

func TestCodeReplay_ObserveAuditsWithoutRevoking(t *testing.T) {
	f := newReplayFixture(t, codeReplayModeObserve, true)
	if _, err := f.exchange(); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("replay = %v", err)
	}
	ev := f.audit.last
	if ev.Details["reason"] != "code_replayed" || ev.Details["mode"] != "observe" || ev.Details["revoked"] != nil {
		t.Fatalf("observe audit = %+v", ev)
	}
	if f.accessRevoked(t) {
		t.Error("observe revoked the access token")
	}
	if _, err := f.refresh(f.resp.RefreshToken); err != nil {
		t.Errorf("observe revoked the refresh token: %v", err)
	}
}

func TestCodeReplay_OffRefusesAsBefore(t *testing.T) {
	f := newReplayFixture(t, "off", true)
	if _, err := f.exchange(); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("replay = %v", err)
	}
	if f.audit.last.Details["reason"] != "invalid_or_used_code" || f.audit.last.UserID != nil {
		t.Fatalf("off audit = %+v, want the historical invalid_or_used_code", f.audit.last)
	}
	if f.codes.stored(f.code) {
		t.Error("off left the replayed code stored")
	}
	if f.accessRevoked(t) {
		t.Error("off revoked the access token")
	}
	if _, err := f.refresh(f.resp.RefreshToken); err != nil {
		t.Errorf("off revoked the refresh token: %v", err)
	}
}

// A code whose redemption recorded nothing (redeemed before migration 0035)
// is audited, and nothing is revoked.
func TestCodeReplay_EnforceWithoutRecordedTokens(t *testing.T) {
	f := newReplayFixture(t, codeReplayModeEnforce, false)
	if _, err := f.exchange(); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("replay = %v", err)
	}
	if f.audit.last.Details["reason"] != "code_replayed" || f.audit.last.Details["revoked"] != "none" {
		t.Fatalf("audit = %+v, want code_replayed with revoked none", f.audit.last)
	}
	if f.accessRevoked(t) {
		t.Error("a token was revoked although none was recorded")
	}
}

// The tokens are minted with the family and jti recorded with the
// redemption.
func TestCodeGrant_MintsTheRecordedIDs(t *testing.T) {
	f := newReplayFixture(t, "off", true)
	stored := f.codes.get(t, f.code)
	ac, err := f.svc.tokenService.VerifyAccessToken(f.resp.AccessToken)
	if err != nil {
		t.Fatal(err)
	}
	rc, err := f.svc.tokenService.VerifyRefreshToken(f.resp.RefreshToken)
	if err != nil {
		t.Fatal(err)
	}
	if stored.AccessJTI == "" || ac.ID != stored.AccessJTI || stored.TokenFamily == "" || rc.Family != stored.TokenFamily {
		t.Errorf("recorded jti/family %q/%q, minted %q/%q", stored.AccessJTI, stored.TokenFamily, ac.ID, rc.Family)
	}
}

// Only the code's client can revoke: a replay without the PKCE verifier, or
// from another client, is audited and revokes nothing — whoever merely saw a
// used code cannot end the user's sign-in.
func TestCodeReplay_EnforceRevokesOnlyForTheCodesClient(t *testing.T) {
	for name, as := range map[string]struct{ client, verifier string }{
		"no verifier":    {"admin-console-dev2", ""},
		"wrong verifier": {"admin-console-dev2", "wrong-verifier-wrong-verifier-wrong-verifier-x"},
		"other client":   {"other-client", authnVerifier},
	} {
		t.Run(name, func(t *testing.T) {
			f := newReplayFixture(t, codeReplayModeEnforce, true)
			if _, err := f.exchangeAs(as.client, as.verifier); !errors.Is(err, ErrInvalidCode) {
				t.Fatalf("replay = %v", err)
			}
			if ev := f.audit.last; ev.Details["reason"] != "code_replayed" || ev.Details["revoked"] != "none_unauthenticated" {
				t.Fatalf("audit = %+v, want code_replayed with revoked none_unauthenticated", ev)
			}
			if f.accessRevoked(t) {
				t.Error("an unauthenticated replay revoked the access token")
			}
			if _, err := f.refresh(f.resp.RefreshToken); err != nil {
				t.Errorf("an unauthenticated replay revoked the refresh token: %v", err)
			}
			// It did not erase the evidence: the code's own client, replaying
			// it afterwards, still revokes.
			if !f.codes.stored(f.code) {
				t.Fatal("an unauthenticated replay removed the code")
			}
			if _, err := f.exchange(); !errors.Is(err, ErrInvalidCode) {
				t.Fatalf("authenticated replay = %v", err)
			}
			if ev := f.audit.last; ev.Details["revoked"] != "tokens" || !f.accessRevoked(t) {
				t.Fatalf("the authenticated replay after an unauthenticated one did not revoke: %+v", ev)
			}
			if f.codes.stored(f.code) {
				t.Error("the authenticated replay left the code stored")
			}
		})
	}
}

// Each refresh rotation keeps the family's code for another retention, so the
// code outlives no token of its family.
func TestCodeReplay_RefreshKeepsTheFamilysCode(t *testing.T) {
	retention := 7 * 24 * time.Hour
	f := newReplayFixtureWith(t, codeReplayModeEnforce, true, auth.CodeStoreConfig{TTL: 10 * time.Minute, ReplayRetention: retention})
	// As if the retention had nearly run out.
	f.codes.setExpiry(t, f.code, time.Now().Add(time.Minute))
	if _, err := f.refresh(f.resp.RefreshToken); err != nil {
		t.Fatalf("refresh: %v", err)
	}
	if exp := f.codes.get(t, f.code).ExpiresAt; exp.Before(time.Now().Add(retention - time.Minute)) {
		t.Fatalf("after a rotation the code expires at %v, want about %v from now", exp, retention)
	}
}

// unretainableCodeRepo records redemptions but cannot extend a family's
// retention until fixed.
type unretainableCodeRepo struct {
	recordingCodeRepo
	broken *bool
}

func (r unretainableCodeRepo) KeepFamilyUntil(ctx context.Context, family string, keepUntil time.Time) error {
	if *r.broken {
		return errors.New("database unavailable")
	}
	return r.recordingCodeRepo.KeepFamilyUntil(ctx, family, keepUntil)
}

// Under enforce, a refresh whose family's code cannot be kept is refused, so
// no token outlives the code a replay would revoke it by; the refusal is a
// server error and leaves the old refresh token good to retry with. Under
// observe the refresh goes on.
func TestCodeReplay_RefreshWhenTheCodeCannotBeKept(t *testing.T) {
	cfg := auth.CodeStoreConfig{TTL: 10 * time.Minute, ReplayRetention: 7 * 24 * time.Hour}
	for _, mode := range []string{codeReplayModeEnforce, codeReplayModeObserve} {
		t.Run(mode, func(t *testing.T) {
			broken := true
			f := newReplayFixtureRepo(t, mode, cfg, func(codes *copyCodeRepo) repository.AuthorizationCodeRepository {
				return unretainableCodeRepo{recordingCodeRepo{codes}, &broken}
			})
			resp, err := f.refresh(f.resp.RefreshToken)
			if mode == codeReplayModeObserve {
				if err != nil || resp == nil {
					t.Fatalf("observe: refresh = %v, %v; want new tokens", resp, err)
				}
				return
			}
			if err == nil || resp != nil {
				t.Fatalf("enforce: refresh = %v, %v; want a refusal", resp, err)
			}
			// A server error, not invalid_grant: the token is still good.
			if errors.Is(err, ErrInvalidToken) {
				t.Fatalf("enforce: refusal %v is invalid_grant; want a server error", err)
			}
			broken = false
			if _, err := f.refresh(f.resp.RefreshToken); err != nil {
				t.Fatalf("enforce: retry with the same refresh token: %v", err)
			}
		})
	}
}

// A redemption that loses the race to another one is a replay of a code
// redeemed a moment ago, not an unknown code.
func TestCodeReplay_ConcurrentRedemptionIsAReplay(t *testing.T) {
	f := newReplayFixture(t, codeReplayModeEnforce, true)
	f.codes.mu.Lock()
	f.codes.staleReads = 1
	f.codes.mu.Unlock()
	if _, err := f.exchange(); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("losing redemption = %v", err)
	}
	if ev := f.audit.last; ev.Details["reason"] != "code_replayed" || ev.Details["revoked"] != "tokens" {
		t.Fatalf("audit = %+v, want a revoking code_replayed", ev)
	}
	if !f.accessRevoked(t) {
		t.Error("the winning redemption's access token is not revoked")
	}
}

// With a replay retention, a redeemed code is kept while its refresh tokens
// may live, so the expiry sweep does not erase the evidence of a late replay.
func TestCodeStore_ReplayRetentionKeepsTheRedeemedCode(t *testing.T) {
	retention := 7 * 24 * time.Hour
	f := newReplayFixtureWith(t, codeReplayModeEnforce, true, auth.CodeStoreConfig{TTL: 10 * time.Minute, ReplayRetention: retention})
	if exp := f.codes.get(t, f.code).ExpiresAt; exp.Before(time.Now().Add(retention - time.Minute)) {
		t.Fatalf("redeemed code expires at %v, want about %v from now", exp, retention)
	}
	// Without a retention it keeps its own expiry.
	g := newReplayFixture(t, codeReplayModeEnforce, true)
	if exp := g.codes.get(t, g.code).ExpiresAt; exp.After(time.Now().Add(11 * time.Minute)) {
		t.Fatalf("without a retention the redeemed code expires at %v", exp)
	}
}

// failingRevocationRepo is a used-token store that cannot record a
// revocation.
type failingRevocationRepo struct{ repository.UsedTokenRepository }

func (failingRevocationRepo) MarkAsUsed(context.Context, string, string, uint, time.Time) error {
	return errors.New("used-token store unavailable")
}

// Under enforce, a replay whose tokens could not be revoked keeps the code:
// the next authenticated replay revokes them, rather than finding an unknown
// code (fail closed).
func TestCodeReplay_EnforceKeepsTheCodeWhenRevocationFails(t *testing.T) {
	f := newReplayFixture(t, codeReplayModeEnforce, true)

	f.svc.usedTokenRepo = failingRevocationRepo{f.used}
	if _, err := f.exchange(); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("replay = %v, want ErrInvalidCode", err)
	}
	if got := f.audit.last.Details["revoked"]; got != "failed" {
		t.Fatalf("revoked = %v, want failed", got)
	}
	if !f.codes.stored(f.code) {
		t.Fatal("the code was removed although its tokens were not revoked")
	}

	f.svc.usedTokenRepo = f.used
	if _, err := f.exchange(); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("second replay = %v, want ErrInvalidCode", err)
	}
	if got := f.audit.last.Details["revoked"]; got != "tokens" {
		t.Fatalf("second replay: revoked = %v, want tokens", got)
	}
	if !f.accessRevoked(t) {
		t.Error("the access token is still not revoked after the second replay")
	}
	if f.codes.stored(f.code) {
		t.Error("the code is still stored once its tokens are revoked")
	}
}
