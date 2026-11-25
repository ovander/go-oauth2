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
	return &c, nil
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
func (r *copyCodeRepo) expire(code string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c := r.codes[code]
	c.ExpiresAt = time.Now().Add(-time.Minute)
	r.codes[code] = c
}

// recordingCodeRepo also records the tokens a code is redeemed for, as the
// GORM repository does.
type recordingCodeRepo struct{ *copyCodeRepo }

func (r recordingCodeRepo) MarkAsUsedWithTokens(_ context.Context, code, family, jti string) error {
	return r.markUsed(code, func(c *model.AuthorizationCode) { c.TokenFamily, c.AccessJTI = family, jti })
}

var _ repository.AuthorizationCodeRedeemer = recordingCodeRepo{}

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
	user := &model.User{ID: 42, Email: "op@example.test", IsVerified: true, Role: model.UserRoleSuperadmin}
	svc := newAuthorizeSvc(t, user)
	f := &replayFixture{svc: svc, codes: newCopyCodeRepo(), used: newMemUsedTokenRepo(), audit: &captureAuditRepo{}}
	var repo repository.AuthorizationCodeRepository = f.codes
	if record {
		repo = recordingCodeRepo{f.codes}
	}
	cs := auth.NewCodeStoreWithTTL(repo, 10*time.Minute)
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
	return f.svc.handleAuthorizationCodeGrant(context.Background(), dto.TokenRequest{
		GrantType:    "authorization_code",
		Code:         f.code,
		RedirectURI:  authorizeReq().RedirectURI,
		CodeVerifier: authnVerifier,
	}, "admin-console-dev2", "")
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
	revoked, _ := f.used.IsUsed(context.Background(), c.ID)
	return revoked
}

func TestCodeReplay_EnforceRevokesWhatTheCodeWasRedeemedFor(t *testing.T) {
	f := newReplayFixture(t, refreshReuseModeEnforce, true)

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
	f := newReplayFixture(t, refreshReuseModeEnforce, true)
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
	f := newReplayFixture(t, refreshReuseModeEnforce, true)
	f.codes.expire(f.code)
	if _, err := f.exchange(); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("replay = %v", err)
	}
	if f.audit.last.Details["reason"] != "code_replayed" || !f.accessRevoked(t) {
		t.Errorf("replay of an expired code not handled: %+v", f.audit.last)
	}
}

func TestCodeReplay_ObserveAuditsWithoutRevoking(t *testing.T) {
	f := newReplayFixture(t, refreshReuseModeObserve, true)
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
	f := newReplayFixture(t, refreshReuseModeOff, true)
	if _, err := f.exchange(); !errors.Is(err, ErrInvalidCode) {
		t.Fatalf("replay = %v", err)
	}
	if f.audit.last.Details["reason"] != "invalid_or_used_code" || f.audit.last.UserID != nil {
		t.Fatalf("off audit = %+v, want the historical invalid_or_used_code", f.audit.last)
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
	f := newReplayFixture(t, refreshReuseModeEnforce, false)
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
	f := newReplayFixture(t, refreshReuseModeOff, true)
	stored := f.codes.codes[f.code]
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
