// Package service — tests for refresh-token reuse detection (RFC 9700 §4.14.2).
//
// A reused (already-rotated) single-use refresh token is always rejected
// (HIGH-04). When REFRESH_REUSE_MODE is "observe" the reuse is additionally
// audited; when "enforce" the token's family (that sign-in's refresh tokens at
// that client) is also revoked, since reuse signals token theft (#365).
package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/repository"
	"github.com/ovander/go-oauth2/internal/shared/auth"
)

// reuseUserRepo wraps high04UserRepo to count IncrementTokenVersion calls.
type reuseUserRepo struct {
	*high04UserRepo
	incremented int
}

func (r *reuseUserRepo) IncrementTokenVersion(_ context.Context, _ uint) error {
	r.incremented++
	return nil
}

// newReuseService consumes the refresh token once (so a replay is a reuse), and
// wires an audit capture + an IncrementTokenVersion spy.
func newReuseService(t *testing.T, mode string) (*oauthService, *captureAuditRepo, *reuseUserRepo, string) {
	t.Helper()
	usedRepo := newMemUsedTokenRepo()
	svc, refreshToken := newHigh04Service(t, usedRepo)

	spy := &reuseUserRepo{high04UserRepo: svc.userRepo.(*high04UserRepo)}
	audit := &captureAuditRepo{}
	svc.userRepo = spy
	svc.auditRepo = audit
	svc.refreshReuseMode = mode

	// First use rotates the token (marks the JTI used).
	if _, err := svc.handleRefreshTokenGrant(context.Background(), refreshReq(refreshToken), "test-client", ""); errors.Is(err, ErrInvalidToken) {
		t.Fatalf("first use unexpectedly rejected: %v", err)
	}
	return svc, audit, spy, refreshToken
}

// Off: a reused token is rejected, with no audit event and no family revocation.
func TestRefreshReuse_OffRejectsOnly(t *testing.T) {
	svc, audit, spy, token := newReuseService(t, refreshReuseModeOff)

	if _, err := svc.handleRefreshTokenGrant(context.Background(), refreshReq(token), "test-client", ""); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("reuse must be rejected, got %v", err)
	}
	if audit.last != nil && audit.last.EventType == model.SecurityEventRefreshTokenReuse {
		t.Error("off mode must not audit a reuse event")
	}
	if spy.incremented != 0 {
		t.Errorf("off mode must not revoke the token family, got %d increments", spy.incremented)
	}
}

// Observe: a reused token is rejected and audited, but the family is not revoked.
func TestRefreshReuse_ObserveAuditsWithoutRevoking(t *testing.T) {
	svc, audit, spy, token := newReuseService(t, refreshReuseModeObserve)

	if _, err := svc.handleRefreshTokenGrant(context.Background(), refreshReq(token), "test-client", ""); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("reuse must be rejected, got %v", err)
	}
	if audit.last == nil || audit.last.EventType != model.SecurityEventRefreshTokenReuse {
		t.Fatalf("observe must audit a refresh_token_reuse event, got %+v", audit.last)
	}
	if audit.last.Details["family_revoked"] == true {
		t.Error("observe must not revoke the token family")
	}
	if spy.incremented != 0 {
		t.Errorf("observe must not revoke the token family, got %d increments", spy.incremented)
	}
}

// Enforce: a reused token is rejected, audited, and its family is revoked —
// only that sign-in's tokens at that client, not the user's other sessions
// (#365).
func TestRefreshReuse_EnforceRevokesOnlyTheFamily(t *testing.T) {
	svc, audit, spy, used, r1, r2 := newFamilyReuseService(t, refreshReuseModeEnforce)
	other := issueRefreshToken(t, svc) // another sign-in: another family

	if _, err := svc.handleRefreshTokenGrant(context.Background(), refreshReq(r1), "test-client", ""); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("reuse must be rejected, got %v", err)
	}
	if audit.count(model.SecurityEventRefreshTokenReuse) != 1 {
		t.Fatalf("enforce must audit one refresh_token_reuse event, got %d", audit.count(model.SecurityEventRefreshTokenReuse))
	}
	ev := audit.lastOf(model.SecurityEventRefreshTokenReuse)
	if ev.Details["family_revoked"] != true || ev.Details["revoked"] != "family" {
		t.Errorf("enforce must record the family revocation, got %v", ev.Details)
	}
	if spy.incremented != 0 {
		t.Errorf("a family reuse must not revoke the user's other sessions, got %d increments", spy.incremented)
	}
	if kind, _ := used.UsedTokenType(context.Background(), familyRevocationKey(refreshClaims(t, svc, r1).Family)); kind != usedTokenTypeFamilyRevoked {
		t.Errorf("family revocation record = %q, want %q", kind, usedTokenTypeFamilyRevoked)
	}
	// The token the first use rotated to belongs to the revoked family.
	if _, err := svc.handleRefreshTokenGrant(context.Background(), refreshReq(r2), "test-client", ""); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("a token of the revoked family must be rejected, got %v", err)
	}
	// Another sign-in keeps working.
	if _, err := svc.handleRefreshTokenGrant(context.Background(), refreshReq(other), "test-client", ""); err != nil {
		t.Fatalf("another family must be unaffected, got %v", err)
	}
}

// A rotation keeps the family; a new sign-in starts another.
func TestRefreshFamily_KeptAcrossRotation(t *testing.T) {
	svc, _, _, _, r1, r2 := newFamilyReuseService(t, refreshReuseModeOff)
	f1, f2 := refreshClaims(t, svc, r1).Family, refreshClaims(t, svc, r2).Family
	if f1 == "" || f1 != f2 {
		t.Fatalf("family across rotation: %q -> %q", f1, f2)
	}
	if other := refreshClaims(t, svc, issueRefreshToken(t, svc)).Family; other == f1 {
		t.Fatal("a new sign-in must start a new family")
	}
}

// Replaying the same old token again is rejected without a second signal: one
// token cannot keep revoking sessions or flooding the audit log.
func TestRefreshReuse_SignalledOncePerToken(t *testing.T) {
	svc, audit, _, _, r1, _ := newFamilyReuseService(t, refreshReuseModeObserve)
	for i := 0; i < 3; i++ {
		if _, err := svc.handleRefreshTokenGrant(context.Background(), refreshReq(r1), "test-client", ""); !errors.Is(err, ErrInvalidToken) {
			t.Fatalf("replay %d must be rejected, got %v", i, err)
		}
	}
	if n := audit.count(model.SecurityEventRefreshTokenReuse); n != 1 {
		t.Fatalf("refresh_token_reuse events = %d, want 1", n)
	}
}

// A token revoked by RFC 7009 or a logout, then presented by a stale tab, is
// rejected but is not a theft signal.
func TestRefreshReuse_RevokedTokenIsNotAReuse(t *testing.T) {
	svc, audit, spy, _, _, r2 := newFamilyReuseService(t, refreshReuseModeEnforce)
	if err := svc.Revoke(context.Background(), r2, 0, "test-client"); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if _, err := svc.handleRefreshTokenGrant(context.Background(), refreshReq(r2), "test-client", ""); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("a revoked token must be rejected, got %v", err)
	}
	if n := audit.count(model.SecurityEventRefreshTokenReuse); n != 0 || spy.incremented != 0 {
		t.Fatalf("a revoked token raised a reuse signal (events %d, increments %d)", n, spy.incremented)
	}
}

// The reuse check runs after client authentication: a caller without the
// client's secret cannot raise the signal, so cannot revoke anything.
func TestRefreshReuse_UnauthenticatedCallerRaisesNoSignal(t *testing.T) {
	svc, audit, _, used, r1, _ := newFamilyReuseService(t, refreshReuseModeEnforce)
	hash, err := auth.HashClientSecret("the-client-secret")
	if err != nil {
		t.Fatal(err)
	}
	svc.appRepo.(*crit02AppRepo).app.ClientSecretHash = hash

	if _, err := svc.handleRefreshTokenGrant(context.Background(), refreshReq(r1), "test-client", "wrong"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong client secret: got %v, want ErrInvalidCredentials", err)
	}
	if n := audit.count(model.SecurityEventRefreshTokenReuse); n != 0 {
		t.Fatalf("an unauthenticated replay raised %d reuse events", n)
	}
	if kind, _ := used.UsedTokenType(context.Background(), familyRevocationKey(refreshClaims(t, svc, r1).Family)); kind != "" {
		t.Fatalf("an unauthenticated replay revoked the family (%q)", kind)
	}
	// With the secret, the same replay is the reuse signal.
	if _, err := svc.handleRefreshTokenGrant(context.Background(), refreshReq(r1), "test-client", "the-client-secret"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("authenticated replay: got %v, want ErrInvalidToken", err)
	}
	if n := audit.count(model.SecurityEventRefreshTokenReuse); n != 1 {
		t.Fatalf("authenticated replay: %d reuse events, want 1", n)
	}
}

// Two requests redeeming the same token at once: the loser is the reuse
// signal too, audited and, in enforce, revoking the family.
func TestRefreshReuse_ConcurrentReplayIsSignalled(t *testing.T) {
	svc, audit, _, used, _, r2 := newFamilyReuseService(t, refreshReuseModeEnforce)
	jti := refreshClaims(t, svc, r2).ID
	// The other request already marked it, but this one read it as unused.
	if err := used.MarkAsUsed(context.Background(), jti, "refresh", 42, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	used.hide = jti

	if _, err := svc.handleRefreshTokenGrant(context.Background(), refreshReq(r2), "test-client", ""); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("concurrent replay must be rejected, got %v", err)
	}
	ev := audit.lastOf(model.SecurityEventRefreshTokenReuse)
	if ev == nil || ev.Details["concurrent"] != true || ev.Details["revoked"] != "family" {
		t.Fatalf("concurrent replay not signalled: %+v", ev)
	}
}

// A refresh token issued before families has none: enforce revokes all the
// user's tokens for it, as before #365.
func TestRefreshReuse_LegacyTokenRevokesAllUserTokens(t *testing.T) {
	svc, audit, spy, _, _, _ := newFamilyReuseService(t, refreshReuseModeEnforce)
	legacy := legacyRefreshToken(t, svc)
	if _, err := svc.handleRefreshTokenGrant(context.Background(), refreshReq(legacy), "test-client", ""); err != nil {
		t.Fatalf("first use of the legacy token: %v", err)
	}
	if _, err := svc.handleRefreshTokenGrant(context.Background(), refreshReq(legacy), "test-client", ""); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("reuse must be rejected, got %v", err)
	}
	ev := audit.lastOf(model.SecurityEventRefreshTokenReuse)
	if ev == nil || ev.Details["revoked"] != "all_user_tokens" || spy.incremented != 1 {
		t.Fatalf("legacy reuse: event %+v, increments %d; want all_user_tokens and 1", ev, spy.incremented)
	}
}

// ---------------------------------------------------------------------------
// Fixtures
// ---------------------------------------------------------------------------

// typedUsedTokenRepo records each token's type (repository.UsedTokenTypeReader)
// and can hide one JTI from reads, to stage a concurrent redemption.
type typedUsedTokenRepo struct {
	*memUsedTokenRepo
	types map[string]string
	hide  string
}

func (r *typedUsedTokenRepo) MarkAsUsed(ctx context.Context, jti, tokenType string, userID uint, exp time.Time) error {
	if err := r.memUsedTokenRepo.MarkAsUsed(ctx, jti, tokenType, userID, exp); err != nil {
		return err
	}
	r.mu.Lock()
	r.types[jti] = tokenType
	r.mu.Unlock()
	return nil
}

func (r *typedUsedTokenRepo) IsUsed(ctx context.Context, jti string) (bool, error) {
	if jti == r.hide {
		return false, nil
	}
	return r.memUsedTokenRepo.IsUsed(ctx, jti)
}

func (r *typedUsedTokenRepo) UsedTokenType(_ context.Context, jti string) (string, error) {
	if jti == r.hide {
		return "", nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.types[jti], nil
}

// countingAuditRepo keeps every audit event.
type countingAuditRepo struct {
	repository.SecurityAuditLogRepository
	events []*model.SecurityAuditLog
}

func (c *countingAuditRepo) Create(_ context.Context, log *model.SecurityAuditLog) error {
	c.events = append(c.events, log)
	return nil
}

func (c *countingAuditRepo) count(t model.SecurityEventType) int {
	n := 0
	for _, e := range c.events {
		if e.EventType == t {
			n++
		}
	}
	return n
}

func (c *countingAuditRepo) lastOf(t model.SecurityEventType) *model.SecurityAuditLog {
	for i := len(c.events) - 1; i >= 0; i-- {
		if c.events[i].EventType == t {
			return c.events[i]
		}
	}
	return nil
}

// newFamilyReuseService is newReuseService with a typed used-token store and
// every audit event kept. It returns the first refresh token, already rotated,
// and the token it was rotated to.
func newFamilyReuseService(t *testing.T, mode string) (*oauthService, *countingAuditRepo, *reuseUserRepo, *typedUsedTokenRepo, string, string) {
	t.Helper()
	used := &typedUsedTokenRepo{memUsedTokenRepo: newMemUsedTokenRepo(), types: map[string]string{}}
	svc, r1 := newHigh04Service(t, used)
	spy := &reuseUserRepo{high04UserRepo: svc.userRepo.(*high04UserRepo)}
	audit := &countingAuditRepo{}
	svc.userRepo = spy
	svc.auditRepo = audit
	svc.refreshReuseMode = mode
	resp, err := svc.handleRefreshTokenGrant(context.Background(), refreshReq(r1), "test-client", "")
	if err != nil {
		t.Fatalf("first use: %v", err)
	}
	return svc, audit, spy, used, r1, resp.RefreshToken
}

func issueRefreshToken(t *testing.T, svc *oauthService) string {
	t.Helper()
	user := svc.userRepo.(*reuseUserRepo).user
	app := svc.appRepo.(*crit02AppRepo).app
	set, err := svc.tokenService.GenerateTokenSet(user, app, "user", "openid offline_access", nil, "", time.Now().Unix())
	if err != nil {
		t.Fatal(err)
	}
	return set.RefreshToken
}

func refreshClaims(t *testing.T, svc *oauthService, token string) *auth.RefreshTokenClaims {
	t.Helper()
	c, err := svc.tokenService.VerifyRefreshToken(token)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// legacyRefreshToken signs a refresh token without a family, as issued before
// #365.
func legacyRefreshToken(t *testing.T, svc *oauthService) string {
	t.Helper()
	now := time.Now()
	claims := auth.RefreshTokenClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    "https://auth.example.com",
			Subject:   "42",
			Audience:  jwt.ClaimStrings{"test-client"},
			IssuedAt:  jwt.NewNumericDate(now),
			NotBefore: jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(now.Add(time.Hour)),
			ID:        "legacy-refresh-jti",
		},
		Scope: "openid offline_access",
		Role:  "user",
		Type:  "refresh",
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = svc.keyManager.GetKeyID()
	signed, err := tok.SignedString(svc.keyManager.GetPrivateKey())
	if err != nil {
		t.Fatal(err)
	}
	return signed
}
