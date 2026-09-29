// Package service — tests for refresh-token reuse detection (RFC 9700 §4.14.2).
//
// A reused (already-rotated) single-use refresh token is always rejected
// (HIGH-04). When REFRESH_REUSE_MODE is "observe" the reuse is additionally
// audited; when "enforce" the user's token family is also revoked, since reuse
// signals token theft.
package service

import (
	"context"
	"errors"
	"testing"

	"github.com/ovander/go-oauth2/internal/model"
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

// Enforce: a reused token is rejected, audited, and the family is revoked.
func TestRefreshReuse_EnforceRevokesFamily(t *testing.T) {
	svc, audit, spy, token := newReuseService(t, refreshReuseModeEnforce)

	if _, err := svc.handleRefreshTokenGrant(context.Background(), refreshReq(token), "test-client", ""); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("reuse must be rejected, got %v", err)
	}
	if audit.last == nil || audit.last.EventType != model.SecurityEventRefreshTokenReuse {
		t.Fatalf("enforce must audit a refresh_token_reuse event, got %+v", audit.last)
	}
	if spy.incremented != 1 {
		t.Errorf("enforce must revoke the token family exactly once, got %d increments", spy.incremented)
	}
	if audit.last.Details["family_revoked"] != true {
		t.Errorf("enforce must record family_revoked, got %v", audit.last.Details["family_revoked"])
	}
}
