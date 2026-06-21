// Package service — tests for LOW-02 (max_age / ErrReauthRequired).
//
// LOW-02 fix: Authorize() now validates the OIDC Core §3.1.2.1 max_age
// parameter.  When max_age is present and the session age (time since
// user.LastLogin) exceeds it, Authorize() returns ErrReauthRequired rather
// than issuing a code that would silently extend a stale session.
package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ovandermoten/go-oauth2/internal/dto"
	"github.com/ovandermoten/go-oauth2/internal/model"
)

// ---------------------------------------------------------------------------
// LOW-02 helper — user with a specific last-login time
// ---------------------------------------------------------------------------

// userWithLastLogin builds a User with a specific LastLogin timestamp so we
// can control how "old" the session appears to Authorize().
func userWithLastLogin(id uint, loginAgo time.Duration) *model.User {
	t := time.Now().Add(-loginAgo)
	return &model.User{
		ID:           id,
		Email:        "test@example.com",
		TokenVersion: 1,
		LastLogin:    &t,
	}
}

// ---------------------------------------------------------------------------
// LOW-02: max_age = -1 (not specified) — no re-auth check performed
// ---------------------------------------------------------------------------

// TestLOW02_MaxAge_Negative1_SkipsCheck verifies that when MaxAge == -1
// (the "not specified" sentinel), Authorize() does not return ErrReauthRequired
// even if LastLogin is very old.
func TestLOW02_MaxAge_Negative1_SkipsCheck(t *testing.T) {
	user := userWithLastLogin(30, 24*time.Hour) // logged in 24h ago
	app := &model.App{
		ID:           30,
		ClientID:     "low02-app",
		RedirectURIs: model.StringArray{"https://app.example.com/cb"},
	}
	svc, _ := newMedSvc(t, newMemUsedTokenRepo(), app, user)

	req := dto.AuthorizeRequest{
		ResponseType: "code",
		ClientID:     "low02-app",
		RedirectURI:  "https://app.example.com/cb",
		Scope:        "openid",
		State:        "s1",
		MaxAge:       -1, // not specified — skip check
	}
	_, err := svc.Authorize(context.Background(), req, user.ID)
	if errors.Is(err, ErrReauthRequired) {
		t.Error("LOW-02: MaxAge=-1 should skip re-auth check, but ErrReauthRequired was returned")
	}
}

// ---------------------------------------------------------------------------
// LOW-02: session within max_age — should succeed
// ---------------------------------------------------------------------------

// TestLOW02_MaxAge_FreshSession_Succeeds verifies that a session whose age is
// strictly less than max_age is accepted without triggering ErrReauthRequired.
func TestLOW02_MaxAge_FreshSession_Succeeds(t *testing.T) {
	// Logged in 30 seconds ago; max_age = 300 seconds (5 minutes).
	user := userWithLastLogin(31, 30*time.Second)
	app := &model.App{
		ID:           31,
		ClientID:     "low02-fresh-app",
		RedirectURIs: model.StringArray{"https://app.example.com/cb"},
	}
	svc, _ := newMedSvc(t, newMemUsedTokenRepo(), app, user)

	req := dto.AuthorizeRequest{
		ResponseType: "code",
		ClientID:     "low02-fresh-app",
		RedirectURI:  "https://app.example.com/cb",
		Scope:        "openid",
		State:        "s2",
		MaxAge:       300, // 5 minutes — session is only 30s old, should pass
	}
	_, err := svc.Authorize(context.Background(), req, user.ID)
	if errors.Is(err, ErrReauthRequired) {
		t.Error("LOW-02: fresh session (30s) within max_age (300s) should not require re-auth")
	}
}

// ---------------------------------------------------------------------------
// LOW-02: session exceeds max_age — must return ErrReauthRequired
// ---------------------------------------------------------------------------

// TestLOW02_MaxAge_StaleSession_ReturnsErrReauthRequired verifies that a
// session older than max_age is rejected with ErrReauthRequired.
func TestLOW02_MaxAge_StaleSession_ReturnsErrReauthRequired(t *testing.T) {
	// Logged in 10 minutes ago; max_age = 60 seconds.
	user := userWithLastLogin(32, 10*time.Minute)
	app := &model.App{
		ID:           32,
		ClientID:     "low02-stale-app",
		RedirectURIs: model.StringArray{"https://app.example.com/cb"},
	}
	svc, _ := newMedSvc(t, newMemUsedTokenRepo(), app, user)

	req := dto.AuthorizeRequest{
		ResponseType: "code",
		ClientID:     "low02-stale-app",
		RedirectURI:  "https://app.example.com/cb",
		Scope:        "openid",
		State:        "s3",
		MaxAge:       60, // 1 minute — session is 10 minutes old, should fail
	}
	_, err := svc.Authorize(context.Background(), req, user.ID)
	if err == nil {
		t.Fatal("LOW-02: stale session (10m) beyond max_age (60s) should return ErrReauthRequired, got nil")
	}
	if !errors.Is(err, ErrReauthRequired) {
		t.Errorf("LOW-02: expected ErrReauthRequired, got: %v", err)
	}
}

// TestLOW02_MaxAge_Zero_AlwaysRequiresReauth verifies that max_age=0 forces
// re-authentication on every request (any non-zero session age fails).
func TestLOW02_MaxAge_Zero_AlwaysRequiresReauth(t *testing.T) {
	// Logged in 1 second ago — even a brand-new session should fail max_age=0.
	user := userWithLastLogin(33, 5*time.Second)
	app := &model.App{
		ID:           33,
		ClientID:     "low02-zero-app",
		RedirectURIs: model.StringArray{"https://app.example.com/cb"},
	}
	svc, _ := newMedSvc(t, newMemUsedTokenRepo(), app, user)

	req := dto.AuthorizeRequest{
		ResponseType: "code",
		ClientID:     "low02-zero-app",
		RedirectURI:  "https://app.example.com/cb",
		Scope:        "openid",
		State:        "s4",
		MaxAge:       0, // 0 = always require fresh authentication
	}
	_, err := svc.Authorize(context.Background(), req, user.ID)
	if err == nil {
		t.Fatal("LOW-02: max_age=0 should always require re-auth, but Authorize() succeeded")
	}
	if !errors.Is(err, ErrReauthRequired) {
		t.Errorf("LOW-02: expected ErrReauthRequired for max_age=0, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// LOW-02: nil LastLogin — check skipped (cannot enforce unknown auth time)
// ---------------------------------------------------------------------------

// TestLOW02_MaxAge_NilLastLogin_SkipsCheck verifies that when user.LastLogin
// is nil (new account with no recorded authentication), the max_age check is
// skipped and Authorize() proceeds normally.
func TestLOW02_MaxAge_NilLastLogin_SkipsCheck(t *testing.T) {
	user := &model.User{
		ID:           34,
		Email:        "newuser@example.com",
		TokenVersion: 1,
		LastLogin:    nil, // no recorded login time
	}
	app := &model.App{
		ID:           34,
		ClientID:     "low02-nil-app",
		RedirectURIs: model.StringArray{"https://app.example.com/cb"},
	}
	svc, _ := newMedSvc(t, newMemUsedTokenRepo(), app, user)

	req := dto.AuthorizeRequest{
		ResponseType: "code",
		ClientID:     "low02-nil-app",
		RedirectURI:  "https://app.example.com/cb",
		Scope:        "openid",
		State:        "s5",
		MaxAge:       0, // even max_age=0 should be skipped when LastLogin is nil
	}
	_, err := svc.Authorize(context.Background(), req, user.ID)
	if errors.Is(err, ErrReauthRequired) {
		t.Error("LOW-02: nil LastLogin should skip max_age check, but ErrReauthRequired was returned")
	}
}

// ---------------------------------------------------------------------------
// LOW-02: max_age exactly equal to session age (boundary condition)
// ---------------------------------------------------------------------------

// TestLOW02_MaxAge_ExactlyAtBoundary_Accepted verifies the boundary condition:
// a session age equal to max_age is accepted (sessionAge > maxAge, not >=).
func TestLOW02_MaxAge_ExactlyAtBoundary_Accepted(t *testing.T) {
	// Session is exactly 60 seconds old; max_age = 60.
	// The check is sessionAge > maxAge, so age=60 with maxAge=60 should pass.
	user := userWithLastLogin(35, 60*time.Second)
	app := &model.App{
		ID:           35,
		ClientID:     "low02-boundary-app",
		RedirectURIs: model.StringArray{"https://app.example.com/cb"},
	}
	svc, _ := newMedSvc(t, newMemUsedTokenRepo(), app, user)

	req := dto.AuthorizeRequest{
		ResponseType: "code",
		ClientID:     "low02-boundary-app",
		RedirectURI:  "https://app.example.com/cb",
		Scope:        "openid",
		State:        "s6",
		MaxAge:       60,
	}
	// Re-anchor LastLogin immediately before the call so the measured session
	// age is deterministically exactly 60s (== max_age). Anchoring at setup time
	// let elapsed test/setup time (δ) accumulate; under the slow -race CI runner
	// δ ≥ 1s pushed int(time.Since)=61, spuriously tripping ErrReauthRequired.
	// Bounding δ to the few fast in-memory ops before the check keeps it at 60,
	// which still exercises the boundary (sessionAge == max_age is accepted).
	boundary := time.Now().Add(-60 * time.Second)
	user.LastLogin = &boundary
	_, err := svc.Authorize(context.Background(), req, user.ID)
	// At exactly the boundary (age == maxAge), the session is still valid.
	if errors.Is(err, ErrReauthRequired) {
		t.Error("LOW-02: session age exactly equal to max_age should be accepted (> not >=)")
	}
}
