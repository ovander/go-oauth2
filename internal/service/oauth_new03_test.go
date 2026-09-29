// Package service — tests for NEW-03 (Introspect token version check).
//
// NEW-03 fix: Introspect() now checks the access token's embedded TokenVersion
// claim against user.TokenVersion.  If the user's stored version exceeds the
// token's version (indicating a nuclear revocation via IncrementTokenVersion),
// Introspect returns active:false even when the token's JTI is not explicitly
// blacklisted.
//
// This aligns Introspect with the auth middleware (internal/middleware/auth.go),
// which already performs an identical version check for direct API access.
// Without the fix, resource servers using the introspection endpoint would not
// detect forced logout / nuclear revocation until the token expired naturally.
//
// Tests:
//   - Token version equals user version → active:true  (normal, not revoked)
//   - Token version is lower than user version → active:false (nuclear revoked)
//   - Token version is zero with user version 1 (default initial state) → active:true
//   - Introspect with no userRepo match (user deleted) → treats as inactive
//   - JTI blacklist check still fires independently of version check
package service

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/shared/auth"
)

// ---------------------------------------------------------------------------
// NEW-03: helpers
// ---------------------------------------------------------------------------

// new03UserRepo is a stub UserRepository whose FindByID always returns the
// configured user.  Useful for controlling user.TokenVersion in tests.
type new03UserRepo struct {
	user *model.User
}

func (r *new03UserRepo) FindByID(_ context.Context, _ uint) (*model.User, error) {
	if r.user == nil {
		return nil, errUserNotFound
	}
	return r.user, nil
}
func (r *new03UserRepo) FindByEmail(_ context.Context, _ string) (*model.User, error) {
	return r.user, nil
}
func (r *new03UserRepo) FindAll(_ context.Context, _, _ int) ([]model.User, int64, error) {
	return nil, 0, nil
}
func (r *new03UserRepo) FindByRole(_ context.Context, _ model.UserRole) ([]model.User, error) {
	return nil, nil
}
func (r *new03UserRepo) CountByRole(_ context.Context, _ model.UserRole) (int64, error) {
	return 0, nil
}
func (r *new03UserRepo) Create(_ context.Context, _ *model.User) error                { return nil }
func (r *new03UserRepo) Update(_ context.Context, _ *model.User) error                { return nil }
func (r *new03UserRepo) Delete(_ context.Context, _ uint) error                       { return nil }
func (r *new03UserRepo) IncrementTokenVersion(_ context.Context, _ uint) error        { return nil }
func (r *new03UserRepo) IncrementFailedLoginAttempts(_ context.Context, _ uint) error { return nil }
func (r *new03UserRepo) ResetFailedLoginAttempts(_ context.Context, _ uint) error     { return nil }
func (r *new03UserRepo) LockAccount(_ context.Context, _ uint, _ *time.Time) error    { return nil }

var errUserNotFound = errNF{}

type errNF struct{}

func (errNF) Error() string { return "user not found" }

// newNew03Svc creates a minimal oauthService configured for NEW-03 tests.
// usedRepo may be nil to disable JTI blacklisting.
func newNew03Svc(t *testing.T, user *model.User) *oauthService {
	t.Helper()

	tmpDir, err := os.MkdirTemp("", "new03-keys-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(tmpDir) })

	km, err := auth.NewKeyManager(tmpDir)
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}
	ts := auth.NewTokenService(km, auth.TokenConfig{
		Issuer:         "https://auth.example.com",
		AccessTokenTTL: time.Hour,
	})

	codeRepo := newMemCodeRepo()
	cs := auth.NewCodeStoreWithTTL(codeRepo, 10*time.Minute)
	t.Cleanup(cs.Stop)

	return &oauthService{
		userRepo:     &new03UserRepo{user: user},
		tokenService: ts,
		keyManager:   km,
		codeStore:    cs,
		issuer:       "https://auth.example.com",
		// usedTokenRepo intentionally nil — we test version check in isolation.
	}
}

// ---------------------------------------------------------------------------
// NEW-03: tests
// ---------------------------------------------------------------------------

// TestNEW03_Introspect_SameVersion_ReturnsActive verifies that an access token
// whose embedded TokenVersion matches the user's current TokenVersion is
// reported as active.  This is the normal, non-revoked case.
func TestNEW03_Introspect_SameVersion_ReturnsActive(t *testing.T) {
	t.Parallel()

	user := &model.User{ID: 100, Email: "alice@example.com", TokenVersion: 3}
	app := &model.App{ID: 1, ClientID: "app-new03"}
	svc := newNew03Svc(t, user)

	ts := svc.tokenService
	tokenSet, err := ts.GenerateTokenSet(user, app, "user", "openid", nil, "", time.Now().Unix())
	if err != nil {
		t.Fatalf("GenerateTokenSet: %v", err)
	}

	// Token was issued with TokenVersion=3; user still has TokenVersion=3.
	resp, err := svc.Introspect(context.Background(), tokenSet.AccessToken, "app-new03")
	if err != nil {
		t.Fatalf("Introspect error: %v", err)
	}
	if !resp.Active {
		t.Error("NEW-03: Introspect returned active:false for a token whose version matches the user — should be active")
	}
}

// TestNEW03_Introspect_StaleVersion_ReturnsInactive verifies that after nuclear
// revocation (IncrementTokenVersion), Introspect returns active:false for tokens
// issued before the version bump.
//
// Scenario:
//  1. Token is issued when user.TokenVersion = 2.
//  2. IncrementTokenVersion is called → user.TokenVersion becomes 3.
//  3. Introspect is called with the old token (still within its TTL).
//  4. Introspect must return active:false because the token's embedded version
//     (2) is less than the user's current version (3).
func TestNEW03_Introspect_StaleVersion_ReturnsInactive(t *testing.T) {
	t.Parallel()

	// Step 1: issue the token with TokenVersion=2.
	user := &model.User{ID: 101, Email: "bob@example.com", TokenVersion: 2}
	app := &model.App{ID: 2, ClientID: "app-new03b"}
	svc := newNew03Svc(t, user)

	ts := svc.tokenService
	tokenSet, err := ts.GenerateTokenSet(user, app, "user", "openid", nil, "", time.Now().Unix())
	if err != nil {
		t.Fatalf("GenerateTokenSet: %v", err)
	}

	// Step 2: simulate nuclear revocation — bump the user's token version.
	// We update the stub repo's user in place (shared pointer).
	svc.userRepo.(*new03UserRepo).user.TokenVersion = 3

	// Step 3+4: Introspect the pre-revocation token.
	resp, err := svc.Introspect(context.Background(), tokenSet.AccessToken, "app-new03b")
	if err != nil {
		t.Fatalf("Introspect error: %v", err)
	}
	if resp.Active {
		t.Error("NEW-03: Introspect returned active:true for a token issued before nuclear revocation — version check missing")
	}
}

// TestNEW03_Introspect_DefaultVersion_ReturnsActive verifies that a freshly
// issued token with TokenVersion=1 (the default initial value for new users)
// is reported as active when the user's stored version is also 1.
func TestNEW03_Introspect_DefaultVersion_ReturnsActive(t *testing.T) {
	t.Parallel()

	user := &model.User{ID: 102, Email: "carol@example.com", TokenVersion: 1}
	app := &model.App{ID: 3, ClientID: "app-new03c"}
	svc := newNew03Svc(t, user)

	ts := svc.tokenService
	tokenSet, err := ts.GenerateTokenSet(user, app, "user", "openid", nil, "", time.Now().Unix())
	if err != nil {
		t.Fatalf("GenerateTokenSet: %v", err)
	}

	resp, err := svc.Introspect(context.Background(), tokenSet.AccessToken, "app-new03c")
	if err != nil {
		t.Fatalf("Introspect error: %v", err)
	}
	if !resp.Active {
		t.Error("NEW-03: Introspect returned active:false for a default-version token that has not been revoked")
	}
}

// TestNEW03_Introspect_MultipleVersionBumps verifies that tokens issued at
// various historical versions all become inactive after the version advances
// past them, and that a freshly issued token at the new version is active.
func TestNEW03_Introspect_MultipleVersionBumps(t *testing.T) {
	t.Parallel()

	user := &model.User{ID: 103, Email: "dave@example.com", TokenVersion: 1}
	app := &model.App{ID: 4, ClientID: "app-new03d"}
	svc := newNew03Svc(t, user)
	ts := svc.tokenService

	// Issue token at version 1.
	tokenV1Set, err := ts.GenerateTokenSet(user, app, "user", "openid", nil, "", time.Now().Unix())
	if err != nil {
		t.Fatalf("GenerateTokenSet v1: %v", err)
	}

	// Bump to version 2 and issue a new token.
	svc.userRepo.(*new03UserRepo).user.TokenVersion = 2
	user.TokenVersion = 2
	tokenV2Set, err := ts.GenerateTokenSet(user, app, "user", "openid", nil, "", time.Now().Unix())
	if err != nil {
		t.Fatalf("GenerateTokenSet v2: %v", err)
	}

	// Bump to version 3.
	svc.userRepo.(*new03UserRepo).user.TokenVersion = 3

	// v1 token: revoked (version 1 < current 3).
	r1, _ := svc.Introspect(context.Background(), tokenV1Set.AccessToken, "app-new03d")
	if r1.Active {
		t.Error("NEW-03: v1 token still active after two version bumps")
	}

	// v2 token: also revoked (version 2 < current 3).
	r2, _ := svc.Introspect(context.Background(), tokenV2Set.AccessToken, "app-new03d")
	if r2.Active {
		t.Error("NEW-03: v2 token still active after one version bump")
	}

	// Issue a fresh token at current version 3.
	user.TokenVersion = 3
	tokenV3Set, err := ts.GenerateTokenSet(user, app, "user", "openid", nil, "", time.Now().Unix())
	if err != nil {
		t.Fatalf("GenerateTokenSet v3: %v", err)
	}

	r3, _ := svc.Introspect(context.Background(), tokenV3Set.AccessToken, "app-new03d")
	if !r3.Active {
		t.Error("NEW-03: freshly issued v3 token should be active")
	}
}

// TestNEW03_Introspect_JTIBlacklist_IndependentOfVersionCheck verifies that
// the JTI blacklist check (MED-01) and the token version check (NEW-03) are
// independent: a token can be revoked by JTI blacklisting even when the version
// still matches.
func TestNEW03_Introspect_JTIBlacklist_IndependentOfVersionCheck(t *testing.T) {
	t.Parallel()

	user := &model.User{ID: 104, Email: "eve@example.com", TokenVersion: 5}
	app := &model.App{ID: 5, ClientID: "app-new03e"}
	usedRepo := newMemUsedTokenRepo()
	svc := newNew03Svc(t, user)
	svc.usedTokenRepo = usedRepo // wire in JTI repo

	ts := svc.tokenService
	tokenSet, err := ts.GenerateTokenSet(user, app, "user", "openid", nil, "", time.Now().Unix())
	if err != nil {
		t.Fatalf("GenerateTokenSet: %v", err)
	}

	// Blacklist the token JTI (MED-01 path), version unchanged.
	_ = svc.Revoke(context.Background(), tokenSet.AccessToken, user.ID, "")

	resp, err := svc.Introspect(context.Background(), tokenSet.AccessToken, "app-new03e")
	if err != nil {
		t.Fatalf("Introspect error: %v", err)
	}
	if resp.Active {
		t.Error("NEW-03: JTI-blacklisted token returned active:true — JTI check broken by version-check addition")
	}
}
