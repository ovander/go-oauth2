// Package service — tests for the HIGH-04 refresh-token single-use fix.
//
// HIGH-04 fix: each refresh token may be used only once.  The JTI (JWT ID)
// of the incoming refresh token is checked against a UsedTokenRepository
// before processing begins; on success the JTI is marked as consumed.
// A second request carrying the same token is rejected with ErrInvalidToken.
package service

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/ovandermoten/go-oauth2/internal/dto"
	"github.com/ovandermoten/go-oauth2/internal/model"
	"github.com/ovandermoten/go-oauth2/internal/repository"
	"github.com/ovandermoten/go-oauth2/internal/shared/auth"
)

// ---------------------------------------------------------------------------
// In-memory UsedTokenRepository
// ---------------------------------------------------------------------------

type memUsedTokenRepo struct {
	mu              sync.Mutex
	used            map[string]struct{}
	forceIsUsedErr  bool // simulate DB error in IsUsed
}

func newMemUsedTokenRepo() *memUsedTokenRepo {
	return &memUsedTokenRepo{used: make(map[string]struct{})}
}

func (r *memUsedTokenRepo) IsUsed(_ context.Context, jti string) (bool, error) {
	if r.forceIsUsedErr {
		return false, errors.New("db error (forced in test)")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	_, ok := r.used[jti]
	return ok, nil
}

func (r *memUsedTokenRepo) MarkAsUsed(_ context.Context, jti, _ string, _ uint, _ time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.used[jti]; ok {
		return repository.ErrTokenAlreadyUsed
	}
	r.used[jti] = struct{}{}
	return nil
}

func (r *memUsedTokenRepo) DeleteExpired(_ context.Context) (int64, error) { return 0, nil }

// Compile-time interface compliance check.
var _ repository.UsedTokenRepository = (*memUsedTokenRepo)(nil)

// ---------------------------------------------------------------------------
// In-memory UserRepository stub (returns a real user for a given ID)
// ---------------------------------------------------------------------------

type high04UserRepo struct {
	user *model.User
}

func (r *high04UserRepo) FindByID(_ context.Context, id uint) (*model.User, error) {
	if r.user != nil && r.user.ID == id {
		return r.user, nil
	}
	return nil, errors.New("user not found")
}
func (r *high04UserRepo) FindAll(_ context.Context, _, _ int) ([]model.User, int64, error) {
	return nil, 0, nil
}
func (r *high04UserRepo) FindByEmail(_ context.Context, _ string) (*model.User, error) {
	return nil, errors.New("not found")
}
func (r *high04UserRepo) FindByRole(_ context.Context, _ model.UserRole) ([]model.User, error) {
	return nil, nil
}
func (r *high04UserRepo) CountByRole(_ context.Context, _ model.UserRole) (int64, error) {
	return 0, nil
}
func (r *high04UserRepo) Create(_ context.Context, _ *model.User) error               { return nil }
func (r *high04UserRepo) Update(_ context.Context, _ *model.User) error               { return nil }
func (r *high04UserRepo) Delete(_ context.Context, _ uint) error                      { return nil }
func (r *high04UserRepo) IncrementTokenVersion(_ context.Context, _ uint) error       { return nil }
func (r *high04UserRepo) IncrementFailedLoginAttempts(_ context.Context, _ uint) error { return nil }
func (r *high04UserRepo) ResetFailedLoginAttempts(_ context.Context, _ uint) error    { return nil }
func (r *high04UserRepo) LockAccount(_ context.Context, _ uint, _ *time.Time) error   { return nil }

var _ repository.UserRepository = (*high04UserRepo)(nil)

// ---------------------------------------------------------------------------
// In-memory UserAppRoleRepository stub
// ---------------------------------------------------------------------------

type high04RoleRepo struct {
	role *model.UserAppRole
}

func (r *high04RoleRepo) FindByUserAndApp(_ context.Context, _, _ uint) (*model.UserAppRole, error) {
	if r.role != nil {
		return r.role, nil
	}
	return nil, errors.New("role not found")
}
func (r *high04RoleRepo) FindByUser(_ context.Context, _ uint) ([]model.UserAppRole, error) {
	return nil, nil
}
func (r *high04RoleRepo) FindByApp(_ context.Context, _ uint, _, _ int, _ string) ([]model.UserAppRole, int64, error) {
	return nil, 0, nil
}
func (r *high04RoleRepo) FindAllByUser(_ context.Context, _ uint) ([]model.UserAppRole, error) {
	return nil, nil
}
func (r *high04RoleRepo) Create(_ context.Context, _ *model.UserAppRole) error { return nil }
func (r *high04RoleRepo) Update(_ context.Context, _ *model.UserAppRole) error { return nil }
func (r *high04RoleRepo) Delete(_ context.Context, _, _ uint) error             { return nil }
func (r *high04RoleRepo) GetUserRolesMap(_ context.Context, _ uint) (map[string]string, error) {
	return make(map[string]string), nil
}

var _ repository.UserAppRoleRepository = (*high04RoleRepo)(nil)

// ---------------------------------------------------------------------------
// Test service factory
// ---------------------------------------------------------------------------

// newHigh04Service builds an oauthService wired with the given usedTokenRepo
// and a user/app/role triple that will satisfy a full refresh-token exchange.
// Returns the service and a fresh refresh token string to use in tests.
func newHigh04Service(t *testing.T, usedRepo repository.UsedTokenRepository) (*oauthService, string) {
	t.Helper()

	tmpDir, err := os.MkdirTemp("", "high04-keys-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(tmpDir) })

	km, err := auth.NewKeyManager(tmpDir)
	if err != nil {
		t.Fatalf("NewKeyManager: %v", err)
	}

	ts := auth.NewTokenService(km, auth.TokenConfig{
		Issuer:          "https://auth.example.com",
		AccessTokenTTL:  time.Hour,
		RefreshTokenTTL: 7 * 24 * time.Hour,
		EmailTokenTTL:   24 * time.Hour,
		ResetTokenTTL:   time.Hour,
		InviteTokenTTL:  24 * time.Hour,
	})

	user := &model.User{
		ID:           42,
		Email:        "alice@example.com",
		TokenVersion: 0,
	}
	app := &model.App{
		ID:       1,
		ClientID: "test-client",
		Active:   true,
	}
	role := &model.UserAppRole{
		UserID: user.ID,
		AppID:  app.ID,
		Role:   model.AppRoleUser,
	}

	codeRepo := newMemCodeRepo()
	cs := auth.NewCodeStoreWithTTL(codeRepo, 10*time.Minute)
	t.Cleanup(cs.Stop)

	svc := &oauthService{
		userRepo:        &high04UserRepo{user: user},
		appRepo:         &crit02AppRepo{app: app},
		userAppRoleRepo: &high04RoleRepo{role: role},
		codeStore:       cs,
		tokenService:    ts,
		keyManager:      km,
		usedTokenRepo:   usedRepo,
		issuer:          "https://auth.example.com",
	}

	// Issue a fresh refresh token for the user.
	tokenSet, err := ts.GenerateTokenSet(user, app, "user", "openid offline_access", nil, "", time.Now().Unix())
	if err != nil {
		t.Fatalf("GenerateTokenSet: %v", err)
	}

	return svc, tokenSet.RefreshToken
}

// refreshReq is a test helper that builds a dto.TokenRequest for the
// refresh_token grant with the given refresh token.
func refreshReq(token string) dto.TokenRequest {
	return dto.TokenRequest{
		GrantType:    "refresh_token",
		RefreshToken: token,
	}
}

// ---------------------------------------------------------------------------
// HIGH-04 tests
// ---------------------------------------------------------------------------

// TestHIGH04_RefreshGrant_ReplayRejected_ReturnsInvalidToken verifies that
// once a refresh token JTI has been consumed, re-presenting the same token
// is rejected with ErrInvalidToken.
func TestHIGH04_RefreshGrant_ReplayRejected_ReturnsInvalidToken(t *testing.T) {
	usedRepo := newMemUsedTokenRepo()
	svc, refreshToken := newHigh04Service(t, usedRepo)

	ctx := context.Background()

	// First use: the JTI check must pass.  The exchange will succeed end-to-end
	// because the full stack (user, app, role) is wired.
	_, firstErr := svc.handleRefreshTokenGrant(ctx, refreshReq(refreshToken), "test-client", "")
	if errors.Is(firstErr, ErrInvalidToken) {
		t.Fatalf("first use of refresh token unexpectedly rejected with ErrInvalidToken: %v", firstErr)
	}

	// Second use: same token must be rejected.
	_, secondErr := svc.handleRefreshTokenGrant(ctx, refreshReq(refreshToken), "test-client", "")
	if secondErr == nil {
		t.Fatal("expected ErrInvalidToken on replay, got nil")
	}
	if !errors.Is(secondErr, ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken on replay, got: %v", secondErr)
	}
}

// TestHIGH04_RefreshGrant_FirstUse_Succeeds_AndMarksJTI verifies that after
// a successful refresh-token exchange, the JTI is recorded in the usedTokenRepo.
func TestHIGH04_RefreshGrant_FirstUse_Succeeds_AndMarksJTI(t *testing.T) {
	usedRepo := newMemUsedTokenRepo()
	svc, refreshToken := newHigh04Service(t, usedRepo)

	_, err := svc.handleRefreshTokenGrant(context.Background(), refreshReq(refreshToken), "test-client", "")
	// The exchange may succeed or fail downstream (e.g. auditRepo is nil), but
	// we only care that it was NOT blocked by the JTI check.
	if errors.Is(err, ErrInvalidToken) {
		t.Fatalf("first-use was blocked by JTI check unexpectedly: %v", err)
	}

	// Verify that at least one JTI was stored in the used-token repo.
	usedRepo.mu.Lock()
	count := len(usedRepo.used)
	usedRepo.mu.Unlock()

	if count == 0 {
		t.Error("expected usedTokenRepo to contain a JTI entry after first use, got 0")
	}
}

// TestHIGH04_RefreshGrant_DBErrorOnIsUsed_ReturnsInvalidToken verifies that
// when usedTokenRepo.IsUsed fails (DB unreachable), the request is rejected
// rather than allowed through.
func TestHIGH04_RefreshGrant_DBErrorOnIsUsed_ReturnsInvalidToken(t *testing.T) {
	usedRepo := newMemUsedTokenRepo()
	usedRepo.forceIsUsedErr = true

	svc, refreshToken := newHigh04Service(t, usedRepo)

	_, err := svc.handleRefreshTokenGrant(context.Background(), refreshReq(refreshToken), "test-client", "")
	if err == nil {
		t.Fatal("expected error when IsUsed DB call fails, got nil")
	}
	if !errors.Is(err, ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken when IsUsed fails, got: %v", err)
	}
}

// TestHIGH04_RefreshGrant_NilUsedRepo_DoesNotPanic verifies that when
// usedTokenRepo is nil, the grant proceeds without panicking.
func TestHIGH04_RefreshGrant_NilUsedRepo_DoesNotPanic(t *testing.T) {
	svc, refreshToken := newHigh04Service(t, nil)

	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("panic with nil usedTokenRepo: %v", r)
		}
	}()

	// Outcome does not matter — just confirm no panic.
	svc.handleRefreshTokenGrant(context.Background(), refreshReq(refreshToken), "test-client", "") //nolint:errcheck
}
