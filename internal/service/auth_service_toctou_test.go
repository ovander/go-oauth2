// Package service_test — black-box tests for the C-03 TOCTOU fix.
//
// Strategy: supply a real auth.TokenService (backed by in-memory RSA keys
// generated once in TestMain) so that real JWT tokens can be issued and
// verified.  The UsedTokenRepository is mocked to return ErrTokenAlreadyUsed
// on the first call, simulating a concurrent duplicate request.  The test then
// asserts that the service correctly propagates service.ErrTokenAlreadyUsed
// without performing any further state changes.
package service_test

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/ovandermoten/go-oauth2/internal/model"
	"github.com/ovandermoten/go-oauth2/internal/repository"
	"github.com/ovandermoten/go-oauth2/internal/service"
	"github.com/ovandermoten/go-oauth2/internal/shared/auth"
)

// ---------------------------------------------------------------------------
// Package-level test key manager / token service (generated once per run)
// ---------------------------------------------------------------------------

var (
	testTokenSvc *auth.TokenService
	testSetupOnce sync.Once
	testSetupErr  error
)

func testTokenService(t *testing.T) *auth.TokenService {
	t.Helper()
	testSetupOnce.Do(func() {
		dir, err := os.MkdirTemp("", "go-oauth2-test-keys-*")
		if err != nil {
			testSetupErr = err
			return
		}
		// We clean up in TestMain so temp keys persist for the duration of the
		// test binary but are removed afterward.
		km, err := auth.NewKeyManager(dir)
		if err != nil {
			testSetupErr = err
			return
		}
		testTokenSvc = auth.NewTokenService(km, auth.TokenConfig{
			Issuer:          "https://test.example.com",
			AccessTokenTTL:  15 * time.Minute,
			RefreshTokenTTL: 7 * 24 * time.Hour,
			EmailTokenTTL:   24 * time.Hour,
			ResetTokenTTL:   1 * time.Hour,
			InviteTokenTTL:  72 * time.Hour,
		})
	})
	if testSetupErr != nil {
		t.Fatalf("testTokenService: setup failed: %v", testSetupErr)
	}
	return testTokenSvc
}

// ---------------------------------------------------------------------------
// Mock repositories (panic on any method that should not be called)
// ---------------------------------------------------------------------------

// alreadyUsedTokenRepo always returns ErrTokenAlreadyUsed from MarkAsUsed,
// simulating the second (losing) request in a concurrent duplicate.
type alreadyUsedTokenRepo struct {
	markAsUsedCalled int
}

func (r *alreadyUsedTokenRepo) MarkAsUsed(_ context.Context, _, _ string, _ uint, _ time.Time) error {
	r.markAsUsedCalled++
	return repository.ErrTokenAlreadyUsed
}
func (r *alreadyUsedTokenRepo) IsUsed(_ context.Context, _ string) (bool, error) { return true, nil }
func (r *alreadyUsedTokenRepo) DeleteExpired(_ context.Context) (int64, error)    { return 0, nil }

// succeedOnceTokenRepo allows the first call and rejects the second —
// useful for testing concurrent behaviour in a single goroutine.
type succeedOnceTokenRepo struct {
	mu    sync.Mutex
	used  map[string]bool
}

func (r *succeedOnceTokenRepo) MarkAsUsed(_ context.Context, jti, _ string, _ uint, _ time.Time) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.used[jti] {
		return repository.ErrTokenAlreadyUsed
	}
	r.used[jti] = true
	return nil
}
func (r *succeedOnceTokenRepo) IsUsed(_ context.Context, jti string) (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.used[jti], nil
}
func (r *succeedOnceTokenRepo) DeleteExpired(_ context.Context) (int64, error) { return 0, nil }

// stubUserRepo returns a pre-configured user for FindByID; panics on other calls.
type stubUserRepo struct {
	user *model.User
}

func (r *stubUserRepo) FindByID(_ context.Context, _ uint) (*model.User, error) {
	if r.user != nil {
		return r.user, nil
	}
	return nil, errors.New("user not found")
}
func (r *stubUserRepo) FindByEmail(_ context.Context, _ string) (*model.User, error)      { panic("unexpected: FindByEmail") }
func (r *stubUserRepo) FindAll(_ context.Context, _, _ int) ([]model.User, int64, error)   { panic("unexpected: FindAll") }
func (r *stubUserRepo) FindByRole(_ context.Context, _ model.UserRole) ([]model.User, error) { panic("unexpected: FindByRole") }
func (r *stubUserRepo) CountByRole(_ context.Context, _ model.UserRole) (int64, error)     { panic("unexpected: CountByRole") }
func (r *stubUserRepo) Create(_ context.Context, _ *model.User) error                      { return nil }
func (r *stubUserRepo) Update(_ context.Context, _ *model.User) error                      { return nil }
func (r *stubUserRepo) Delete(_ context.Context, _ uint) error                             { panic("unexpected: Delete") }
func (r *stubUserRepo) IncrementTokenVersion(_ context.Context, _ uint) error              { panic("unexpected: IncrementTokenVersion") }
func (r *stubUserRepo) IncrementFailedLoginAttempts(_ context.Context, _ uint) error       { panic("unexpected: IncrementFailedLoginAttempts") }
func (r *stubUserRepo) ResetFailedLoginAttempts(_ context.Context, _ uint) error           { panic("unexpected: ResetFailedLoginAttempts") }
func (r *stubUserRepo) LockAccount(_ context.Context, _ uint, _ *time.Time) error          { panic("unexpected: LockAccount") }

// stubAppRepo returns a pre-configured app for FindByID; panics elsewhere.
type stubAppRepo struct {
	app *model.App
}

func (r *stubAppRepo) FindByID(_ context.Context, _ uint) (*model.App, error) {
	if r.app != nil {
		return r.app, nil
	}
	return nil, errors.New("app not found")
}
func (r *stubAppRepo) FindAll(_ context.Context) ([]model.App, error)                              { panic("unexpected: FindAll") }
func (r *stubAppRepo) FindByClientID(_ context.Context, _ string) (*model.App, error)              { panic("unexpected: FindByClientID") }
func (r *stubAppRepo) FindByOwnerID(_ context.Context, _ uint) ([]model.App, error)                { panic("unexpected: FindByOwnerID") }
func (r *stubAppRepo) Create(_ context.Context, _ *model.App) error                                { panic("unexpected: Create") }
func (r *stubAppRepo) Update(_ context.Context, _ *model.App) error                                { panic("unexpected: Update") }
func (r *stubAppRepo) Delete(_ context.Context, _ uint) error                                      { panic("unexpected: Delete") }
func (r *stubAppRepo) GetAllRedirectURIs(_ context.Context) ([]string, error)                      { panic("unexpected: GetAllRedirectURIs") }

// nilUserAppRoleRepo satisfies the interface without doing anything.
type nilUserAppRoleRepo struct{}

func (r *nilUserAppRoleRepo) FindByUserAndApp(_ context.Context, _, _ uint) (*model.UserAppRole, error) { return nil, errors.New("not found") }
func (r *nilUserAppRoleRepo) FindByUser(_ context.Context, _ uint) ([]model.UserAppRole, error)        { return nil, nil }
func (r *nilUserAppRoleRepo) FindByApp(_ context.Context, _ uint, _, _ int, _ string) ([]model.UserAppRole, int64, error) { return nil, 0, nil }
func (r *nilUserAppRoleRepo) FindAllByUser(_ context.Context, _ uint) ([]model.UserAppRole, error)     { return nil, nil }
func (r *nilUserAppRoleRepo) Create(_ context.Context, _ *model.UserAppRole) error                     { return nil }
func (r *nilUserAppRoleRepo) Update(_ context.Context, _ *model.UserAppRole) error                     { return nil }
func (r *nilUserAppRoleRepo) Delete(_ context.Context, _, _ uint) error                                { return nil }
func (r *nilUserAppRoleRepo) GetUserRolesMap(_ context.Context, _ uint) (map[string]string, error)     { return nil, nil }

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func newAuthServiceWithMockToken(t *testing.T, tokenRepo repository.UsedTokenRepository) service.AuthService {
	t.Helper()
	return service.NewAuthServiceWithUsedTokenRepo(
		&stubUserRepo{},
		&stubAppRepo{},
		&nilUserAppRoleRepo{},
		tokenRepo,
		testTokenService(t),
		service.AuthServiceConfig{MaxFailedAttempts: 5, LockoutDuration: 15 * time.Minute},
	)
}

// ---------------------------------------------------------------------------
// C-03: VerifyEmail — duplicate token returns ErrTokenAlreadyUsed
// ---------------------------------------------------------------------------

func TestVerifyEmail_FirstCall_Succeeds(t *testing.T) {
	// The first request to use a token must succeed (MarkAsUsed is called exactly
	// once and the user's verified flag is updated).
	ts := testTokenService(t)
	tokenRepo := &succeedOnceTokenRepo{used: map[string]bool{}}

	// User to be returned when the service looks up the ID from the token subject.
	user := &model.User{
		ID:         42,
		Email:      "alice@example.com",
		IsVerified: false,
	}
	svc := service.NewAuthServiceWithUsedTokenRepo(
		&stubUserRepo{user: user},
		&stubAppRepo{},
		&nilUserAppRoleRepo{},
		tokenRepo,
		ts,
		service.AuthServiceConfig{MaxFailedAttempts: 5},
	)

	tokenStr, err := ts.GenerateEmailVerificationToken("alice@example.com", 42, nil)
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	if err := svc.VerifyEmail(context.Background(), tokenStr); err != nil {
		t.Errorf("first VerifyEmail call failed: %v (want nil)", err)
	}
}

func TestVerifyEmail_SecondCall_ErrTokenAlreadyUsed(t *testing.T) {
	// C-03 core: the second call with the same token must be rejected atomically.
	ts := testTokenService(t)
	tokenRepo := &alreadyUsedTokenRepo{}
	svc := newAuthServiceWithMockToken(t, tokenRepo)

	tokenStr, err := ts.GenerateEmailVerificationToken("alice@example.com", 42, nil)
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	err = svc.VerifyEmail(context.Background(), tokenStr)
	if !errors.Is(err, service.ErrTokenAlreadyUsed) {
		t.Errorf("VerifyEmail returned %v, want %v", err, service.ErrTokenAlreadyUsed)
	}
}

func TestVerifyEmail_MarkAsUsed_CalledBeforeUserLookup(t *testing.T) {
	// The TOCTOU fix requires MarkAsUsed to be called BEFORE any state-changing
	// operations.  We verify this by having MarkAsUsed fail and confirming that
	// the user's state was NOT accessed.
	ts := testTokenService(t)

	callOrder := []string{}
	trackingUserRepo := &callTrackingUserRepo{
		order: &callOrder,
		user:  &model.User{ID: 42, Email: "bob@example.com"},
	}
	trackingTokenRepo := &callTrackingTokenRepo{
		order: &callOrder,
		err:   repository.ErrTokenAlreadyUsed,
	}

	svc := service.NewAuthServiceWithUsedTokenRepo(
		trackingUserRepo,
		&stubAppRepo{},
		&nilUserAppRoleRepo{},
		trackingTokenRepo,
		ts,
		service.AuthServiceConfig{MaxFailedAttempts: 5},
	)

	tokenStr, _ := ts.GenerateEmailVerificationToken("bob@example.com", 42, nil)
	_ = svc.VerifyEmail(context.Background(), tokenStr)

	// MarkAsUsed must appear before any FindByID call.
	for i, call := range callOrder {
		if call == "FindByID" {
			t.Errorf("FindByID (position %d) was called even though MarkAsUsed returned ErrTokenAlreadyUsed; call order: %v", i, callOrder)
			break
		}
	}
}

// callTrackingUserRepo records the order in which FindByID is called.
type callTrackingUserRepo struct {
	order *[]string
	user  *model.User
}
func (r *callTrackingUserRepo) FindByID(_ context.Context, _ uint) (*model.User, error) {
	*r.order = append(*r.order, "FindByID")
	return r.user, nil
}
func (r *callTrackingUserRepo) FindByEmail(_ context.Context, _ string) (*model.User, error)      { return nil, nil }
func (r *callTrackingUserRepo) FindAll(_ context.Context, _, _ int) ([]model.User, int64, error)   { return nil, 0, nil }
func (r *callTrackingUserRepo) FindByRole(_ context.Context, _ model.UserRole) ([]model.User, error) { return nil, nil }
func (r *callTrackingUserRepo) CountByRole(_ context.Context, _ model.UserRole) (int64, error)     { return 0, nil }
func (r *callTrackingUserRepo) Create(_ context.Context, _ *model.User) error                      { return nil }
func (r *callTrackingUserRepo) Update(_ context.Context, _ *model.User) error                      { return nil }
func (r *callTrackingUserRepo) Delete(_ context.Context, _ uint) error                             { return nil }
func (r *callTrackingUserRepo) IncrementTokenVersion(_ context.Context, _ uint) error              { return nil }
func (r *callTrackingUserRepo) IncrementFailedLoginAttempts(_ context.Context, _ uint) error       { return nil }
func (r *callTrackingUserRepo) ResetFailedLoginAttempts(_ context.Context, _ uint) error           { return nil }
func (r *callTrackingUserRepo) LockAccount(_ context.Context, _ uint, _ *time.Time) error          { return nil }

// callTrackingTokenRepo records MarkAsUsed calls and returns a configured error.
type callTrackingTokenRepo struct {
	order *[]string
	err   error
}
func (r *callTrackingTokenRepo) MarkAsUsed(_ context.Context, _, _ string, _ uint, _ time.Time) error {
	*r.order = append(*r.order, "MarkAsUsed")
	return r.err
}
func (r *callTrackingTokenRepo) IsUsed(_ context.Context, _ string) (bool, error) { return false, nil }
func (r *callTrackingTokenRepo) DeleteExpired(_ context.Context) (int64, error)    { return 0, nil }

// ---------------------------------------------------------------------------
// C-03: ResetPassword — duplicate token returns ErrTokenAlreadyUsed
// ---------------------------------------------------------------------------

func TestResetPassword_SecondCall_ErrTokenAlreadyUsed(t *testing.T) {
	ts := testTokenService(t)
	tokenRepo := &alreadyUsedTokenRepo{}
	svc := newAuthServiceWithMockToken(t, tokenRepo)

	tokenStr, err := ts.GeneratePasswordResetToken("charlie@example.com", 7, nil)
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	err = svc.ResetPassword(context.Background(), tokenStr, "NewSecure@Pass123")
	if !errors.Is(err, service.ErrTokenAlreadyUsed) {
		t.Errorf("ResetPassword returned %v, want %v", err, service.ErrTokenAlreadyUsed)
	}
}

func TestResetPassword_MarkAsUsed_CalledOnce(t *testing.T) {
	// Verify MarkAsUsed is called exactly once per ResetPassword invocation.
	ts := testTokenService(t)
	repo := &alreadyUsedTokenRepo{}
	svc := newAuthServiceWithMockToken(t, repo)

	tokenStr, _ := ts.GeneratePasswordResetToken("dave@example.com", 8, nil)
	_ = svc.ResetPassword(context.Background(), tokenStr, "NewSecure@Pass123")

	if repo.markAsUsedCalled != 1 {
		t.Errorf("MarkAsUsed called %d times, want 1", repo.markAsUsedCalled)
	}
}

// ---------------------------------------------------------------------------
// C-03: AcceptInvite — duplicate token returns ErrTokenAlreadyUsed
// ---------------------------------------------------------------------------

func TestAcceptInvite_SecondCall_ErrTokenAlreadyUsed(t *testing.T) {
	ts := testTokenService(t)
	tokenRepo := &alreadyUsedTokenRepo{}
	svc := service.NewAuthServiceWithUsedTokenRepo(
		&stubUserRepo{},
		&stubAppRepo{app: &model.App{ID: 1, Name: "Test App", ClientID: "test"}},
		&nilUserAppRoleRepo{},
		tokenRepo,
		ts,
		service.AuthServiceConfig{MaxFailedAttempts: 5},
	)

	tokenStr, err := ts.GenerateInviteToken("eve@example.com", 1, "user", 99)
	if err != nil {
		t.Fatalf("failed to generate invite token: %v", err)
	}

	_, err = svc.AcceptInvite(context.Background(), tokenStr, "Eve Smith", "Secure@Pass123!")
	if !errors.Is(err, service.ErrTokenAlreadyUsed) {
		t.Errorf("AcceptInvite returned %v, want %v", err, service.ErrTokenAlreadyUsed)
	}
}

// ---------------------------------------------------------------------------
// C-03: Concurrency — two goroutines, only one wins
// ---------------------------------------------------------------------------

func TestVerifyEmail_ConcurrentCalls_OnlyOneSucceeds(t *testing.T) {
	// Simulate two goroutines racing to use the same token.
	// succeedOnceTokenRepo serializes them: exactly one must succeed and the
	// other must receive ErrTokenAlreadyUsed.
	ts := testTokenService(t)
	tokenRepo := &succeedOnceTokenRepo{used: map[string]bool{}}
	user := &model.User{ID: 55, Email: "frank@example.com", IsVerified: false}
	svc := service.NewAuthServiceWithUsedTokenRepo(
		&stubUserRepo{user: user},
		&stubAppRepo{},
		&nilUserAppRoleRepo{},
		tokenRepo,
		ts,
		service.AuthServiceConfig{MaxFailedAttempts: 5},
	)

	tokenStr, err := ts.GenerateEmailVerificationToken("frank@example.com", 55, nil)
	if err != nil {
		t.Fatalf("failed to generate token: %v", err)
	}

	type result struct{ err error }
	results := make(chan result, 2)

	for i := 0; i < 2; i++ {
		go func() {
			results <- result{err: svc.VerifyEmail(context.Background(), tokenStr)}
		}()
	}

	r1 := <-results
	r2 := <-results

	// Exactly one call must succeed and exactly one must return ErrTokenAlreadyUsed.
	errs := []error{r1.err, r2.err}
	successCount := 0
	alreadyUsedCount := 0
	for _, err := range errs {
		if err == nil {
			successCount++
		} else if errors.Is(err, service.ErrTokenAlreadyUsed) {
			alreadyUsedCount++
		} else {
			t.Errorf("unexpected error: %v", err)
		}
	}

	if successCount != 1 {
		t.Errorf("expected exactly 1 success, got %d", successCount)
	}
	if alreadyUsedCount != 1 {
		t.Errorf("expected exactly 1 ErrTokenAlreadyUsed, got %d", alreadyUsedCount)
	}
}
