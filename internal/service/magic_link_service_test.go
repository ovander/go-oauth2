package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ovander/go-oauth2/internal/dto"
	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/repository"
	"github.com/ovander/go-oauth2/internal/shared/auth"
)

// t_tempDir is a stand-in for t.TempDir() that works in non-test functions.
// We use it in buildMagicLinkService which accepts *testing.T.
func t_tempDir(t *testing.T) string {
	return t.TempDir()
}

// ---------------------------------------------------------------------------
// Minimal in-memory fakes
// ---------------------------------------------------------------------------

// fakeMagicLinkRepo is a thread-unsafe in-memory MagicLinkRepository for tests.
type fakeMagicLinkRepo struct {
	tokens  map[string]*model.MagicLinkToken
	nextID  uint
	usedErr error // if set, MarkUsed returns this error
}

func newFakeMagicLinkRepo() *fakeMagicLinkRepo {
	return &fakeMagicLinkRepo{tokens: make(map[string]*model.MagicLinkToken), nextID: 1}
}

func (r *fakeMagicLinkRepo) Create(_ context.Context, t *model.MagicLinkToken) error {
	t.ID = r.nextID
	r.nextID++
	t.CreatedAt = time.Now()
	cp := *t
	r.tokens[t.TokenHash] = &cp
	return nil
}

func (r *fakeMagicLinkRepo) FindByTokenHash(_ context.Context, hash string) (*model.MagicLinkToken, error) {
	t, ok := r.tokens[hash]
	if !ok {
		return nil, repository.ErrMagicLinkNotFound
	}
	cp := *t
	return &cp, nil
}

func (r *fakeMagicLinkRepo) MarkUsed(_ context.Context, id uint) error {
	if r.usedErr != nil {
		return r.usedErr
	}
	for _, t := range r.tokens {
		if t.ID == id {
			if t.Used {
				return repository.ErrMagicLinkAlreadyUsed
			}
			now := time.Now()
			t.Used = true
			t.UsedAt = &now
			return nil
		}
	}
	return repository.ErrMagicLinkAlreadyUsed
}

func (r *fakeMagicLinkRepo) CountUnusedByEmail(_ context.Context, email string, appID uint, since time.Time) (int64, error) {
	var count int64
	for _, t := range r.tokens {
		if t.Email == email && t.AppID == appID && !t.Used && t.CreatedAt.After(since) {
			count++
		}
	}
	return count, nil
}

func (r *fakeMagicLinkRepo) DeleteExpired(_ context.Context) (int64, error) {
	return 0, nil
}

// fakeUserRepo is a minimal UserRepository for magic-link tests.
type fakeMagicLinkUserRepo struct {
	users map[string]*model.User // keyed by email
	byID  map[uint]*model.User
}

func newFakeMagicLinkUserRepo() *fakeMagicLinkUserRepo {
	return &fakeMagicLinkUserRepo{
		users: make(map[string]*model.User),
		byID:  make(map[uint]*model.User),
	}
}

func (r *fakeMagicLinkUserRepo) add(u *model.User) {
	r.users[u.Email] = u
	r.byID[u.ID] = u
}

func (r *fakeMagicLinkUserRepo) FindByEmail(_ context.Context, email string) (*model.User, error) {
	u, ok := r.users[email]
	if !ok {
		return nil, errors.New("not found")
	}
	return u, nil
}

func (r *fakeMagicLinkUserRepo) FindByID(_ context.Context, id uint) (*model.User, error) {
	u, ok := r.byID[id]
	if !ok {
		return nil, errors.New("not found")
	}
	return u, nil
}

func (r *fakeMagicLinkUserRepo) Update(_ context.Context, u *model.User) error {
	r.users[u.Email] = u
	r.byID[u.ID] = u
	return nil
}

// Stub out unused interface methods.
func (r *fakeMagicLinkUserRepo) FindAll(_ context.Context, _, _ int) ([]model.User, int64, error) {
	return nil, 0, nil
}
func (r *fakeMagicLinkUserRepo) FindByRole(_ context.Context, _ model.UserRole) ([]model.User, error) {
	return nil, nil
}
func (r *fakeMagicLinkUserRepo) CountByRole(_ context.Context, _ model.UserRole) (int64, error) {
	return 0, nil
}
func (r *fakeMagicLinkUserRepo) Create(_ context.Context, _ *model.User) error { return nil }
func (r *fakeMagicLinkUserRepo) Delete(_ context.Context, _ uint) error        { return nil }
func (r *fakeMagicLinkUserRepo) IncrementTokenVersion(_ context.Context, _ uint) error {
	return nil
}
func (r *fakeMagicLinkUserRepo) IncrementFailedLoginAttempts(_ context.Context, _ uint) error {
	return nil
}
func (r *fakeMagicLinkUserRepo) ResetFailedLoginAttempts(_ context.Context, _ uint) error {
	return nil
}
func (r *fakeMagicLinkUserRepo) LockAccount(_ context.Context, _ uint, _ *time.Time) error {
	return nil
}

// fakeAppRepo is a minimal AppRepository for magic-link tests.
type fakeMagicLinkAppRepo struct {
	apps map[string]*model.App // keyed by client_id
}

func newFakeMagicLinkAppRepo() *fakeMagicLinkAppRepo {
	return &fakeMagicLinkAppRepo{apps: make(map[string]*model.App)}
}

func (r *fakeMagicLinkAppRepo) add(a *model.App) { r.apps[a.ClientID] = a }

func (r *fakeMagicLinkAppRepo) FindByClientID(_ context.Context, cid string) (*model.App, error) {
	a, ok := r.apps[cid]
	if !ok {
		return nil, errors.New("not found")
	}
	return a, nil
}

// Stub out the rest of AppRepository (must match repository.AppRepository interface).
func (r *fakeMagicLinkAppRepo) FindAll(_ context.Context) ([]model.App, error) { return nil, nil }
func (r *fakeMagicLinkAppRepo) FindByID(_ context.Context, _ uint) (*model.App, error) {
	return nil, nil
}
func (r *fakeMagicLinkAppRepo) FindByOwnerID(_ context.Context, _ uint) ([]model.App, error) {
	return nil, nil
}
func (r *fakeMagicLinkAppRepo) Create(_ context.Context, _ *model.App) error { return nil }
func (r *fakeMagicLinkAppRepo) Update(_ context.Context, _ *model.App) error { return nil }
func (r *fakeMagicLinkAppRepo) Delete(_ context.Context, _ uint) error       { return nil }
func (r *fakeMagicLinkAppRepo) GetAllRedirectURIs(_ context.Context) ([]string, error) {
	return nil, nil
}

// fakeUserAppRoleRepo is a minimal UserAppRoleRepository for magic-link tests.
type fakeMagicLinkRoleRepo struct {
	roles map[string]*model.UserAppRole // keyed by "userID:appID"
}

func newFakeMagicLinkRoleRepo() *fakeMagicLinkRoleRepo {
	return &fakeMagicLinkRoleRepo{roles: make(map[string]*model.UserAppRole)}
}

func (r *fakeMagicLinkRoleRepo) add(uar *model.UserAppRole) {
	key := roleKey(uar.UserID, uar.AppID)
	r.roles[key] = uar
}

func roleKey(userID, appID uint) string {
	return string(rune(userID)) + ":" + string(rune(appID))
}

func (r *fakeMagicLinkRoleRepo) FindByUserAndApp(_ context.Context, userID, appID uint) (*model.UserAppRole, error) {
	role, ok := r.roles[roleKey(userID, appID)]
	if !ok {
		return nil, errors.New("not found")
	}
	return role, nil
}

func (r *fakeMagicLinkRoleRepo) GetUserRolesMap(_ context.Context, userID uint) (map[string]string, error) {
	result := make(map[string]string)
	for _, uar := range r.roles {
		if uar.UserID == userID {
			result[string(rune(uar.AppID))] = string(uar.Role)
		}
	}
	return result, nil
}

// Stub the rest (must match repository.UserAppRoleRepository interface).
func (r *fakeMagicLinkRoleRepo) Create(_ context.Context, _ *model.UserAppRole) error { return nil }
func (r *fakeMagicLinkRoleRepo) Update(_ context.Context, _ *model.UserAppRole) error { return nil }
func (r *fakeMagicLinkRoleRepo) Delete(_ context.Context, _, _ uint) error            { return nil }
func (r *fakeMagicLinkRoleRepo) FindByUser(_ context.Context, _ uint) ([]model.UserAppRole, error) {
	return nil, nil
}
func (r *fakeMagicLinkRoleRepo) FindAllByUser(_ context.Context, _ uint) ([]model.UserAppRole, error) {
	return nil, nil
}
func (r *fakeMagicLinkRoleRepo) FindByApp(_ context.Context, _ uint, _, _ int, _ string) ([]model.UserAppRole, int64, error) {
	return nil, 0, nil
}

// ---------------------------------------------------------------------------
// Test helpers
// ---------------------------------------------------------------------------

// buildMagicLinkService wires up a MagicLinkService backed by in-memory fakes
// and returns the component fakes for further manipulation.
func buildMagicLinkService(t *testing.T) (
	MagicLinkService,
	*fakeMagicLinkRepo,
	*fakeMagicLinkUserRepo,
	*fakeMagicLinkAppRepo,
	*fakeMagicLinkRoleRepo,
	*NoOpEmailService,
) {
	t.Helper()
	mlRepo := newFakeMagicLinkRepo()
	userRepo := newFakeMagicLinkUserRepo()
	appRepo := newFakeMagicLinkAppRepo()
	roleRepo := newFakeMagicLinkRoleRepo()
	emailSvc := &NoOpEmailService{}

	// NewKeyManager writes a key file; use a temp directory so tests are hermetic.
	km, err := auth.NewKeyManager(t_tempDir(t))
	if err != nil {
		panic("failed to create key manager: " + err.Error())
	}
	tokenSvc := auth.NewTokenService(km, auth.TokenConfig{
		Issuer:          "http://localhost",
		AccessTokenTTL:  15 * time.Minute,
		RefreshTokenTTL: 24 * time.Hour,
		EmailTokenTTL:   24 * time.Hour,
		ResetTokenTTL:   time.Hour,
		InviteTokenTTL:  24 * time.Hour,
	})

	svc := NewMagicLinkService(
		mlRepo, userRepo, appRepo, roleRepo,
		tokenSvc, emailSvc,
		"http://localhost", "development",
	)
	return svc, mlRepo, userRepo, appRepo, roleRepo, emailSvc
}

// seedTestUser adds a verified, unlocked user with a role in the given app.
func seedTestUser(
	userRepo *fakeMagicLinkUserRepo,
	roleRepo *fakeMagicLinkRoleRepo,
	user *model.User,
	app *model.App,
) {
	userRepo.add(user)
	roleRepo.add(&model.UserAppRole{
		UserID: user.ID,
		AppID:  app.ID,
		Role:   model.AppRoleUser,
	})
}

// ---------------------------------------------------------------------------
// RequestMagicLink tests
// ---------------------------------------------------------------------------

func TestRequestMagicLink_HappyPath(t *testing.T) {
	svc, mlRepo, userRepo, appRepo, roleRepo, emailSvc := buildMagicLinkService(t)

	app := &model.App{ID: 1, ClientID: "app-1", Name: "Test App", MagicLinkURL: &testMagicLanding, Active: true}
	user := &model.User{ID: 10, Email: "alice@example.com", Name: "Alice", IsVerified: true}
	appRepo.add(app) // needed by VerifyMagicLink; not used in request path
	seedTestUser(userRepo, roleRepo, user, app)

	// With the M2M architecture the app is injected by ServiceAccountMiddleware;
	// we pass it directly here.
	rawToken, err := svc.RequestMagicLink(context.Background(), "alice@example.com", app)

	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rawToken == "" {
		t.Fatal("expected non-empty rawToken in development mode")
	}
	if len(mlRepo.tokens) != 1 {
		t.Fatalf("expected 1 token in repo, got %d", len(mlRepo.tokens))
	}
	if emailSvc.LastEmail == nil {
		t.Fatal("expected email to be sent")
	}
	if emailSvc.LastEmail.To != "alice@example.com" {
		t.Errorf("email sent to wrong address: %s", emailSvc.LastEmail.To)
	}
}

func TestRequestMagicLink_UnknownEmail_SilentSuccess(t *testing.T) {
	// An unknown email must not return an error (enumeration resistance).
	svc, mlRepo, _, _, _, _ := buildMagicLinkService(t)
	app := &model.App{ID: 1, ClientID: "app-1", Name: "Test App", MagicLinkURL: &testMagicLanding, Active: true}

	rawToken, err := svc.RequestMagicLink(context.Background(), "ghost@example.com", app)

	if err != nil {
		t.Fatalf("expected nil error for unknown email, got: %v", err)
	}
	if rawToken != "" {
		t.Errorf("expected empty rawToken for unknown email, got non-empty")
	}
	if len(mlRepo.tokens) != 0 {
		t.Errorf("expected no tokens to be created for unknown user")
	}
}

func TestRequestMagicLink_UserNoRoleInApp_SilentSuccess(t *testing.T) {
	// A user known to the system but not associated with the app must be
	// silently ignored so that enumeration via the M2M channel is prevented.
	svc, mlRepo, userRepo, _, _, _ := buildMagicLinkService(t)

	app := &model.App{ID: 1, ClientID: "app-1", Name: "Test App", MagicLinkURL: &testMagicLanding, Active: true}
	user := &model.User{ID: 10, Email: "alice@example.com", Name: "Alice", IsVerified: true}
	userRepo.add(user)
	// Intentionally NOT calling seedTestUser — user has no role in app.

	rawToken, err := svc.RequestMagicLink(context.Background(), "alice@example.com", app)

	if err != nil {
		t.Fatalf("expected nil error when user has no role, got: %v", err)
	}
	if rawToken != "" {
		t.Errorf("expected empty rawToken when user has no role in app")
	}
	if len(mlRepo.tokens) != 0 {
		t.Errorf("expected no tokens to be created when user has no role")
	}
}

func TestRequestMagicLink_RateLimit(t *testing.T) {
	svc, _, userRepo, appRepo, roleRepo, _ := buildMagicLinkService(t)

	app := &model.App{ID: 1, ClientID: "app-1", Name: "Test App", MagicLinkURL: &testMagicLanding, Active: true}
	user := &model.User{ID: 10, Email: "alice@example.com", Name: "Alice", IsVerified: true}
	appRepo.add(app)
	seedTestUser(userRepo, roleRepo, user, app)

	// Exhaust the per-address limit (magicLinkRateMax = 5).
	for i := 0; i < magicLinkRateMax; i++ {
		_, err := svc.RequestMagicLink(context.Background(), "alice@example.com", app)
		if err != nil {
			t.Fatalf("request %d failed unexpectedly: %v", i+1, err)
		}
	}

	// The next request must be rate-limited.
	_, err := svc.RequestMagicLink(context.Background(), "alice@example.com", app)
	if !errors.Is(err, ErrMagicLinkRateLimited) {
		t.Errorf("expected ErrMagicLinkRateLimited, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// VerifyMagicLink tests
// ---------------------------------------------------------------------------

func TestVerifyMagicLink_HappyPath(t *testing.T) {
	svc, _, userRepo, appRepo, roleRepo, _ := buildMagicLinkService(t)

	app := &model.App{ID: 1, ClientID: "app-1", Name: "Test App", MagicLinkURL: &testMagicLanding, Active: true}
	user := &model.User{ID: 10, Email: "alice@example.com", Name: "Alice", IsVerified: true}
	appRepo.add(app)
	seedTestUser(userRepo, roleRepo, user, app)

	// Request a magic link first.
	rawToken, err := svc.RequestMagicLink(context.Background(), "alice@example.com", app)
	if err != nil || rawToken == "" {
		t.Fatalf("RequestMagicLink failed: err=%v token=%q", err, rawToken)
	}

	// Exchange it for a token set.
	resp, err := svc.VerifyMagicLink(context.Background(), dto.MagicLinkVerifyRequest{
		Token:    rawToken,
		ClientID: "app-1",
	})
	if err != nil {
		t.Fatalf("VerifyMagicLink failed: %v", err)
	}
	if resp.AccessToken == "" {
		t.Error("expected non-empty access_token")
	}
	if resp.RefreshToken == "" {
		t.Error("expected non-empty refresh_token")
	}
	if resp.IDToken == "" {
		t.Error("expected non-empty id_token")
	}
	if resp.UserID != 10 {
		t.Errorf("expected user_id=10, got %d", resp.UserID)
	}
}

func TestVerifyMagicLink_AlreadyUsed(t *testing.T) {
	svc, _, userRepo, appRepo, roleRepo, _ := buildMagicLinkService(t)

	app := &model.App{ID: 1, ClientID: "app-1", Name: "Test App", MagicLinkURL: &testMagicLanding, Active: true}
	user := &model.User{ID: 10, Email: "alice@example.com", Name: "Alice", IsVerified: true}
	appRepo.add(app)
	seedTestUser(userRepo, roleRepo, user, app)

	rawToken, _ := svc.RequestMagicLink(context.Background(), "alice@example.com", app)

	// First use succeeds.
	if _, err := svc.VerifyMagicLink(context.Background(), dto.MagicLinkVerifyRequest{
		Token: rawToken, ClientID: "app-1",
	}); err != nil {
		t.Fatalf("first verify failed: %v", err)
	}

	// Second use must fail.
	_, err := svc.VerifyMagicLink(context.Background(), dto.MagicLinkVerifyRequest{
		Token: rawToken, ClientID: "app-1",
	})
	if !errors.Is(err, ErrTokenAlreadyUsed) {
		t.Errorf("expected ErrTokenAlreadyUsed on second use, got: %v", err)
	}
}

func TestVerifyMagicLink_WrongToken(t *testing.T) {
	svc, _, _, appRepo, _, _ := buildMagicLinkService(t)
	appRepo.add(&model.App{ID: 1, ClientID: "app-1", Name: "Test App", MagicLinkURL: &testMagicLanding, Active: true})

	_, err := svc.VerifyMagicLink(context.Background(), dto.MagicLinkVerifyRequest{
		Token:    "notavalidtoken",
		ClientID: "app-1",
	})
	if !errors.Is(err, ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken for unknown token, got: %v", err)
	}
}

func TestVerifyMagicLink_ExpiredToken(t *testing.T) {
	svc, mlRepo, userRepo, appRepo, roleRepo, _ := buildMagicLinkService(t)

	app := &model.App{ID: 1, ClientID: "app-1", Name: "Test App", MagicLinkURL: &testMagicLanding, Active: true}
	user := &model.User{ID: 10, Email: "alice@example.com", Name: "Alice", IsVerified: true}
	appRepo.add(app)
	seedTestUser(userRepo, roleRepo, user, app)

	rawToken, _ := svc.RequestMagicLink(context.Background(), "alice@example.com", app)

	// Backdate the token's expiry.
	for _, t2 := range mlRepo.tokens {
		t2.ExpiresAt = time.Now().Add(-1 * time.Hour)
	}

	_, err := svc.VerifyMagicLink(context.Background(), dto.MagicLinkVerifyRequest{
		Token: rawToken, ClientID: "app-1",
	})
	if !errors.Is(err, ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken for expired token, got: %v", err)
	}
}

func TestVerifyMagicLink_EmptyToken(t *testing.T) {
	svc, _, _, appRepo, _, _ := buildMagicLinkService(t)
	appRepo.add(&model.App{ID: 1, ClientID: "app-1", Name: "Test App", MagicLinkURL: &testMagicLanding, Active: true})

	_, err := svc.VerifyMagicLink(context.Background(), dto.MagicLinkVerifyRequest{
		Token:    "",
		ClientID: "app-1",
	})
	if !errors.Is(err, ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken for empty token, got: %v", err)
	}
}

func TestVerifyMagicLink_AppMismatch(t *testing.T) {
	svc, _, userRepo, appRepo, roleRepo, _ := buildMagicLinkService(t)

	app1 := &model.App{ID: 1, ClientID: "app-1", Name: "App One", MagicLinkURL: &testMagicLanding, Active: true}
	app2 := &model.App{ID: 2, ClientID: "app-2", Name: "App Two", MagicLinkURL: &testMagicLanding, Active: true}
	user := &model.User{ID: 10, Email: "alice@example.com", Name: "Alice", IsVerified: true}
	appRepo.add(app1)
	appRepo.add(app2)
	seedTestUser(userRepo, roleRepo, user, app1)

	// Request a token for app-1.
	rawToken, _ := svc.RequestMagicLink(context.Background(), "alice@example.com", app1)

	// Attempt to verify against app-2.
	_, err := svc.VerifyMagicLink(context.Background(), dto.MagicLinkVerifyRequest{
		Token:    rawToken,
		ClientID: "app-2",
	})
	if !errors.Is(err, ErrInvalidToken) {
		t.Errorf("expected ErrInvalidToken for app mismatch, got: %v", err)
	}
}

// ---------------------------------------------------------------------------
// hashMagicToken determinism test
// ---------------------------------------------------------------------------

func TestHashMagicToken_Deterministic(t *testing.T) {
	h1 := hashMagicToken("abc123")
	h2 := hashMagicToken("abc123")
	if h1 != h2 {
		t.Errorf("hash not deterministic: %q != %q", h1, h2)
	}
}

func TestHashMagicToken_DifferentInputs(t *testing.T) {
	h1 := hashMagicToken("token-a")
	h2 := hashMagicToken("token-b")
	if h1 == h2 {
		t.Error("expected different hashes for different inputs")
	}
}

func (*fakeMagicLinkUserRepo) ClaimInviteApp(_ context.Context, _, _ uint) (bool, error) {
	return false, nil
}
func (*fakeMagicLinkUserRepo) AdvanceMFAStep(context.Context, uint, int64) (bool, error) {
	return false, nil
}

func (*fakeMagicLinkUserRepo) UpdateProfile(context.Context, *model.User, bool) error { return nil }

// ---------------------------------------------------------------------------
// VerifyMagicLink: the checks of the other sign-in paths
// ---------------------------------------------------------------------------

// stubMagicLinkPolicy records the admin checks and answers with err.
type stubMagicLinkPolicy struct {
	calls int
	err   error
}

func (p *stubMagicLinkPolicy) checkMagicLinkSignIn(context.Context, *model.User, *model.App) error {
	p.calls++
	return p.err
}

func verifyMagicLinkFor(t *testing.T, user *model.User, app *model.App, policy MagicLinkSignInPolicy) (*dto.LoginResponse, error) {
	t.Helper()
	svc, _, userRepo, appRepo, roleRepo, _ := buildMagicLinkService(t)
	if policy != nil {
		svc.(*magicLinkService).SetSignInPolicy(policy)
	}
	appRepo.add(app)
	seedTestUser(userRepo, roleRepo, user, app)
	activeApp := *app
	activeApp.Active = true // the request side is not what is tested here
	raw, err := svc.RequestMagicLink(context.Background(), user.Email, &activeApp)
	if err != nil || raw == "" {
		t.Fatalf("RequestMagicLink: %v %q", err, raw)
	}
	return svc.VerifyMagicLink(context.Background(), dto.MagicLinkVerifyRequest{Token: raw, ClientID: app.ClientID})
}

// A magic link is one factor: an account with MFA enabled is refused.
func TestVerifyMagicLink_MFAUserRefused(t *testing.T) {
	app := &model.App{ID: 1, ClientID: "app-1", Name: "Test App", MagicLinkURL: &testMagicLanding, Active: true}
	user := &model.User{ID: 10, Email: "alice@example.com", IsVerified: true, MFAEnabled: true}
	if _, err := verifyMagicLinkFor(t, user, app, nil); !errors.Is(err, ErrMagicLinkSecondFactor) {
		t.Fatalf("%v, want ErrMagicLinkSecondFactor", err)
	}
}

// A deactivated client gets no tokens through a magic link.
func TestVerifyMagicLink_InactiveAppRefused(t *testing.T) {
	app := &model.App{ID: 1, ClientID: "app-1", Name: "Test App", MagicLinkURL: &testMagicLanding, Active: false}
	user := &model.User{ID: 10, Email: "alice@example.com", IsVerified: true}
	if _, err := verifyMagicLinkFor(t, user, app, nil); !errors.Is(err, ErrAppInactive) {
		t.Fatalf("%v, want ErrAppInactive", err)
	}
}

// A Socrate admin goes through the admin sign-in policies; without them wired
// the sign-in is refused. A regular user is not affected by them.
func TestVerifyMagicLink_AdminPolicies(t *testing.T) {
	app := &model.App{ID: 1, ClientID: "app-1", Name: "Test App", MagicLinkURL: &testMagicLanding, Active: true}
	admin := func() *model.User {
		return &model.User{ID: 10, Email: "admin@example.com", IsVerified: true, Role: model.UserRoleSuperadmin}
	}

	if _, err := verifyMagicLinkFor(t, admin(), app, nil); !errors.Is(err, ErrAdminAppSignInRefused) {
		t.Fatalf("admin without policy wired: %v, want ErrAdminAppSignInRefused", err)
	}

	refusing := &stubMagicLinkPolicy{err: ErrMFAEnrollmentRequired}
	if _, err := verifyMagicLinkFor(t, admin(), app, refusing); !errors.Is(err, ErrMFAEnrollmentRequired) || refusing.calls != 1 {
		t.Fatalf("admin refused by policy: %v (calls %d), want ErrMFAEnrollmentRequired", err, refusing.calls)
	}

	allowing := &stubMagicLinkPolicy{}
	if resp, err := verifyMagicLinkFor(t, admin(), app, allowing); err != nil || resp.AccessToken == "" || allowing.calls != 1 {
		t.Fatalf("admin allowed by policy: %v (calls %d)", err, allowing.calls)
	}

	regular := &stubMagicLinkPolicy{err: ErrAdminAppSignInRefused}
	user := &model.User{ID: 11, Email: "bob@example.com", IsVerified: true}
	if _, err := verifyMagicLinkFor(t, user, app, regular); err != nil || regular.calls != 0 {
		t.Fatalf("regular user: %v (policy calls %d), want success without the admin checks", err, regular.calls)
	}
}

// The auth service implements the admin checks: enforce-mode MFA enrollment
// refuses an admin without MFA; a regular user is untouched.
func TestAuthService_CheckMagicLinkSignIn(t *testing.T) {
	s := &authService{adminMFAPolicy: MFAPolicyEnforce, auditRepo: &captureAuditRepo{}}
	admin := &model.User{ID: 1, Role: model.UserRoleSuperadmin}
	if err := s.checkMagicLinkSignIn(context.Background(), admin, &model.App{ID: 1, ClientID: "app-1"}); !errors.Is(err, ErrMFAEnrollmentRequired) {
		t.Fatalf("admin without MFA under enforce: %v, want ErrMFAEnrollmentRequired", err)
	}
	if err := s.checkMagicLinkSignIn(context.Background(), &model.User{ID: 2, Role: model.UserRoleUser}, &model.App{ID: 1}); err != nil {
		t.Fatalf("regular user: %v", err)
	}
	// ADMIN_APP_SIGNIN_POLICY covers admins without a membership; a magic link
	// always has one, so a member admin with MFA policy satisfied signs in to a
	// non-console app as with a password.
	member := &authService{adminAppSignIn: NewAdminAppSignInPolicy(AdminAppSignInEnforce, []string{"admin-console"}), auditRepo: &captureAuditRepo{}}
	if err := member.checkMagicLinkSignIn(context.Background(), &model.User{ID: 3, Role: model.UserRoleAdmin}, &model.App{ID: 1, ClientID: "member-app"}); err != nil {
		t.Fatalf("member admin, app sign-in policy enforce: %v, want allowed", err)
	}
	var _ MagicLinkSignInPolicy = s
}
