// Package service — tests for CRIT-02 and HIGH-03 fixes.
//
// CRIT-02 fix: confidential clients (those with a non-empty ClientSecretHash)
// MUST supply their client_secret at the authorization_code token endpoint.
// The previous code was conditioned on `clientSecret != ""`, which allowed any
// client to skip authentication by simply omitting the secret.
//
// HIGH-03 fix: the refresh_token grant now also enforces client
// authentication for confidential clients, mirroring the authorization_code
// grant.  Additionally, a refresh token without an audience matching the
// requesting clientID is now always rejected.
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
// In-memory AuthorizationCode repository — no database needed
// ---------------------------------------------------------------------------

type memCodeRepo struct {
	mu    sync.Mutex
	codes map[string]*model.AuthorizationCode
}

func newMemCodeRepo() *memCodeRepo {
	return &memCodeRepo{codes: make(map[string]*model.AuthorizationCode)}
}

func (r *memCodeRepo) Create(_ context.Context, code *model.AuthorizationCode) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.codes[code.Code] = code
	return nil
}

func (r *memCodeRepo) FindByCode(_ context.Context, code string) (*model.AuthorizationCode, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	c, ok := r.codes[code]
	if !ok {
		return nil, errors.New("not found")
	}
	return c, nil
}

func (r *memCodeRepo) MarkAsUsed(_ context.Context, code string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if c, ok := r.codes[code]; ok {
		c.Used = true
	}
	return nil
}

func (r *memCodeRepo) Delete(_ context.Context, code string) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.codes, code)
	return nil
}

func (r *memCodeRepo) DeleteExpired(_ context.Context) (int64, error)  { return 0, nil }
func (r *memCodeRepo) DeleteByUserID(_ context.Context, _ uint) error  { return nil }

// ---------------------------------------------------------------------------
// Minimal App repository stub
// ---------------------------------------------------------------------------

type crit02AppRepo struct {
	app *model.App
}

func (r *crit02AppRepo) FindByClientID(_ context.Context, _ string) (*model.App, error) {
	if r.app == nil {
		return nil, errors.New("not found")
	}
	return r.app, nil
}
func (r *crit02AppRepo) FindAll(_ context.Context) ([]model.App, error)           { return nil, nil }
func (r *crit02AppRepo) FindByID(_ context.Context, _ uint) (*model.App, error)   { return nil, errors.New("not found") }
func (r *crit02AppRepo) FindByOwnerID(_ context.Context, _ uint) ([]model.App, error) { return nil, nil }
func (r *crit02AppRepo) Create(_ context.Context, _ *model.App) error             { return nil }
func (r *crit02AppRepo) Update(_ context.Context, _ *model.App) error             { return nil }
func (r *crit02AppRepo) Delete(_ context.Context, _ uint) error                   { return nil }
func (r *crit02AppRepo) GetAllRedirectURIs(_ context.Context) ([]string, error)   { return nil, nil }

// Compile-time interface compliance check.
var _ repository.AppRepository = (*crit02AppRepo)(nil)

// ---------------------------------------------------------------------------
// Minimal User repository stub — always returns "not found"
// ---------------------------------------------------------------------------
//
// After the credential check passes in handleAuthorizationCodeGrant the code
// proceeds to look up the user via userRepo.FindByID.  Without this stub the
// service would dereference a nil pointer and panic, turning what should be a
// clean ErrUserNotFound into a test crash.

type stubUserRepo struct{}

func (stubUserRepo) FindByID(_ context.Context, _ uint) (*model.User, error) {
	return nil, errors.New("user not found (stub)")
}
func (stubUserRepo) FindAll(_ context.Context, _, _ int) ([]model.User, int64, error) {
	return nil, 0, nil
}
func (stubUserRepo) FindByEmail(_ context.Context, _ string) (*model.User, error) {
	return nil, errors.New("not found")
}
func (stubUserRepo) FindByRole(_ context.Context, _ model.UserRole) ([]model.User, error) {
	return nil, nil
}
func (stubUserRepo) CountByRole(_ context.Context, _ model.UserRole) (int64, error) { return 0, nil }
func (stubUserRepo) Create(_ context.Context, _ *model.User) error                  { return nil }
func (stubUserRepo) Update(_ context.Context, _ *model.User) error                  { return nil }
func (stubUserRepo) Delete(_ context.Context, _ uint) error                          { return nil }
func (stubUserRepo) IncrementTokenVersion(_ context.Context, _ uint) error           { return nil }
func (stubUserRepo) IncrementFailedLoginAttempts(_ context.Context, _ uint) error    { return nil }
func (stubUserRepo) ResetFailedLoginAttempts(_ context.Context, _ uint) error        { return nil }
func (stubUserRepo) LockAccount(_ context.Context, _ uint, _ *time.Time) error       { return nil }

// Compile-time interface compliance check.
var _ repository.UserRepository = stubUserRepo{}

// ---------------------------------------------------------------------------
// Test service factory
// ---------------------------------------------------------------------------

func newCrit02Service(t *testing.T, app *model.App) *oauthService {
	t.Helper()

	tmpDir, err := os.MkdirTemp("", "crit02-keys-*")
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

	codeRepo := newMemCodeRepo()
	cs := auth.NewCodeStoreWithTTL(codeRepo, 10*time.Minute)
	t.Cleanup(cs.Stop)

	return &oauthService{
		appRepo:      &crit02AppRepo{app: app},
		userRepo:     stubUserRepo{}, // prevents nil-deref after credential check passes
		codeStore:    cs,
		tokenService: ts,
		keyManager:   km,
		issuer:       "https://auth.example.com",
	}
}

// seedCode inserts a code directly into the service's codeStore.
func seedCode(t *testing.T, svc *oauthService, clientID, redirectURI string, userID uint) string {
	t.Helper()
	code, err := svc.codeStore.GenerateCode(context.Background(), userID, 1, clientID,
		redirectURI, "openid", "", "", "", "user", nil)
	if err != nil {
		t.Fatalf("GenerateCode: %v", err)
	}
	return code
}

// ---------------------------------------------------------------------------
// CRIT-02: handleAuthorizationCodeGrant — client secret enforcement
// ---------------------------------------------------------------------------

func TestCRIT02_ConfidentialClient_NoSecret_ReturnsCredentialsError(t *testing.T) {
	// A client with a stored secret hash is confidential and MUST supply its
	// secret.  Omitting the secret entirely must now be rejected.
	secretHash, _ := auth.HashClientSecret("correct-secret")
	app := &model.App{
		ID:               1,
		ClientID:         "confidential-app",
		ClientSecretHash: secretHash,
		Active:           true,
		RedirectURIs:     model.StringArray{"https://app.example.com/cb"},
	}

	svc := newCrit02Service(t, app)
	code := seedCode(t, svc, "confidential-app", "https://app.example.com/cb", 42)

	req := dto.TokenRequest{
		GrantType:   "authorization_code",
		Code:        code,
		RedirectURI: "https://app.example.com/cb",
	}

	_, err := svc.handleAuthorizationCodeGrant(context.Background(), req, "confidential-app", "")
	if err == nil {
		t.Fatal("expected error when confidential client omits client_secret, got nil")
	}
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("error = %v, want ErrInvalidCredentials", err)
	}
}

func TestCRIT02_ConfidentialClient_WrongSecret_ReturnsCredentialsError(t *testing.T) {
	secretHash, _ := auth.HashClientSecret("correct-secret")
	app := &model.App{
		ID:               1,
		ClientID:         "confidential-app",
		ClientSecretHash: secretHash,
		Active:           true,
		RedirectURIs:     model.StringArray{"https://app.example.com/cb"},
	}

	svc := newCrit02Service(t, app)
	code := seedCode(t, svc, "confidential-app", "https://app.example.com/cb", 42)

	req := dto.TokenRequest{
		GrantType:   "authorization_code",
		Code:        code,
		RedirectURI: "https://app.example.com/cb",
	}

	_, err := svc.handleAuthorizationCodeGrant(context.Background(), req, "confidential-app", "wrong-secret")
	if err == nil {
		t.Fatal("expected error for wrong client_secret, got nil")
	}
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("error = %v, want ErrInvalidCredentials", err)
	}
}

func TestCRIT02_ConfidentialClient_CorrectSecret_PassesCredentialCheck(t *testing.T) {
	// When the correct secret is supplied the credential check must pass.
	// The call may still fail for other reasons (no user repo wired), but
	// the error must NOT be ErrInvalidCredentials.
	secretHash, _ := auth.HashClientSecret("correct-secret")
	app := &model.App{
		ID:               1,
		ClientID:         "confidential-app",
		ClientSecretHash: secretHash,
		Active:           true,
		RedirectURIs:     model.StringArray{"https://app.example.com/cb"},
	}

	svc := newCrit02Service(t, app)
	code := seedCode(t, svc, "confidential-app", "https://app.example.com/cb", 42)

	req := dto.TokenRequest{
		GrantType:   "authorization_code",
		Code:        code,
		RedirectURI: "https://app.example.com/cb",
	}

	_, err := svc.handleAuthorizationCodeGrant(context.Background(), req, "confidential-app", "correct-secret")
	if errors.Is(err, ErrInvalidCredentials) {
		t.Error("ErrInvalidCredentials returned despite correct client_secret — credential check is broken")
	}
}

func TestCRIT02_PublicClient_NoSecret_PassesCredentialCheck(t *testing.T) {
	// A public client (empty ClientSecretHash) authenticates via PKCE.
	// It must NOT be rejected for omitting a client_secret.
	app := &model.App{
		ID:               2,
		ClientID:         "public-spa",
		ClientSecretHash: "", // no secret stored → public client
		Active:           true,
		RedirectURIs:     model.StringArray{"https://spa.example.com/cb"},
	}

	svc := newCrit02Service(t, app)
	code := seedCode(t, svc, "public-spa", "https://spa.example.com/cb", 10)

	req := dto.TokenRequest{
		GrantType:   "authorization_code",
		Code:        code,
		RedirectURI: "https://spa.example.com/cb",
	}

	_, err := svc.handleAuthorizationCodeGrant(context.Background(), req, "public-spa", "")
	// May fail for other reasons (no user repo), but must NOT be a credentials error.
	if errors.Is(err, ErrInvalidCredentials) {
		t.Error("public client rejected with ErrInvalidCredentials — client secret check must be skipped")
	}
}

// ---------------------------------------------------------------------------
// HIGH-03: handleRefreshTokenGrant — audience and client auth enforcement
// ---------------------------------------------------------------------------

func TestHIGH03_RefreshGrant_WrongClientID_ReturnsInvalidToken(t *testing.T) {
	// If the refresh token's audience does not match the requesting clientID,
	// the grant must be rejected.
	app := &model.App{
		ID:               1,
		ClientID:         "correct-client",
		ClientSecretHash: "",
		Active:           true,
	}
	svc := newCrit02Service(t, app)

	// Build a valid refresh token issued for "correct-client".
	tokenSet, err := svc.tokenService.GenerateTokenSet(
		&model.User{ID: 5, Email: "u@test.com", TokenVersion: 0},
		app,
		"user", "openid", nil, "", time.Now().Unix(),
	)
	if err != nil {
		t.Fatalf("GenerateTokenSet: %v", err)
	}

	req := dto.TokenRequest{
		GrantType:    "refresh_token",
		RefreshToken: tokenSet.RefreshToken,
	}

	// Presenting the token to a different client must fail.
	_, err = svc.handleRefreshTokenGrant(context.Background(), req, "wrong-client", "")
	if err == nil {
		t.Fatal("expected error for audience mismatch, got nil")
	}
	if !errors.Is(err, ErrInvalidToken) {
		t.Errorf("error = %v, want ErrInvalidToken", err)
	}
}

func TestHIGH03_RefreshGrant_ConfidentialClient_NoSecret_ReturnsError(t *testing.T) {
	// HIGH-03: a confidential client must supply its secret on the refresh
	// grant too.  Previously clientSecret was not even threaded into this path.
	secretHash, _ := auth.HashClientSecret("app-secret")
	app := &model.App{
		ID:               1,
		ClientID:         "confidential-app",
		ClientSecretHash: secretHash,
		Active:           true,
	}
	svc := newCrit02Service(t, app)

	tokenSet, err := svc.tokenService.GenerateTokenSet(
		&model.User{ID: 5, Email: "u@test.com", TokenVersion: 0},
		app,
		"user", "openid", nil, "", time.Now().Unix(),
	)
	if err != nil {
		t.Fatalf("GenerateTokenSet: %v", err)
	}

	req := dto.TokenRequest{
		GrantType:    "refresh_token",
		RefreshToken: tokenSet.RefreshToken,
	}

	// No user repo is wired, so the call will fail regardless — but we need
	// it to fail with ErrInvalidCredentials (not some other error) to confirm
	// the credential check ran.
	_, err = svc.handleRefreshTokenGrant(context.Background(), req, "confidential-app", "")
	if err == nil {
		t.Fatal("expected error when confidential client omits secret on refresh grant, got nil")
	}
	if !errors.Is(err, ErrInvalidCredentials) {
		t.Errorf("error = %v, want ErrInvalidCredentials", err)
	}
}

func TestHIGH03_RefreshGrant_ConfidentialClient_CorrectSecret_PassesCredentialCheck(t *testing.T) {
	// When the correct secret is supplied the credential check passes.
	// The error must NOT be ErrInvalidCredentials.
	secretHash, _ := auth.HashClientSecret("app-secret")
	app := &model.App{
		ID:               1,
		ClientID:         "confidential-app",
		ClientSecretHash: secretHash,
		Active:           true,
	}
	svc := newCrit02Service(t, app)

	tokenSet, err := svc.tokenService.GenerateTokenSet(
		&model.User{ID: 5, Email: "u@test.com", TokenVersion: 0},
		app,
		"user", "openid", nil, "", time.Now().Unix(),
	)
	if err != nil {
		t.Fatalf("GenerateTokenSet: %v", err)
	}

	req := dto.TokenRequest{
		GrantType:    "refresh_token",
		RefreshToken: tokenSet.RefreshToken,
	}

	_, err = svc.handleRefreshTokenGrant(context.Background(), req, "confidential-app", "app-secret")
	if errors.Is(err, ErrInvalidCredentials) {
		t.Error("ErrInvalidCredentials returned despite correct client_secret on refresh grant")
	}
}
