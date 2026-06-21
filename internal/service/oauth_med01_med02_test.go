// Package service — tests for MED-01 (per-token revocation) and MED-02
// (PKCE enforcement for clients with RequirePKCE=true).
//
// MED-01 fix: Revoke() now blacklists the specific token JTI rather than
// performing nuclear IncrementTokenVersion.  Introspect() returns active:false
// for blacklisted tokens.
//
// MED-02 fix: Authorize() and handleAuthorizationCodeGrant() enforce
// PKCE when app.RequirePKCE is true.
package service

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/ovandermoten/go-oauth2/internal/dto"
	"github.com/ovandermoten/go-oauth2/internal/model"
	"github.com/ovandermoten/go-oauth2/internal/repository"
	"github.com/ovandermoten/go-oauth2/internal/shared/auth"
)

// ---------------------------------------------------------------------------
// Shared factory for MED tests
// ---------------------------------------------------------------------------

func newMedSvc(t *testing.T, usedRepo repository.UsedTokenRepository, app *model.App, user *model.User) (*oauthService, *auth.TokenService) {
	t.Helper()

	tmpDir, err := os.MkdirTemp("", "med-keys-*")
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

	role := &model.UserAppRole{UserID: user.ID, AppID: app.ID, Role: model.AppRoleUser}

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
	return svc, ts
}

// medTokenRequest builds a token exchange request for authorization_code grant.
func medTokenRequest(clientID, code, redirectURI, verifier string) dto.TokenRequest {
	return dto.TokenRequest{
		GrantType:    "authorization_code",
		Code:         code,
		RedirectURI:  redirectURI,
		CodeVerifier: verifier,
	}
}

// ---------------------------------------------------------------------------
// MED-01: per-token revocation
// ---------------------------------------------------------------------------

// TestMED01_Revoke_BlacklistsJTI verifies that Revoke() stores the access
// token JTI in the usedTokenRepo (per-token, not per-user revocation).
func TestMED01_Revoke_BlacklistsJTI(t *testing.T) {
	usedRepo := newMemUsedTokenRepo()
	user := &model.User{ID: 7, Email: "bob@example.com", TokenVersion: 1}
	app := &model.App{ID: 1, ClientID: "my-app"}
	svc, ts := newMedSvc(t, usedRepo, app, user)

	tokenSet, err := ts.GenerateTokenSet(user, app, "user", "openid", nil, "", time.Now().Unix())
	if err != nil {
		t.Fatalf("GenerateTokenSet: %v", err)
	}

	claims, err := ts.VerifyAccessToken(tokenSet.AccessToken)
	if err != nil {
		t.Fatalf("VerifyAccessToken: %v", err)
	}

	// JTI must NOT be in used repo before revocation.
	used, _ := usedRepo.IsUsed(context.Background(), claims.ID)
	if used {
		t.Fatal("JTI already in used repo before Revoke()")
	}

	_ = svc.Revoke(context.Background(), tokenSet.AccessToken, user.ID)

	// JTI MUST be in used repo after revocation.
	used, _ = usedRepo.IsUsed(context.Background(), claims.ID)
	if !used {
		t.Error("MED-01: JTI not blacklisted after Revoke() — per-token revocation broken")
	}
}

// TestMED01_Revoke_RefreshToken_BlacklistsJTI verifies that Revoke() also
// handles refresh token strings and blacklists their JTI.
func TestMED01_Revoke_RefreshToken_BlacklistsJTI(t *testing.T) {
	usedRepo := newMemUsedTokenRepo()
	user := &model.User{ID: 8, Email: "carol@example.com", TokenVersion: 1}
	app := &model.App{ID: 2, ClientID: "app-b"}
	svc, ts := newMedSvc(t, usedRepo, app, user)

	tokenSet, err := ts.GenerateTokenSet(user, app, "user", "openid offline_access", nil, "", time.Now().Unix())
	if err != nil {
		t.Fatalf("GenerateTokenSet: %v", err)
	}
	rClaims, err := ts.VerifyRefreshToken(tokenSet.RefreshToken)
	if err != nil {
		t.Fatalf("VerifyRefreshToken: %v", err)
	}

	_ = svc.Revoke(context.Background(), tokenSet.RefreshToken, user.ID)

	used, _ := usedRepo.IsUsed(context.Background(), rClaims.ID)
	if !used {
		t.Error("MED-01: refresh token JTI not blacklisted after Revoke()")
	}
}

// TestMED01_Introspect_ReturnsFalse_ForRevokedToken verifies that Introspect()
// returns active:false immediately after a token is revoked.
func TestMED01_Introspect_ReturnsFalse_ForRevokedToken(t *testing.T) {
	usedRepo := newMemUsedTokenRepo()
	user := &model.User{ID: 9, Email: "dave@example.com", TokenVersion: 1}
	app := &model.App{ID: 3, ClientID: "app-c"}
	svc, ts := newMedSvc(t, usedRepo, app, user)

	tokenSet, err := ts.GenerateTokenSet(user, app, "user", "openid", nil, "", time.Now().Unix())
	if err != nil {
		t.Fatalf("GenerateTokenSet: %v", err)
	}

	_ = svc.Revoke(context.Background(), tokenSet.AccessToken, user.ID)

	resp, err := svc.Introspect(context.Background(), tokenSet.AccessToken)
	if err != nil {
		t.Fatalf("Introspect error: %v", err)
	}
	if resp.Active {
		t.Error("MED-01: Introspect returned active:true for a revoked token — JTI blacklist not enforced in Introspect")
	}
}

// TestMED01_Introspect_ReturnsTrue_ForNonRevokedToken confirms that valid,
// non-revoked tokens still introspect as active.
func TestMED01_Introspect_ReturnsTrue_ForNonRevokedToken(t *testing.T) {
	usedRepo := newMemUsedTokenRepo()
	user := &model.User{ID: 10, Email: "eve@example.com", TokenVersion: 1}
	app := &model.App{ID: 4, ClientID: "app-d"}
	svc, ts := newMedSvc(t, usedRepo, app, user)

	tokenSet, err := ts.GenerateTokenSet(user, app, "user", "openid", nil, "", time.Now().Unix())
	if err != nil {
		t.Fatalf("GenerateTokenSet: %v", err)
	}

	resp, err := svc.Introspect(context.Background(), tokenSet.AccessToken)
	if err != nil {
		t.Fatalf("Introspect error: %v", err)
	}
	if !resp.Active {
		t.Error("MED-01: Introspect returned active:false for a valid, non-revoked token")
	}
}

// TestMED01_Revoke_MalformedToken_FallsBackToNuclear verifies that a
// malformed token triggers the fallback IncrementTokenVersion path.
func TestMED01_Revoke_MalformedToken_FallsBackToNuclear(t *testing.T) {
	usedRepo := newMemUsedTokenRepo()
	user := &model.User{ID: 11, Email: "frank@example.com", TokenVersion: 0}
	app := &model.App{ID: 5, ClientID: "app-e"}

	incrementCalled := false
	innerUserRepo := &high04UserRepo{user: user}
	trackRepo := &trackIncrUserRepo{inner: innerUserRepo, cb: func() { incrementCalled = true }}

	tmpDir, err := os.MkdirTemp("", "med-keys-fallback-*")
	if err != nil {
		t.Fatalf("MkdirTemp: %v", err)
	}
	t.Cleanup(func() { os.RemoveAll(tmpDir) })
	km, _ := auth.NewKeyManager(tmpDir)
	ts := auth.NewTokenService(km, auth.TokenConfig{
		Issuer: "https://auth.example.com", AccessTokenTTL: time.Hour,
		RefreshTokenTTL: 7 * 24 * time.Hour, EmailTokenTTL: 24 * time.Hour,
		ResetTokenTTL: time.Hour, InviteTokenTTL: 24 * time.Hour,
	})
	codeRepo := newMemCodeRepo()
	cs := auth.NewCodeStoreWithTTL(codeRepo, 10*time.Minute)
	t.Cleanup(cs.Stop)

	svc := &oauthService{
		userRepo: trackRepo, appRepo: &crit02AppRepo{app: app},
		userAppRoleRepo: &high04RoleRepo{role: &model.UserAppRole{UserID: user.ID, AppID: app.ID, Role: model.AppRoleUser}},
		codeStore:       cs, tokenService: ts, keyManager: km,
		usedTokenRepo: usedRepo, issuer: "https://auth.example.com",
	}

	_ = svc.Revoke(context.Background(), "not.a.valid.jwt", user.ID)

	if !incrementCalled {
		t.Error("MED-01: fallback IncrementTokenVersion not called for malformed token")
	}
}

// trackIncrUserRepo wraps UserRepository to observe IncrementTokenVersion.
type trackIncrUserRepo struct {
	inner repository.UserRepository
	cb    func()
}

func (r *trackIncrUserRepo) FindByID(ctx context.Context, id uint) (*model.User, error) {
	return r.inner.FindByID(ctx, id)
}
func (r *trackIncrUserRepo) FindByEmail(ctx context.Context, e string) (*model.User, error) {
	return r.inner.FindByEmail(ctx, e)
}
func (r *trackIncrUserRepo) FindAll(ctx context.Context, o, l int) ([]model.User, int64, error) {
	return r.inner.FindAll(ctx, o, l)
}
func (r *trackIncrUserRepo) FindByRole(ctx context.Context, role model.UserRole) ([]model.User, error) {
	return r.inner.FindByRole(ctx, role)
}
func (r *trackIncrUserRepo) CountByRole(ctx context.Context, role model.UserRole) (int64, error) {
	return r.inner.CountByRole(ctx, role)
}
func (r *trackIncrUserRepo) Create(ctx context.Context, u *model.User) error { return nil }
func (r *trackIncrUserRepo) Update(ctx context.Context, u *model.User) error { return nil }
func (r *trackIncrUserRepo) Delete(ctx context.Context, id uint) error       { return nil }
func (r *trackIncrUserRepo) IncrementTokenVersion(ctx context.Context, id uint) error {
	if r.cb != nil {
		r.cb()
	}
	return r.inner.IncrementTokenVersion(ctx, id)
}
func (r *trackIncrUserRepo) IncrementFailedLoginAttempts(_ context.Context, _ uint) error {
	return nil
}
func (r *trackIncrUserRepo) ResetFailedLoginAttempts(_ context.Context, _ uint) error { return nil }
func (r *trackIncrUserRepo) LockAccount(_ context.Context, _ uint, _ *time.Time) error {
	return nil
}

var _ repository.UserRepository = (*trackIncrUserRepo)(nil)

// ---------------------------------------------------------------------------
// MED-02: PKCE enforcement for RequirePKCE clients
// ---------------------------------------------------------------------------

// TestMED02_Authorize_RequirePKCE_RejectsNoPKCE verifies that Authorize()
// returns ErrPKCERequired when the app sets RequirePKCE=true but no
// code_challenge is included in the request.
func TestMED02_Authorize_RequirePKCE_RejectsNoPKCE(t *testing.T) {
	user := &model.User{ID: 20, Email: "pkce@example.com", TokenVersion: 1}
	app := &model.App{ID: 10, ClientID: "public-app", RequirePKCE: true,
		RedirectURIs: model.StringArray{"https://app.example.com/cb"}}
	svc, _ := newMedSvc(t, newMemUsedTokenRepo(), app, user)

	req := dto.AuthorizeRequest{
		ResponseType: "code",
		ClientID:     "public-app",
		RedirectURI:  "https://app.example.com/cb",
		Scope:        "openid",
		State:        "test-state",
		// CodeChallenge intentionally empty
	}
	_, err := svc.Authorize(context.Background(), req, user.ID)
	if err == nil {
		t.Fatal("MED-02: Authorize() should reject RequirePKCE client without code_challenge")
	}
	if !errors.Is(err, ErrPKCERequired) {
		t.Errorf("MED-02: expected ErrPKCERequired, got: %v", err)
	}
}

// TestMED02_Authorize_RequirePKCE_AllowsWithPKCE verifies that Authorize()
// proceeds when RequirePKCE=true and a code_challenge is provided.
func TestMED02_Authorize_RequirePKCE_AllowsWithPKCE(t *testing.T) {
	user := &model.User{ID: 21, Email: "pkce2@example.com", TokenVersion: 1}
	app := &model.App{ID: 11, ClientID: "public-app2", RequirePKCE: true,
		RedirectURIs: model.StringArray{"https://app.example.com/cb"}}
	svc, _ := newMedSvc(t, newMemUsedTokenRepo(), app, user)

	req := dto.AuthorizeRequest{
		ResponseType:        "code",
		ClientID:            "public-app2",
		RedirectURI:         "https://app.example.com/cb",
		Scope:               "openid",
		State:               "test-state",
		CodeChallenge:       "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM",
		CodeChallengeMethod: "S256",
	}
	_, err := svc.Authorize(context.Background(), req, user.ID)
	// Should NOT be ErrPKCERequired; downstream errors (e.g. nil auditRepo) are acceptable.
	if errors.Is(err, ErrPKCERequired) {
		t.Errorf("MED-02: ErrPKCERequired should not be returned when code_challenge provided: %v", err)
	}
}

// TestMED02_Authorize_NoPKCERequired_AllowsNoPKCE verifies that a client
// without RequirePKCE can omit code_challenge without getting ErrPKCERequired.
func TestMED02_Authorize_NoPKCERequired_AllowsNoPKCE(t *testing.T) {
	user := &model.User{ID: 22, Email: "confidential@example.com", TokenVersion: 1}
	app := &model.App{ID: 12, ClientID: "confidential-app", RequirePKCE: false,
		ClientSecretHash: "hashed",
		RedirectURIs:     model.StringArray{"https://app.example.com/cb"}}
	svc, _ := newMedSvc(t, newMemUsedTokenRepo(), app, user)

	req := dto.AuthorizeRequest{
		ResponseType: "code",
		ClientID:     "confidential-app",
		RedirectURI:  "https://app.example.com/cb",
		Scope:        "openid",
		State:        "test-state",
	}
	_, err := svc.Authorize(context.Background(), req, user.ID)
	if errors.Is(err, ErrPKCERequired) {
		t.Errorf("MED-02: ErrPKCERequired should not be returned for non-RequirePKCE client: %v", err)
	}
}

// TestMED02_TokenGrant_RequirePKCE_RejectsCodeWithoutChallenge verifies that
// token exchange is rejected when RequirePKCE=true but the stored code has no
// code_challenge (i.e. the auth request bypassed the PKCE check).
func TestMED02_TokenGrant_RequirePKCE_RejectsCodeWithoutChallenge(t *testing.T) {
	user := &model.User{ID: 23, Email: "pkce3@example.com", TokenVersion: 1}
	app := &model.App{ID: 13, ClientID: "pkce-app", RequirePKCE: true,
		RedirectURIs: model.StringArray{"https://app.example.com/cb"}}
	svc, _ := newMedSvc(t, newMemUsedTokenRepo(), app, user)

	// Inject a code that has no code_challenge (simulating an old code or bypass).
	code, _ := svc.codeStore.GenerateCode(
		context.Background(),
		user.ID, app.ID, "pkce-app",
		"https://app.example.com/cb",
		"openid", "",
		"", "", // no code_challenge
		"user", nil,
	)

	_, err := svc.handleAuthorizationCodeGrant(
		context.Background(),
		medTokenRequest("pkce-app", code, "https://app.example.com/cb", ""),
		"pkce-app", "",
	)
	if err == nil {
		t.Fatal("MED-02: token grant should reject RequirePKCE code without challenge")
	}
	if !errors.Is(err, ErrPKCERequired) {
		t.Errorf("MED-02: expected ErrPKCERequired, got: %v", err)
	}
}
