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

// A sign-in loads the user, checks the password (and MFA), then records the
// sign-in time. It records it with RecordLogin, never with a full-row Update
// of the copy it loaded: a change made to the account in between (an MFA
// enrolment, a rename, a password change) is kept.

// signInUserRepo holds one user. meanwhile, when set, changes the stored user
// after the password check and before the sign-in is recorded, as a
// concurrent request would. The embedded nil interface fails loudly if any
// other method is called.
type signInUserRepo struct {
	repository.UserRepository
	stored       *model.User
	meanwhile    func(u *model.User)
	fullSaves    int
	recordLogins int
	attempt      bool
}

func (r *signInUserRepo) FindByEmail(_ context.Context, email string) (*model.User, error) {
	if r.stored == nil || r.stored.Email != email {
		return nil, errors.New("record not found")
	}
	cp := *r.stored
	return &cp, nil
}

func (r *signInUserRepo) ResetFailedLoginAttempts(_ context.Context, id uint) error {
	if r.stored == nil || r.stored.ID != id {
		return errors.New("record not found")
	}
	r.stored.FailedLoginAttempts, r.stored.LockedUntil = 0, nil
	if r.meanwhile != nil {
		r.meanwhile(r.stored)
	}
	return nil
}

// Update models the GORM repository: it writes every column but the guarded
// ones.
func (r *signInUserRepo) Update(_ context.Context, u *model.User) error {
	r.fullSaves++
	cp := *u
	s := r.stored
	cp.TokenVersion, cp.FailedLoginAttempts, cp.LockedUntil, cp.MFALastStep = s.TokenVersion, s.FailedLoginAttempts, s.LockedUntil, s.MFALastStep
	cp.HashedPassword, cp.PasswordChangedAt, cp.MustChangePassword, cp.InviteAppID = s.HashedPassword, s.PasswordChangedAt, s.MustChangePassword, s.InviteAppID
	r.stored = &cp
	return nil
}

func (r *signInUserRepo) RecordLogin(_ context.Context, id uint, at time.Time, attempt bool) error {
	if r.stored == nil || r.stored.ID != id {
		return errors.New("record not found")
	}
	r.recordLogins++
	r.attempt = attempt
	r.stored.LastLogin, r.stored.UpdatedAt = &at, at
	if attempt {
		r.stored.LastLoginAttempt = &at
	}
	return nil
}

const signInTestPassword = "Str0ng!Passw0rd"

func signInService(t *testing.T) (*authService, *signInUserRepo) {
	t.Helper()
	hash, err := auth.HashPassword(signInTestPassword)
	if err != nil {
		t.Fatalf("HashPassword: %v", err)
	}
	// A superadmin: no app membership is needed (#191), and AdminLogin
	// accepts it.
	repo := &signInUserRepo{stored: &model.User{ID: 21, Email: "signin@example.com", Name: "Before",
		HashedPassword: hash, IsVerified: true, Role: model.UserRoleSuperadmin, TokenVersion: 3}}
	// Meanwhile the user enrols MFA and renames the account.
	repo.meanwhile = func(u *model.User) {
		u.MFAEnabled, u.MFASecret, u.Name = true, "enrolled-secret", "After"
	}
	return &authService{
		userRepo:          repo,
		appRepo:           &crit02AppRepo{app: &model.App{ID: 1, ClientID: "admin-console-dev2", Active: true}},
		userAppRoleRepo:   &high04RoleRepo{role: nil},
		tokenService:      newTestTokenServiceForLockout(t),
		maxFailedAttempts: 5,
		lockoutDuration:   15 * time.Minute,
	}, repo
}

func TestSignIn_RecordsTheLoginWithoutAFullRowSave(t *testing.T) {
	for name, signIn := range map[string]func(s *authService) (*dto.LoginResponse, error){
		"login": func(s *authService) (*dto.LoginResponse, error) {
			return s.Login(context.Background(), dto.LoginRequest{Email: "signin@example.com", Password: signInTestPassword, AppClientID: "admin-console-dev2"})
		},
		"admin login": func(s *authService) (*dto.LoginResponse, error) {
			return s.AdminLogin(context.Background(), dto.AdminLoginRequest{Email: "signin@example.com", Password: signInTestPassword})
		},
	} {
		t.Run(name, func(t *testing.T) {
			s, repo := signInService(t)
			start := time.Now()
			resp, err := signIn(s)
			if err != nil || resp.AccessToken == "" {
				t.Fatalf("sign-in: %v", err)
			}
			if repo.fullSaves != 0 {
				t.Fatalf("the sign-in saved the whole user (%d Update calls)", repo.fullSaves)
			}
			if repo.recordLogins != 1 || !repo.attempt {
				t.Fatalf("RecordLogin calls %d (attempt %v), want 1 with the attempt time", repo.recordLogins, repo.attempt)
			}
			u := repo.stored
			if !u.MFAEnabled || u.MFASecret != "enrolled-secret" || u.Name != "After" {
				t.Fatalf("the sign-in undid a change made meanwhile: mfa %v, name %q", u.MFAEnabled, u.Name)
			}
			if u.LastLogin == nil || u.LastLogin.Before(start) || u.LastLoginAttempt == nil || !u.LastLoginAttempt.Equal(*u.LastLogin) {
				t.Fatalf("last_login %v, last_login_attempt %v; want both set to the sign-in time", u.LastLogin, u.LastLoginAttempt)
			}
			if u.TokenVersion != 3 {
				t.Fatalf("token version %d, want 3", u.TokenVersion)
			}
		})
	}
}

// A failure to record the sign-in time stays non-fatal.
func TestSignIn_RecordLoginFailureIsNotFatal(t *testing.T) {
	s, repo := signInService(t)
	s.userRepo = &failingRecordLoginRepo{repo}
	resp, err := s.Login(context.Background(), dto.LoginRequest{Email: "signin@example.com", Password: signInTestPassword, AppClientID: "admin-console-dev2"})
	if err != nil || resp.AccessToken == "" {
		t.Fatalf("login with RecordLogin failing: %v", err)
	}
	if repo.fullSaves != 0 {
		t.Fatalf("a failed RecordLogin fell back to a full-row save (%d Update calls)", repo.fullSaves)
	}
}

type failingRecordLoginRepo struct{ *signInUserRepo }

func (*failingRecordLoginRepo) RecordLogin(context.Context, uint, time.Time, bool) error {
	return errors.New("database unavailable")
}

func TestVerifyMagicLink_RecordsTheLoginWithoutAFullRowSave(t *testing.T) {
	svc, _, userRepo, appRepo, roleRepo, _ := buildMagicLinkService(t)
	app := &model.App{ID: 1, ClientID: "app-1", Name: "Test App", MagicLinkURL: &testMagicLanding, Active: true}
	appRepo.add(app)
	seedTestUser(userRepo, roleRepo, &model.User{ID: 10, Email: "alice@example.com", Name: "Alice", IsVerified: true}, app)

	rawToken, err := svc.RequestMagicLink(context.Background(), "alice@example.com", app)
	if err != nil {
		t.Fatalf("RequestMagicLink: %v", err)
	}
	start := time.Now()
	if _, err := svc.VerifyMagicLink(context.Background(), dto.MagicLinkVerifyRequest{Token: rawToken, ClientID: "app-1"}); err != nil {
		t.Fatalf("VerifyMagicLink: %v", err)
	}
	if userRepo.updates != 0 || userRepo.recordLogins != 1 {
		t.Fatalf("Update calls %d, RecordLogin calls %d; want 0 and 1", userRepo.updates, userRepo.recordLogins)
	}
	u := userRepo.byID[10]
	if u.LastLogin == nil || u.LastLogin.Before(start) {
		t.Fatalf("last_login %v, want the sign-in time", u.LastLogin)
	}
	if u.LastLoginAttempt != nil {
		t.Fatalf("a magic link set last_login_attempt (%v); it records only last_login", u.LastLoginAttempt)
	}
}
