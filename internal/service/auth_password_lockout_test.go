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
	"golang.org/x/crypto/bcrypt"
)

// Every password check — login, admin login, re-authentication (/elevate) and
// change password — counts a wrong password on the same per-account counter,
// locks the account at the limit, and refuses a locked account even with the
// right password.

func (r *lockoutUserRepo) FindByEmail(_ context.Context, email string) (*model.User, error) {
	for _, u := range r.users {
		if u.Email == email {
			cp := *u
			return &cp, nil
		}
	}
	return nil, errors.New("record not found")
}

func (r *lockoutUserRepo) ResetFailedLoginAttempts(_ context.Context, id uint) error {
	u, ok := r.users[id]
	if !ok {
		return errors.New("record not found")
	}
	u.FailedLoginAttempts = 0
	u.LockedUntil = nil
	return nil
}

// Update saves the row except the columns the GORM repository leaves to
// targeted statements (token version, lockout, last TOTP step).
func (r *lockoutUserRepo) Update(_ context.Context, u *model.User) error {
	cp := *u
	if s, ok := r.users[u.ID]; ok {
		cp.TokenVersion, cp.FailedLoginAttempts, cp.LockedUntil, cp.MFALastStep =
			s.TokenVersion, s.FailedLoginAttempts, s.LockedUntil, s.MFALastStep
	}
	r.users[u.ID] = &cp
	return nil
}

// RecordLogin writes the sign-in times and updated_at, and nothing else, like
// the repository.
func (r *lockoutUserRepo) RecordLogin(_ context.Context, id uint, at time.Time, attempt bool) error {
	u, ok := r.users[id]
	if !ok {
		return errors.New("record not found")
	}
	u.LastLogin, u.UpdatedAt = &at, at
	if attempt {
		u.LastLoginAttempt = &at
	}
	return nil
}

// SetPassword stores the hash and increments the token version together, or
// fails with setPasswordErr and changes nothing.
func (r *lockoutUserRepo) SetPassword(_ context.Context, id uint, c repository.PasswordChange) error {
	if r.setPasswordErr != nil {
		return r.setPasswordErr
	}
	u, ok := r.users[id]
	if !ok {
		return errors.New("record not found")
	}
	u.HashedPassword = c.HashedPassword
	if c.ClearMustChangePassword {
		u.MustChangePassword = false
	}
	if c.ChangedAt != nil {
		u.PasswordChangedAt = c.ChangedAt
	}
	u.TokenVersion++
	return nil
}

func (r *lockoutUserRepo) IncrementTokenVersion(_ context.Context, id uint) error {
	u, ok := r.users[id]
	if !ok {
		return errors.New("record not found")
	}
	u.TokenVersion++
	return nil
}

const lockoutTestPassword = "Right-Password-1"

func lockoutTestUser(t *testing.T, role model.UserRole) *model.User {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(lockoutTestPassword), bcrypt.MinCost)
	if err != nil {
		t.Fatal(err)
	}
	return &model.User{ID: 5, Email: "lock@example.com", HashedPassword: string(h), IsVerified: true, Role: role}
}

func TestPasswordLockout_EveryPath(t *testing.T) {
	type attempt func(s *authService, password string) error
	for name, tc := range map[string]struct {
		role model.UserRole
		try  attempt
	}{
		"login": {model.UserRoleUser, func(s *authService, pw string) error {
			_, err := s.Login(context.Background(), dto.LoginRequest{Email: "lock@example.com", Password: pw, AppClientID: "app"})
			return err
		}},
		"admin login": {model.UserRoleSuperadmin, func(s *authService, pw string) error {
			_, err := s.AdminLogin(context.Background(), dto.AdminLoginRequest{Email: "lock@example.com", Password: pw})
			return err
		}},
		"re-authentication": {model.UserRoleSuperadmin, func(s *authService, pw string) error {
			_, err := s.ReAuthenticate(context.Background(), 5, pw, "")
			return err
		}},
		"change password": {model.UserRoleSuperadmin, func(s *authService, pw string) error {
			return s.ChangePassword(context.Background(), 5, pw, "Another-Password-2!")
		}},
		// The hosted account page's sign-in (ACCOUNT_SECURITY_PAGE).
		"account page": {model.UserRoleUser, func(s *authService, pw string) error {
			_, err := s.AuthenticateAccount(context.Background(), "lock@example.com", pw, "")
			return err
		}},
	} {
		t.Run(name, func(t *testing.T) {
			repo := newLockoutUserRepo(lockoutTestUser(t, tc.role))
			s := &authService{userRepo: repo, maxFailedAttempts: 3, lockoutDuration: 15 * time.Minute, auditRepo: &captureAuditRepo{}}
			for i := 1; i <= 2; i++ {
				if err := tc.try(s, "wrong"); !errors.Is(err, ErrInvalidCredentials) {
					t.Fatalf("wrong password %d: %v, want ErrInvalidCredentials", i, err)
				}
				if got := repo.users[5].FailedLoginAttempts; got != i {
					t.Fatalf("after %d wrong passwords the counter is %d", i, got)
				}
			}
			// The attempt that locks the account is answered like any wrong
			// password: "locked" would show that the email names an account.
			if err := tc.try(s, "wrong"); !errors.Is(err, ErrInvalidCredentials) || errors.Is(err, ErrAccountLocked) {
				t.Fatalf("third wrong password: %v, want ErrInvalidCredentials", err)
			}
			if !repo.users[5].IsLocked() {
				t.Fatal("account not locked")
			}
			audit := s.auditRepo.(*captureAuditRepo)
			if audit.last == nil || audit.last.EventType != model.SecurityEventAccountLocked {
				t.Fatalf("the lock was not audited: %+v", audit.last)
			}
			// While locked, a wrong password gets the answer an unknown
			// email gets: the lock is not revealed to someone without the
			// password. It is audited, and does not move the counter.
			counter := repo.users[5].FailedLoginAttempts
			if err := tc.try(s, "wrong"); !errors.Is(err, ErrInvalidCredentials) || errors.Is(err, ErrAccountLocked) {
				t.Fatalf("wrong password on a locked account: %v, want ErrInvalidCredentials", err)
			}
			if repo.users[5].FailedLoginAttempts != counter {
				t.Fatalf("counter moved while locked: %d → %d", counter, repo.users[5].FailedLoginAttempts)
			}
			if audit.last == nil || audit.last.EventType != model.SecurityEventLoginFailed || audit.last.Details["account_locked"] != true {
				t.Fatalf("the attempt on a locked account was not audited: %+v", audit.last)
			}
			if audit.last.Details["password_verified"] != false {
				t.Fatalf("a wrong password on a locked account audited password_verified %v", audit.last.Details["password_verified"])
			}
			// The right password learns about the lock, and is audited too:
			// whoever typed it knows the credential.
			audit.last = nil
			if err := tc.try(s, lockoutTestPassword); !errors.Is(err, ErrAccountLocked) {
				t.Fatalf("right password on a locked account: %v, want ErrAccountLocked", err)
			}
			if audit.last == nil || audit.last.EventType != model.SecurityEventLoginFailed ||
				audit.last.Details["account_locked"] != true || audit.last.Details["password_verified"] != true {
				t.Fatalf("the right password on a locked account was not audited: %+v", audit.last)
			}
		})
	}
}

// A successful re-authentication or password change resets the counter.
func TestPasswordLockout_SuccessResets(t *testing.T) {
	for name, ok := range map[string]func(s *authService) error{
		"re-authentication": func(s *authService) error {
			_, err := s.ReAuthenticate(context.Background(), 5, lockoutTestPassword, "")
			return err
		},
		"change password": func(s *authService) error {
			return s.ChangePassword(context.Background(), 5, lockoutTestPassword, "Another-Password-2!")
		},
	} {
		t.Run(name, func(t *testing.T) {
			u := lockoutTestUser(t, model.UserRoleSuperadmin)
			u.FailedLoginAttempts = 2
			repo := newLockoutUserRepo(u)
			s := &authService{userRepo: repo, maxFailedAttempts: 3, lockoutDuration: 15 * time.Minute, auditRepo: &captureAuditRepo{}, tokenService: newTestTokenServiceForLockout(t)}
			if err := ok(s); err != nil {
				t.Fatalf("right password: %v", err)
			}
			if got := repo.users[5].FailedLoginAttempts; got != 0 {
				t.Fatalf("counter %d after success, want 0", got)
			}
		})
	}
}

// A successful password change stores the new password and revokes the
// user's tokens.
func TestPasswordLockout_ChangePasswordChangesIt(t *testing.T) {
	repo := newLockoutUserRepo(lockoutTestUser(t, model.UserRoleSuperadmin))
	s := &authService{userRepo: repo, maxFailedAttempts: 3, lockoutDuration: 15 * time.Minute, auditRepo: &captureAuditRepo{}}
	if err := s.ChangePassword(context.Background(), 5, lockoutTestPassword, "Another-Password-2!"); err != nil {
		t.Fatal(err)
	}
	u := repo.users[5]
	if bcrypt.CompareHashAndPassword([]byte(u.HashedPassword), []byte("Another-Password-2!")) != nil {
		t.Fatal("the new password was not stored")
	}
	if u.TokenVersion != 1 {
		t.Fatalf("token version %d, want 1 (tokens revoked)", u.TokenVersion)
	}
}

func newTestTokenServiceForLockout(t *testing.T) *auth.TokenService {
	t.Helper()
	km, err := auth.NewKeyManager(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	return auth.NewTokenService(km, auth.TokenConfig{Issuer: "https://auth.example.com", AccessTokenTTL: time.Hour, RefreshTokenTTL: time.Hour})
}
