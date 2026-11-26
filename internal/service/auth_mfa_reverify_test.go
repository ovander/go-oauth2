package service

import (
	"context"
	"errors"
	"testing"

	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/shared/auth"
)

// P3-9 and the v1.14.2 audit (H-2): disabling MFA re-proves the account, and
// a wrong password or code counts toward the lockout as on every sign-in path,
// so a stolen access token is not a way to guess them without limit.

func reverifyFixture(t *testing.T, stub *stubMFAVerifier, user *model.User) (*authService, *lockoutUserRepo) {
	t.Helper()
	repo := newLockoutUserRepo(user)
	return lockoutService(stub, repo), repo
}

func hashed(t *testing.T, password string) string {
	t.Helper()
	h, err := auth.HashPassword(password)
	if err != nil {
		t.Fatal(err)
	}
	return h
}

func TestReverifyForMFAChange_WrongCodesLockTheAccount(t *testing.T) {
	const pw = "Correct-Horse-1!"
	stub := &stubMFAVerifier{verifyErr: ErrMFAInvalidCode}
	s, repo := reverifyFixture(t, stub, &model.User{ID: 7, MFAEnabled: true, HashedPassword: hashed(t, pw)})
	password := pw
	for i := 1; i <= 2; i++ {
		if err := s.ReverifyForMFAChange(context.Background(), 7, &password, "000000"); !errors.Is(err, ErrMFAInvalidCode) {
			t.Fatalf("attempt %d: %v, want ErrMFAInvalidCode", i, err)
		}
	}
	if err := s.ReverifyForMFAChange(context.Background(), 7, &password, "000000"); !errors.Is(err, ErrAccountLocked) {
		t.Fatalf("third wrong code: %v, want ErrAccountLocked", err)
	}
	if !repo.users[7].IsLocked() {
		t.Fatal("the account is not locked after the limit")
	}
	// Locked: nothing more is checked, the right password and code included.
	stub.verifyErr, stub.verifyHit, stub.redeemHit = nil, false, false
	if err := s.ReverifyForMFAChange(context.Background(), 7, &password, "123456"); !errors.Is(err, ErrAccountLocked) {
		t.Fatalf("locked account: %v, want ErrAccountLocked", err)
	}
	if stub.verifyHit || stub.redeemHit {
		t.Error("a locked account must be refused before any code is checked")
	}
}

func TestReverifyForMFAChange_WrongPasswordCountsAndChecksNoCode(t *testing.T) {
	stub := &stubMFAVerifier{}
	s, repo := reverifyFixture(t, stub, &model.User{ID: 7, MFAEnabled: true, HashedPassword: hashed(t, "Correct-Horse-1!")})
	wrong := "wrong"
	if err := s.ReverifyForMFAChange(context.Background(), 7, &wrong, "123456"); !errors.Is(err, ErrInvalidCredentials) {
		t.Fatalf("wrong password: %v, want ErrInvalidCredentials", err)
	}
	if repo.users[7].FailedLoginAttempts != 1 {
		t.Errorf("counter %d, want 1", repo.users[7].FailedLoginAttempts)
	}
	if stub.verifyHit {
		t.Error("the code was checked after a wrong password")
	}
}

func TestReverifyForMFAChange_Succeeds(t *testing.T) {
	const pw = "Correct-Horse-1!"
	for name, tc := range map[string]struct {
		user     *model.User
		password *string
		stub     *stubMFAVerifier
	}{
		"password and TOTP": {&model.User{ID: 7, MFAEnabled: true, HashedPassword: hashed(t, pw)}, func() *string { p := pw; return &p }(), &stubMFAVerifier{}},
		"recovery code":     {&model.User{ID: 7, MFAEnabled: true, HashedPassword: hashed(t, pw)}, func() *string { p := pw; return &p }(), &stubMFAVerifier{verifyErr: ErrMFAInvalidCode, redeemOK: true}},
		// The hosted account page: its session already proves the password.
		"no password asked": {&model.User{ID: 7, MFAEnabled: true, HashedPassword: hashed(t, pw)}, nil, &stubMFAVerifier{}},
		// An account created by an invite or a magic link may have none.
		"passwordless account": {&model.User{ID: 7, MFAEnabled: true}, func() *string { p := ""; return &p }(), &stubMFAVerifier{}},
	} {
		s, repo := reverifyFixture(t, tc.stub, tc.user)
		repo.users[7].FailedLoginAttempts = 1
		if err := s.ReverifyForMFAChange(context.Background(), 7, tc.password, "123456"); err != nil {
			t.Errorf("%s: %v", name, err)
		}
		// Not a sign-in: the counter is left as it was.
		if got := repo.users[7].FailedLoginAttempts; got != 1 {
			t.Errorf("%s: counter %d, want 1", name, got)
		}
	}
}

func TestReverifyForMFAChange_LockedWithoutPasswordIsRefused(t *testing.T) {
	stub := &stubMFAVerifier{}
	s, repo := reverifyFixture(t, stub, &model.User{ID: 7, MFAEnabled: true, FailedLoginAttempts: 3})
	// Lock it the way the service does.
	u, _ := repo.FindByID(context.Background(), 7)
	if locked, _ := s.countFailedAttempt(context.Background(), u); !locked {
		t.Fatal("fixture: the account did not lock")
	}
	if err := s.ReverifyForMFAChange(context.Background(), 7, nil, "123456"); !errors.Is(err, ErrAccountLocked) {
		t.Fatalf("%v, want ErrAccountLocked", err)
	}
	if stub.verifyHit {
		t.Error("a locked account's code was checked")
	}
}

func TestReverifyForMFAChange_FailsClosed(t *testing.T) {
	s, _ := reverifyFixture(t, &stubMFAVerifier{}, &model.User{ID: 7})
	if err := s.ReverifyForMFAChange(context.Background(), 7, nil, "123456"); !errors.Is(err, ErrMFANotEnrolled) {
		t.Errorf("MFA not enabled: %v, want ErrMFANotEnrolled", err)
	}
	if err := s.ReverifyForMFAChange(context.Background(), 99, nil, "123456"); !errors.Is(err, ErrUserNotFound) {
		t.Errorf("unknown user: %v, want ErrUserNotFound", err)
	}
	noMFA := &authService{userRepo: newLockoutUserRepo(&model.User{ID: 7, MFAEnabled: true})}
	if err := noMFA.ReverifyForMFAChange(context.Background(), 7, nil, "123456"); err == nil {
		t.Error("no MFA verifier wired: accepted")
	}
}
