package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/repository"
)

// lockoutUserRepo keeps the failed-attempt counter and lock of the users it
// holds, like the database does. The embedded nil interface fails loudly if
// any other method is called.
type lockoutUserRepo struct {
	repository.UserRepository
	users map[uint]*model.User
	locks int
}

func newLockoutUserRepo(us ...*model.User) *lockoutUserRepo {
	r := &lockoutUserRepo{users: map[uint]*model.User{}}
	for _, u := range us {
		cp := *u
		r.users[u.ID] = &cp
	}
	return r
}

func (r *lockoutUserRepo) FindByID(_ context.Context, id uint) (*model.User, error) {
	u, ok := r.users[id]
	if !ok {
		return nil, errors.New("record not found")
	}
	cp := *u
	return &cp, nil
}

func (r *lockoutUserRepo) IncrementFailedLoginAttempts(_ context.Context, id uint) error {
	u, ok := r.users[id]
	if !ok {
		return errors.New("record not found")
	}
	u.FailedLoginAttempts++
	return nil
}

func (r *lockoutUserRepo) LockAccount(_ context.Context, id uint, until *time.Time) error {
	u, ok := r.users[id]
	if !ok {
		return errors.New("record not found")
	}
	r.locks++
	u.LockedUntil = until
	return nil
}

func lockoutService(stub *stubMFAVerifier, repo *lockoutUserRepo) *authService {
	return &authService{mfa: stub, userRepo: repo, maxFailedAttempts: 3, lockoutDuration: 15 * time.Minute}
}

// A wrong second-factor code counts on the same per-account counter as a wrong
// password, and the account is locked when the counter reaches the limit.
func TestStepUpMFA_WrongCodesLockTheAccount(t *testing.T) {
	stub := &stubMFAVerifier{verifyErr: ErrMFAInvalidCode}
	user := &model.User{ID: 7, Email: "u@example.com", MFAEnabled: true}
	repo := newLockoutUserRepo(user)
	s := lockoutService(stub, repo)

	for i := 1; i <= 2; i++ {
		u, _ := repo.FindByID(context.Background(), 7)
		if err := s.stepUpMFA(context.Background(), u, "000000"); !errors.Is(err, ErrMFAInvalidCode) {
			t.Fatalf("attempt %d: %v, want ErrMFAInvalidCode", i, err)
		}
		if got := repo.users[7].FailedLoginAttempts; got != i {
			t.Fatalf("attempt %d: counter %d, want %d", i, got, i)
		}
	}
	u, _ := repo.FindByID(context.Background(), 7)
	if err := s.stepUpMFA(context.Background(), u, "000000"); !errors.Is(err, ErrAccountLocked) {
		t.Fatalf("third wrong code: %v, want ErrAccountLocked", err)
	}
	if repo.locks != 1 || repo.users[7].LockedUntil == nil || !repo.users[7].IsLocked() {
		t.Fatalf("account not locked: locks=%d until=%v", repo.locks, repo.users[7].LockedUntil)
	}

	// Once locked, no code is checked, a right one included.
	stub.verifyErr, stub.verifyHit, stub.redeemHit = nil, false, false
	u, _ = repo.FindByID(context.Background(), 7)
	if err := s.stepUpMFA(context.Background(), u, "123456"); !errors.Is(err, ErrAccountLocked) {
		t.Fatalf("locked account: %v, want ErrAccountLocked", err)
	}
	if stub.verifyHit || stub.redeemHit {
		t.Error("a locked account must be refused before any code is checked")
	}
}

// The counter is shared with wrong passwords: earlier password failures count
// toward the limit reached by a wrong code.
func TestStepUpMFA_CounterIsSharedWithPasswordFailures(t *testing.T) {
	stub := &stubMFAVerifier{verifyErr: ErrMFAInvalidCode}
	user := &model.User{ID: 8, MFAEnabled: true, FailedLoginAttempts: 2}
	repo := newLockoutUserRepo(user)
	s := lockoutService(stub, repo)
	if err := s.stepUpMFA(context.Background(), user, "000000"); !errors.Is(err, ErrAccountLocked) {
		t.Fatalf("%v, want ErrAccountLocked (2 password failures + 1 wrong code = limit 3)", err)
	}
	if got := repo.users[8]; got.FailedLoginAttempts != 3 || repo.locks != 1 || !got.IsLocked() {
		t.Fatalf("stored state: counter %d, locks %d, locked %v; want 3, 1, true",
			got.FailedLoginAttempts, repo.locks, got.IsLocked())
	}
}

// Neither a valid code, a missing code, a redeemed recovery code, a
// recovery-store error nor a failure to check the TOTP code counts as a
// failed attempt (each is still refused when it is not a valid code).
func TestStepUpMFA_OnlyAWrongCodeCounts(t *testing.T) {
	for name, tc := range map[string]struct {
		stub    *stubMFAVerifier
		wantErr error
	}{
		"valid TOTP":     {&stubMFAVerifier{}, nil},
		"recovery code":  {&stubMFAVerifier{verifyErr: ErrMFAInvalidCode, redeemOK: true}, nil},
		"recovery error": {&stubMFAVerifier{verifyErr: ErrMFAInvalidCode, redeemErr: errors.New("db down")}, ErrMFAInvalidCode},
		"verifier error": {&stubMFAVerifier{verifyErr: errors.New("decrypt failed")}, ErrMFAInvalidCode},
	} {
		repo := newLockoutUserRepo(&model.User{ID: 9, MFAEnabled: true})
		u, _ := repo.FindByID(context.Background(), 9)
		err := lockoutService(tc.stub, repo).stepUpMFA(context.Background(), u, "123456")
		if (tc.wantErr == nil && err != nil) || (tc.wantErr != nil && !errors.Is(err, tc.wantErr)) {
			t.Errorf("%s: error %v, want %v", name, err, tc.wantErr)
		}
		if got := repo.users[9].FailedLoginAttempts; got != 0 {
			t.Errorf("%s: counter %d, want 0", name, got)
		}
	}
	repo := newLockoutUserRepo(&model.User{ID: 9, MFAEnabled: true})
	u, _ := repo.FindByID(context.Background(), 9)
	if err := lockoutService(&stubMFAVerifier{}, repo).stepUpMFA(context.Background(), u, " "); !errors.Is(err, ErrMFARequired) {
		t.Fatalf("missing code: %v, want ErrMFARequired", err)
	}
	if got := repo.users[9].FailedLoginAttempts; got != 0 {
		t.Errorf("missing code: counter %d, want 0", got)
	}
}
