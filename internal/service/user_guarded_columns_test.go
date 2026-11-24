package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/repository"
	"golang.org/x/crypto/bcrypt"
)

// The token version and the lockout columns are written only by targeted
// statements (UserRepository.Update leaves them out). These tests check that
// the paths that change them use those statements, not Update.

// guardedOnlyRepo implements FindByID, SetPassword and
// ResetFailedLoginAttempts. Any other call, Update and IncrementTokenVersion
// included, panics on the nil embedded interface.
type guardedOnlyRepo struct {
	repository.UserRepository
	user      *model.User
	passwords []repository.PasswordChange
	resets    int
}

func (r *guardedOnlyRepo) FindByID(_ context.Context, id uint) (*model.User, error) {
	if r.user == nil || r.user.ID != id {
		return nil, errors.New("record not found")
	}
	cp := *r.user
	return &cp, nil
}

func (r *guardedOnlyRepo) SetPassword(_ context.Context, _ uint, c repository.PasswordChange) error {
	r.passwords = append(r.passwords, c)
	return nil
}

func (r *guardedOnlyRepo) ResetFailedLoginAttempts(_ context.Context, _ uint) error {
	r.resets++
	return nil
}

// An admin's password reset for a user stores the new hash and revokes the
// sessions in one write, and leaves the forced-change flag as it is.
func TestUserService_UpdatePassword_RevokesInTheSameWrite(t *testing.T) {
	repo := &guardedOnlyRepo{user: &model.User{ID: 4, MustChangePassword: true}}
	if err := NewUserService(repo).UpdatePassword(context.Background(), 4, "A-new-Passw0rd!x"); err != nil {
		t.Fatal(err)
	}
	if len(repo.passwords) != 1 {
		t.Fatalf("SetPassword called %d times, want 1", len(repo.passwords))
	}
	c := repo.passwords[0]
	if bcrypt.CompareHashAndPassword([]byte(c.HashedPassword), []byte("A-new-Passw0rd!x")) != nil {
		t.Fatal("the new password is not the one stored")
	}
	if c.ClearMustChangePassword || c.ChangedAt != nil {
		t.Fatalf("UpdatePassword changed more than the password: %+v", c)
	}
}

// Unlocking clears the counter and the lock with the targeted reset.
func TestUserService_Unlock_UsesTheTargetedReset(t *testing.T) {
	until := time.Now().Add(time.Hour)
	repo := &guardedOnlyRepo{user: &model.User{ID: 4, FailedLoginAttempts: 5, LockedUntil: &until}}
	if err := NewUserService(repo).Unlock(context.Background(), 4); err != nil {
		t.Fatal(err)
	}
	if repo.resets != 1 {
		t.Fatalf("ResetFailedLoginAttempts called %d times, want 1", repo.resets)
	}
	if err := NewUserService(repo).Unlock(context.Background(), 99); err == nil {
		t.Fatal("unlocking an unknown user must fail")
	}
}

// A password change whose write fails is refused and changes nothing: the
// old password still works and no session is left half-revoked.
func TestChangePassword_FailedWriteChangesNothing(t *testing.T) {
	repo := newLockoutUserRepo(lockoutTestUser(t, model.UserRoleUser))
	before := *repo.users[5]
	repo.setPasswordErr = errors.New("db down")
	s := &authService{userRepo: repo, maxFailedAttempts: 3, lockoutDuration: 15 * time.Minute, auditRepo: &captureAuditRepo{}}
	if err := s.ChangePassword(context.Background(), 5, lockoutTestPassword, "Another-Password-2!"); err == nil {
		t.Fatal("a failed write must be reported")
	}
	u := repo.users[5]
	if u.HashedPassword != before.HashedPassword || u.TokenVersion != before.TokenVersion {
		t.Fatal("a failed write must change neither the password nor the token version")
	}
}
