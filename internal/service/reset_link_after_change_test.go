package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/repository"
	"github.com/ovander/go-oauth2/internal/shared/auth"
)

// #366: a password-reset link issued before the password last changed no
// longer resets it; one issued after does.
func TestResetPassword_LinkOlderThanThePasswordIsRefused(t *testing.T) {
	user := lockoutTestUser(t, model.UserRoleUser)
	repo := newLockoutUserRepo(user)
	km, err := auth.NewKeyManager(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ts := auth.NewTokenService(km, auth.TokenConfig{Issuer: "https://auth.example.com", AccessTokenTTL: time.Hour, ResetTokenTTL: time.Hour})
	s := &authService{userRepo: repo, tokenService: ts, auditRepo: &captureAuditRepo{}}

	link, err := s.tokenService.GeneratePasswordResetToken(user.Email, user.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	// The password changes after the link was issued (another reset, the
	// user, or an admin).
	later := time.Now().Add(2 * time.Second)
	repo.users[5].PasswordChangedAt = &later
	if err := s.ResetPassword(context.Background(), link, "A-New-Password-9!"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("old link: %v, want ErrInvalidToken", err)
	}
	if repo.users[5].HashedPassword != user.HashedPassword {
		t.Fatal("the old link changed the password")
	}

	// A link issued after the change works.
	earlier := time.Now().Add(-time.Hour)
	repo.users[5].PasswordChangedAt = &earlier
	fresh, err := s.tokenService.GeneratePasswordResetToken(user.Email, user.ID, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := s.ResetPassword(context.Background(), fresh, "A-New-Password-9!"); err != nil {
		t.Fatalf("fresh link: %v", err)
	}
	// And the reset it made retires every link issued before it: the first
	// link, checked again, is refused.
	if repo.users[5].PasswordChangedAt == nil || !repo.users[5].PasswordChangedAt.After(earlier) {
		t.Fatalf("the reset did not record its time: %v", repo.users[5].PasswordChangedAt)
	}
	stamped := *repo.users[5].PasswordChangedAt
	later = stamped.Add(2 * time.Second) // keep the stored change clearly after the first link
	repo.users[5].PasswordChangedAt = &later
	if err := s.ResetPassword(context.Background(), link, "Yet-Another-Password-7!"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("first link after the reset: %v, want ErrInvalidToken", err)
	}
}

func resetTestService(t *testing.T) (*authService, *lockoutUserRepo) {
	t.Helper()
	user := lockoutTestUser(t, model.UserRoleUser)
	repo := newLockoutUserRepo(user)
	km, err := auth.NewKeyManager(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ts := auth.NewTokenService(km, auth.TokenConfig{Issuer: "https://auth.example.com", AccessTokenTTL: time.Hour, ResetTokenTTL: time.Hour})
	return &authService{userRepo: repo, tokenService: ts, auditRepo: &captureAuditRepo{}}, repo
}

// iat has one-second precision: a link requested in the same second as a
// password change, after it, must still work.
func TestResetPassword_LinkInTheSameSecondAsAChangeWorks(t *testing.T) {
	s, repo := resetTestService(t)
	link, err := s.tokenService.GeneratePasswordResetToken("lock@example.com", 5, nil)
	if err != nil {
		t.Fatal(err)
	}
	claims, err := s.tokenService.VerifyEmailToken(link)
	if err != nil {
		t.Fatal(err)
	}
	// The change happened 100 ms into the second the link carries.
	changed := claims.IssuedAt.Add(100 * time.Millisecond)
	repo.users[5].PasswordChangedAt = &changed
	if err := s.ResetPassword(context.Background(), link, "A-New-Password-9!"); err != nil {
		t.Fatalf("link of the same second: %v", err)
	}
}

// A change that lands between the link's check and the write wins: the store
// refuses the guarded write, and the link is refused.
func TestResetPassword_ConcurrentChangeIsNotOverwritten(t *testing.T) {
	s, repo := resetTestService(t)
	link, err := s.tokenService.GeneratePasswordResetToken("lock@example.com", 5, nil)
	if err != nil {
		t.Fatal(err)
	}
	repo.setPasswordErr = repository.ErrPasswordChangedMeanwhile
	if err := s.ResetPassword(context.Background(), link, "A-New-Password-9!"); !errors.Is(err, ErrInvalidToken) {
		t.Fatalf("concurrent change: %v, want ErrInvalidToken", err)
	}
}
