package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ovander/go-oauth2/internal/model"
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
	// And the reset it made retires every link issued before it.
	if repo.users[5].PasswordChangedAt == nil || !repo.users[5].PasswordChangedAt.After(earlier) {
		t.Fatalf("the reset did not record its time: %v", repo.users[5].PasswordChangedAt)
	}
}
