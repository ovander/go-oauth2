package main

import (
	"testing"
	"time"

	"github.com/ovander/go-oauth2/internal/model"
)

// seed -force resets the superadmin's password: like any password change,
// it ends the reset links issued before (#366).
func TestApplyForcedReset(t *testing.T) {
	old := time.Now().Add(-48 * time.Hour)
	u := &model.User{Name: "Old", HashedPassword: "old-hash", Role: model.UserRoleUser, PasswordChangedAt: &old}
	now := time.Now()
	applyForcedReset(u, "Admin", "new-hash", now)
	if u.PasswordChangedAt == nil || !u.PasswordChangedAt.Equal(now) {
		t.Fatalf("PasswordChangedAt = %v, want %v: earlier reset links would stay valid", u.PasswordChangedAt, now)
	}
	if u.Name != "Admin" || u.HashedPassword != "new-hash" || u.Role != model.UserRoleSuperadmin ||
		!u.IsVerified || !u.MustChangePassword || u.ConfirmedAt == nil {
		t.Errorf("reset account = %+v", u)
	}
}
