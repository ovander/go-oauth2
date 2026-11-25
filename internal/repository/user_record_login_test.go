package repository_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/ovander/go-oauth2/internal/database/migrate"
	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/repository"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// A sign-in loads the user, checks the password and the second factor, then
// records the sign-in time. RecordLogin writes the sign-in times and nothing
// else, so a password change, a session revocation or an MFA enrolment that
// lands in between is kept.
func TestUserRepository_RecordLoginWritesOnlyTheSignInTimes(t *testing.T) {
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping the Postgres integration test")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	if err := migrate.Run(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	tx := db.Begin()
	if tx.Error != nil {
		t.Fatalf("begin: %v", tx.Error)
	}
	t.Cleanup(func() { tx.Rollback() })
	repo := repository.NewUserRepository(tx)
	ctx := context.Background()

	u := &model.User{Email: fmt.Sprintf("record-login-%d@example.test", time.Now().UnixNano()), Name: "Record",
		HashedPassword: "old-hash", Source: "manual", Role: model.UserRoleUser, MustChangePassword: true}
	if err := repo.Create(ctx, u); err != nil {
		t.Fatalf("create: %v", err)
	}
	stored := func() *model.User {
		got, err := repo.FindByID(ctx, u.ID)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}

	// Loaded by a sign-in with the old password, before the changes below.
	stale := stored()

	// Meanwhile: the user changes the password (new hash and token version
	// in one statement) and enrols MFA (a save of a fresh copy).
	changedAt := time.Now().Truncate(time.Microsecond)
	if err := repo.SetPassword(ctx, u.ID, repository.PasswordChange{HashedPassword: "new-hash",
		ClearMustChangePassword: true, ChangedAt: &changedAt}); err != nil {
		t.Fatalf("set password: %v", err)
	}
	fresh := stored()
	fresh.MFAEnabled, fresh.MFASecret = true, "enrolled-secret"
	if err := repo.Update(ctx, fresh); err != nil {
		t.Fatalf("enrol mfa: %v", err)
	}
	before := stored()

	// The sign-in now records its time.
	at := time.Now().Add(time.Second).Truncate(time.Microsecond)
	if err := repo.RecordLogin(ctx, stale.ID, at, true); err != nil {
		t.Fatalf("record login: %v", err)
	}
	got := stored()
	if got.HashedPassword != "new-hash" || got.MustChangePassword || got.PasswordChangedAt == nil {
		t.Fatalf("the sign-in restored the old password state: hash new %v, must_change %v, changed_at %v",
			got.HashedPassword == "new-hash", got.MustChangePassword, got.PasswordChangedAt)
	}
	if got.TokenVersion != before.TokenVersion || got.TokenVersion != stale.TokenVersion+1 {
		t.Fatalf("token version %d, want %d (the password change's)", got.TokenVersion, stale.TokenVersion+1)
	}
	if !got.MFAEnabled || got.MFASecret != "enrolled-secret" {
		t.Fatalf("the sign-in undid the MFA enrolment: enabled %v, secret kept %v", got.MFAEnabled, got.MFASecret == "enrolled-secret")
	}
	if got.LastLogin == nil || !got.LastLogin.Equal(at) {
		t.Fatalf("last_login %v, want %v", got.LastLogin, at)
	}
	if got.LastLoginAttempt == nil || !got.LastLoginAttempt.Equal(at) {
		t.Fatalf("last_login_attempt %v, want %v", got.LastLoginAttempt, at)
	}
	if !got.UpdatedAt.Equal(at) {
		t.Fatalf("updated_at %v, want %v", got.UpdatedAt, at)
	}

	// Without attempt, last_login_attempt is left alone.
	later := at.Add(time.Minute)
	if err := repo.RecordLogin(ctx, u.ID, later, false); err != nil {
		t.Fatalf("record login without attempt: %v", err)
	}
	got = stored()
	if got.LastLogin == nil || !got.LastLogin.Equal(later) || !got.LastLoginAttempt.Equal(at) {
		t.Fatalf("last_login %v (want %v), last_login_attempt %v (want %v)", got.LastLogin, later, got.LastLoginAttempt, at)
	}

	// A user deleted since it was read stays deleted.
	if err := repo.Delete(ctx, u.ID); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := repo.RecordLogin(ctx, u.ID, later, true); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("record login of a deleted user: %v, want gorm.ErrRecordNotFound", err)
	}
	if _, err := repo.FindByID(ctx, u.ID); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("the deleted user is back: %v", err)
	}
}
