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

// A save of a user loaded before a password change does not restore the old
// password: Update never writes the password columns, which only SetPassword
// (and UpdateProfile) change. SetPassword can also mark the user verified.
func TestUserRepository_UpdateKeepsThePassword(t *testing.T) {
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

	u := &model.User{Email: fmt.Sprintf("password-%d@example.test", time.Now().UnixNano()), Name: "Password",
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

	// Loaded before the password change, as a sign-in loads the user before
	// it saves the last-login time.
	stale := stored()
	changedAt := time.Now().Truncate(time.Microsecond)
	confirmedAt := changedAt
	if err := repo.SetPassword(ctx, u.ID, repository.PasswordChange{HashedPassword: "new-hash",
		ClearMustChangePassword: true, ChangedAt: &changedAt, ConfirmedAt: &confirmedAt}); err != nil {
		t.Fatalf("set password: %v", err)
	}
	got := stored()
	if !got.IsVerified || got.ConfirmedAt == nil {
		t.Fatalf("verified %v, confirmed_at %v; want true and set", got.IsVerified, got.ConfirmedAt)
	}

	stale.LastLogin = &changedAt
	if err := repo.Update(ctx, stale); err != nil {
		t.Fatalf("stale save: %v", err)
	}
	got = stored()
	if got.HashedPassword != "new-hash" || got.MustChangePassword || got.PasswordChangedAt == nil {
		t.Fatalf("a stale save restored the old password state: hash new %v, must_change %v, changed_at %v",
			got.HashedPassword == "new-hash", got.MustChangePassword, got.PasswordChangedAt)
	}
	if got.LastLogin == nil {
		t.Fatal("the stale save did not write its own change")
	}

	// Setting the password fields on the struct does not write them.
	got.HashedPassword, got.MustChangePassword = "ignored", true
	if err := repo.Update(ctx, got); err != nil {
		t.Fatalf("update: %v", err)
	}
	if after := stored(); after.HashedPassword != "new-hash" || after.MustChangePassword {
		t.Fatal("Update wrote a password column")
	}
}

// #366: a guarded SetPassword writes only if password_changed_at still holds
// the value the caller read, so a reset link checked against the last change
// cannot overwrite a change that landed meanwhile.
func TestUserRepository_SetPasswordGuard(t *testing.T) {
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
	tx := db.Begin()
	if tx.Error != nil {
		t.Fatalf("begin: %v", tx.Error)
	}
	t.Cleanup(func() { tx.Rollback() })
	repo := repository.NewUserRepository(tx)
	ctx := context.Background()

	u := &model.User{Email: fmt.Sprintf("guard-%d@example.test", time.Now().UnixNano()), Name: "Guard",
		HashedPassword: "first", Source: "manual", Role: model.UserRoleUser}
	if err := repo.Create(ctx, u); err != nil {
		t.Fatalf("create: %v", err)
	}
	hash := func() string {
		got, err := repo.FindByID(ctx, u.ID)
		if err != nil {
			t.Fatal(err)
		}
		return got.HashedPassword
	}

	// Never changed: a guard expecting NULL writes.
	first := time.Now().Truncate(time.Microsecond)
	if err := repo.SetPassword(ctx, u.ID, repository.PasswordChange{HashedPassword: "second", ChangedAt: &first,
		OnlyIfUnchangedSince: &repository.PasswordState{}}); err != nil {
		t.Fatalf("guard on a never-changed password: %v", err)
	}
	// A stale guard (still expecting NULL) writes nothing.
	if err := repo.SetPassword(ctx, u.ID, repository.PasswordChange{HashedPassword: "stale",
		OnlyIfUnchangedSince: &repository.PasswordState{}}); !errors.Is(err, repository.ErrPasswordChangedMeanwhile) {
		t.Fatalf("stale guard: %v, want ErrPasswordChangedMeanwhile", err)
	}
	if got := hash(); got != "second" {
		t.Fatalf("a stale guard wrote %q", got)
	}
	// The value read back matches.
	read, err := repo.FindByID(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}
	later := first.Add(time.Second)
	if err := repo.SetPassword(ctx, u.ID, repository.PasswordChange{HashedPassword: "third", ChangedAt: &later,
		OnlyIfUnchangedSince: &repository.PasswordState{ChangedAt: read.PasswordChangedAt}}); err != nil {
		t.Fatalf("guard on the value read back: %v", err)
	}
	if got := hash(); got != "third" {
		t.Fatalf("hash = %q, want third", got)
	}
}
