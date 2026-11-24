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

// Update (a full-row save) leaves out the columns that targeted statements
// own: saving a user loaded before a session revocation, a failed sign-in, a
// lock or a reset does not undo it. SetPassword stores the new hash and
// revokes the sessions in one statement.
func TestUserRepository_UpdateKeepsGuardedColumns(t *testing.T) {
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

	newUser := func(t *testing.T) *model.User {
		t.Helper()
		u := &model.User{Email: fmt.Sprintf("guarded-%d@example.test", time.Now().UnixNano()), Name: "Before",
			HashedPassword: "old-hash", Source: "manual", Role: model.UserRoleUser, TokenVersion: 1}
		if err := repo.Create(ctx, u); err != nil {
			t.Fatalf("create: %v", err)
		}
		return u
	}
	load := func(t *testing.T, id uint) *model.User {
		t.Helper()
		got, err := repo.FindByID(ctx, id)
		if err != nil {
			t.Fatal(err)
		}
		return got
	}
	// saveStale changes an ordinary column on a copy loaded earlier and saves
	// it, as a login or profile path does after its read.
	saveStale := func(t *testing.T, stale *model.User) {
		t.Helper()
		stale.Name = "Saved later"
		if err := repo.Update(ctx, stale); err != nil {
			t.Fatalf("update: %v", err)
		}
		if got := load(t, stale.ID).Name; got != "Saved later" {
			t.Fatalf("Update did not save the name: %q", got)
		}
	}

	t.Run("revocation, failed sign-ins and lock survive a stale save", func(t *testing.T) {
		u := newUser(t)
		stale := load(t, u.ID)
		if err := repo.IncrementTokenVersion(ctx, u.ID); err != nil {
			t.Fatal(err)
		}
		for i := 0; i < 3; i++ {
			if err := repo.IncrementFailedLoginAttempts(ctx, u.ID); err != nil {
				t.Fatal(err)
			}
		}
		until := time.Now().Add(15 * time.Minute)
		if err := repo.LockAccount(ctx, u.ID, &until); err != nil {
			t.Fatal(err)
		}

		saveStale(t, stale)
		got := load(t, u.ID)
		if got.TokenVersion != 2 {
			t.Errorf("token_version %d, want 2: a stale save undid a session revocation", got.TokenVersion)
		}
		if got.FailedLoginAttempts != 3 {
			t.Errorf("failed_login_attempts %d, want 3", got.FailedLoginAttempts)
		}
		if got.LockedUntil == nil || !got.IsLocked() {
			t.Errorf("locked_until %v: a stale save unlocked the account", got.LockedUntil)
		}
	})

	t.Run("a reset survives a stale save", func(t *testing.T) {
		u := newUser(t)
		for i := 0; i < 2; i++ {
			if err := repo.IncrementFailedLoginAttempts(ctx, u.ID); err != nil {
				t.Fatal(err)
			}
		}
		until := time.Now().Add(15 * time.Minute)
		if err := repo.LockAccount(ctx, u.ID, &until); err != nil {
			t.Fatal(err)
		}
		// A successful sign-in loads the user, resets the counter, then
		// saves its last-login time on the copy it loaded.
		stale := load(t, u.ID)
		if err := repo.ResetFailedLoginAttempts(ctx, u.ID); err != nil {
			t.Fatal(err)
		}

		saveStale(t, stale)
		got := load(t, u.ID)
		if got.FailedLoginAttempts != 0 || got.LockedUntil != nil {
			t.Errorf("failed_login_attempts %d, locked_until %v; want 0, nil", got.FailedLoginAttempts, got.LockedUntil)
		}
	})

	t.Run("Update does not write the guarded columns from the struct", func(t *testing.T) {
		u := newUser(t)
		stale := load(t, u.ID)
		until := time.Now().Add(time.Hour)
		stale.TokenVersion = 0
		stale.FailedLoginAttempts = 9
		stale.LockedUntil = &until
		saveStale(t, stale)
		got := load(t, u.ID)
		if got.TokenVersion != 1 || got.FailedLoginAttempts != 0 || got.LockedUntil != nil {
			t.Errorf("token_version %d, failed_login_attempts %d, locked_until %v; want 1, 0, nil",
				got.TokenVersion, got.FailedLoginAttempts, got.LockedUntil)
		}
	})

	t.Run("SetPassword stores the hash and revokes in one write", func(t *testing.T) {
		u := newUser(t)
		if err := repo.IncrementTokenVersion(ctx, u.ID); err != nil { // an earlier revocation
			t.Fatal(err)
		}
		if err := tx.Model(&model.User{}).Where("id = ?", u.ID).Update("must_change_password", true).Error; err != nil {
			t.Fatal(err)
		}
		stale := load(t, u.ID)

		changedAt := time.Now().Truncate(time.Second)
		if err := repo.SetPassword(ctx, u.ID, repository.PasswordChange{
			HashedPassword: "new-hash", ClearMustChangePassword: true, ChangedAt: &changedAt,
		}); err != nil {
			t.Fatalf("set password: %v", err)
		}
		got := load(t, u.ID)
		if got.HashedPassword != "new-hash" || got.TokenVersion != 3 || got.MustChangePassword ||
			got.PasswordChangedAt == nil || !got.PasswordChangedAt.Equal(changedAt) {
			t.Fatalf("hash stored %v, token_version %d, must_change_password %v, password_changed_at %v; want true, 3, false, %v",
				got.HashedPassword == "new-hash", got.TokenVersion, got.MustChangePassword, got.PasswordChangedAt, changedAt)
		}

		// A path that loaded the user before the change saves it afterwards:
		// the revocation that came with the new password stays.
		saveStale(t, stale)
		if got := load(t, u.ID).TokenVersion; got != 3 {
			t.Fatalf("token_version %d after a stale save, want 3", got)
		}
	})

	t.Run("SetPassword without options changes only the hash and the version", func(t *testing.T) {
		u := newUser(t)
		if err := tx.Model(&model.User{}).Where("id = ?", u.ID).Update("must_change_password", true).Error; err != nil {
			t.Fatal(err)
		}
		if err := repo.SetPassword(ctx, u.ID, repository.PasswordChange{HashedPassword: "admin-set"}); err != nil {
			t.Fatal(err)
		}
		got := load(t, u.ID)
		if got.HashedPassword != "admin-set" || got.TokenVersion != 2 || !got.MustChangePassword || got.PasswordChangedAt != nil {
			t.Fatalf("hash stored %v, token_version %d, must_change_password %v, password_changed_at %v; want true, 2, true, nil",
				got.HashedPassword == "admin-set", got.TokenVersion, got.MustChangePassword, got.PasswordChangedAt)
		}
	})

	t.Run("SetPassword on a missing or deleted user", func(t *testing.T) {
		u := newUser(t)
		if err := repo.SetPassword(ctx, u.ID+1_000_000, repository.PasswordChange{HashedPassword: "x"}); !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Fatalf("unknown user: %v, want record not found", err)
		}
		if err := repo.Delete(ctx, u.ID); err != nil {
			t.Fatal(err)
		}
		if err := repo.SetPassword(ctx, u.ID, repository.PasswordChange{HashedPassword: "x"}); !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Fatalf("deleted user: %v, want record not found", err)
		}
	})
}
