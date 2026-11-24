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

// UpdateProfile writes the profile and credential columns only: saving a user
// loaded before a concurrent session revocation or failed sign-in does not
// undo them, and revokeSessions increments the stored token version.
func TestUserRepository_UpdateProfile(t *testing.T) {
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

	u := &model.User{Email: fmt.Sprintf("profile-%d@example.test", time.Now().UnixNano()), Name: "Before",
		HashedPassword: "old-hash", Source: "manual", Role: model.UserRoleSuperadmin}
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
	start := stored().TokenVersion

	// Loaded before a concurrent revocation and failed sign-in.
	stale := stored()
	if err := repo.IncrementTokenVersion(ctx, u.ID); err != nil {
		t.Fatal(err)
	}
	if err := repo.IncrementFailedLoginAttempts(ctx, u.ID); err != nil {
		t.Fatal(err)
	}

	stale.Name = "Renamed"
	if err := repo.UpdateProfile(ctx, stale, false); err != nil {
		t.Fatalf("update profile: %v", err)
	}
	got := stored()
	if got.Name != "Renamed" || got.TokenVersion != start+1 || got.FailedLoginAttempts != 1 {
		t.Fatalf("name %q, token version %d, failed attempts %d; want Renamed, %d, 1",
			got.Name, got.TokenVersion, got.FailedLoginAttempts, start+1)
	}

	now := time.Now()
	stale.HashedPassword = "new-hash"
	stale.PasswordChangedAt = &now
	if err := repo.UpdateProfile(ctx, stale, true); err != nil {
		t.Fatalf("update credentials: %v", err)
	}
	got = stored()
	if got.HashedPassword != "new-hash" || got.PasswordChangedAt == nil || got.TokenVersion != start+2 {
		t.Fatalf("password saved %v, token version %d; want true, %d", got.HashedPassword == "new-hash", got.TokenVersion, start+2)
	}

	missing := *stale
	missing.ID = u.ID + 1_000_000
	if err := repo.UpdateProfile(ctx, &missing, true); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Fatalf("unknown user: %v, want record not found", err)
	}
}
