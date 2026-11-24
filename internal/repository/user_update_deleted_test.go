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

// Saving a user loaded before it was deleted does not bring it back (GORM's
// Save would retry as an upsert that clears deleted_at); Update reports it as
// not found. An ordinary save still writes zero values.
func TestUserRepository_UpdateDoesNotResurrect(t *testing.T) {
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

	title := "Engineer"
	u := &model.User{Email: fmt.Sprintf("deleted-%d@example.test", time.Now().UnixNano()), Name: "Deleted",
		HashedPassword: "x", Source: "manual", Role: model.UserRoleUser, IsVerified: true, Title: &title}
	if err := repo.Create(ctx, u); err != nil {
		t.Fatalf("create: %v", err)
	}

	t.Run("zero values are written", func(t *testing.T) {
		got, err := repo.FindByID(ctx, u.ID)
		if err != nil {
			t.Fatal(err)
		}
		got.IsVerified, got.Title = false, nil
		if err := repo.Update(ctx, got); err != nil {
			t.Fatalf("update: %v", err)
		}
		stored, err := repo.FindByID(ctx, u.ID)
		if err != nil {
			t.Fatal(err)
		}
		if stored.IsVerified || stored.Title != nil {
			t.Fatalf("is_verified %v, title %v; want false, nil", stored.IsVerified, stored.Title)
		}
	})

	t.Run("a deleted user stays deleted", func(t *testing.T) {
		stale, err := repo.FindByID(ctx, u.ID)
		if err != nil {
			t.Fatal(err)
		}
		if err := repo.Delete(ctx, u.ID); err != nil {
			t.Fatalf("delete: %v", err)
		}
		stale.Name = "Saved later"
		if err := repo.Update(ctx, stale); !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Fatalf("update of a deleted user: %v, want record not found", err)
		}
		if _, err := repo.FindByID(ctx, u.ID); !errors.Is(err, gorm.ErrRecordNotFound) {
			t.Fatalf("the deleted user is visible again: %v", err)
		}
		var live int64
		if err := tx.Unscoped().Model(&model.User{}).Where("id = ? AND deleted_at IS NULL", u.ID).Count(&live).Error; err != nil {
			t.Fatal(err)
		}
		if live != 0 {
			t.Fatal("deleted_at was cleared")
		}
	})
}
