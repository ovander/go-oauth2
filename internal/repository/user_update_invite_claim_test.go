package repository_test

import (
	"context"
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

// A save of a pending account loaded before ClaimInviteApp does not clear the
// claim (which would let another app's invite activate the account), and an
// app set on the struct is not written: only Create and ClaimInviteApp set it.
func TestUserRepository_UpdateKeepsTheInviteClaim(t *testing.T) {
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

	u := &model.User{Email: fmt.Sprintf("pending-%d@example.test", time.Now().UnixNano()), Name: "Pending",
		HashedPassword: "throwaway", Source: "manual", Role: model.UserRoleUser}
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

	// Loaded before the claim, as an admin edit of the pending account is.
	stale := stored()
	if claimed, err := repo.ClaimInviteApp(ctx, u.ID, 41); err != nil || !claimed {
		t.Fatalf("claim: %v, %v", claimed, err)
	}
	stale.Name = "Edited"
	if err := repo.Update(ctx, stale); err != nil {
		t.Fatalf("stale save: %v", err)
	}
	got := stored()
	if got.InviteAppID == nil || *got.InviteAppID != 41 {
		t.Fatalf("invite_app_id %v after a stale save, want 41", got.InviteAppID)
	}
	if got.Name != "Edited" {
		t.Fatal("the stale save did not write its own change")
	}

	other := uint(42)
	got.InviteAppID = &other
	if err := repo.Update(ctx, got); err != nil {
		t.Fatalf("update: %v", err)
	}
	if after := stored(); after.InviteAppID == nil || *after.InviteAppID != 41 {
		t.Fatalf("Update wrote invite_app_id: %v", after.InviteAppID)
	}
}
