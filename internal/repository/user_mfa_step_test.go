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

// AdvanceMFAStep (migration 0032) only moves the last accepted TOTP step
// forward, and saving a user loaded earlier (Update is a full-row Save) does
// not move it back.
func TestUserRepository_AdvanceMFAStep(t *testing.T) {
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

	u := &model.User{Email: fmt.Sprintf("step-%d@example.test", time.Now().UnixNano()), Name: "Step",
		HashedPassword: "x", Source: "manual", Role: model.UserRoleUser}
	if err := repo.Create(ctx, u); err != nil {
		t.Fatalf("create: %v", err)
	}
	stored := func() int64 {
		got, err := repo.FindByID(ctx, u.ID)
		if err != nil {
			t.Fatal(err)
		}
		return got.MFALastStep
	}
	if got := stored(); got != 0 {
		t.Fatalf("new user: mfa_last_step %d, want 0", got)
	}
	// Loaded before the steps below, as a login path loads the user before
	// the MFA check and saves it afterwards.
	stale, err := repo.FindByID(ctx, u.ID)
	if err != nil {
		t.Fatal(err)
	}

	for _, tc := range []struct {
		step int64
		want bool
	}{{100, true}, {100, false}, {99, false}, {101, true}} {
		if ok, err := repo.AdvanceMFAStep(ctx, u.ID, tc.step); err != nil || ok != tc.want {
			t.Fatalf("AdvanceMFAStep(%d) = %v, %v; want %v", tc.step, ok, err, tc.want)
		}
	}
	if got := stored(); got != 101 {
		t.Fatalf("mfa_last_step %d, want 101", got)
	}

	stale.Name = "Saved later"
	stale.MFALastStep = 0
	if err := repo.Update(ctx, stale); err != nil {
		t.Fatalf("update: %v", err)
	}
	if got := stored(); got != 101 {
		t.Fatalf("a full-row save moved mfa_last_step back to %d", got)
	}
}
