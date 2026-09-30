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
	"github.com/ovander/go-oauth2/internal/service"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// superadminRoleTx opens TEST_DATABASE_URL and returns a transaction rolled back at
// the end of the test, holding one app, one superadmin and one regular user, each
// with an app-role row written directly — the way a data migration writes it,
// bypassing the admin API's refusal.
func superadminRoleTx(t *testing.T) (tx *gorm.DB, app model.App, superadmin, member model.User) {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set; skipping the Postgres integration test")
	}
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{Logger: logger.Default.LogMode(logger.Silent)})
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	if err := migrate.Run(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	if err := db.AutoMigrate(&model.User{}, &model.App{}, &model.UserAppRole{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	tx = db.Begin()
	t.Cleanup(func() { tx.Rollback() })

	tag := fmt.Sprintf("%d", time.Now().UnixNano())
	app = model.App{Name: "sa-test", ClientID: "sa-test-" + tag, Active: true}
	superadmin = model.User{Email: "sa-" + tag + "@example.test", Role: model.UserRoleSuperadmin}
	member = model.User{Email: "member-" + tag + "@example.test", Role: model.UserRoleUser}
	for _, v := range []any{&app, &superadmin, &member} {
		if err := tx.Create(v).Error; err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	for _, r := range []model.UserAppRole{
		{UserID: superadmin.ID, AppID: app.ID, Role: model.AppRoleAdmin},
		{UserID: member.ID, AppID: app.ID, Role: model.AppRoleUser},
	} {
		if err := tx.Create(&r).Error; err != nil {
			t.Fatalf("seed role: %v", err)
		}
	}
	return tx, app, superadmin, member
}

func TestUserAppRoles_SuperadminRowIsIgnoredOnEveryRead(t *testing.T) {
	tx, app, sa, member := superadminRoleTx(t)
	repo := repository.NewUserAppRoleRepository(tx)
	ctx := context.Background()

	// The superadmin's stray row is invisible to every read …
	if _, err := repo.FindByUserAndApp(ctx, sa.ID, app.ID); !errors.Is(err, gorm.ErrRecordNotFound) {
		t.Errorf("FindByUserAndApp(superadmin) err = %v, want record not found", err)
	}
	if m, err := repo.GetUserRolesMap(ctx, sa.ID); err != nil || len(m) != 0 {
		t.Errorf("GetUserRolesMap(superadmin) = %v, %v; want empty", m, err)
	}
	if rs, err := repo.FindByUser(ctx, sa.ID); err != nil || len(rs) != 0 {
		t.Errorf("FindByUser(superadmin) = %d rows, %v; want none", len(rs), err)
	}
	if rs, err := repo.FindAllByUser(ctx, sa.ID); err != nil || len(rs) != 0 {
		t.Errorf("FindAllByUser(superadmin) = %d rows, %v; want none", len(rs), err)
	}
	rs, total, err := repo.FindByApp(ctx, app.ID, 1, 50, "")
	if err != nil || total != 1 || len(rs) != 1 || rs[0].UserID != member.ID {
		t.Errorf("FindByApp = %d rows (total %d), %v; want only the regular member", len(rs), total, err)
	}

	// … so the app-admin actions' membership gate (GetUserRoleForApp) refuses a
	// superadmin target: force-reset and resend-verification cannot reach it.
	svc := service.NewUserAppRoleService(repo)
	if _, err := svc.GetUserRoleForApp(ctx, sa.ID, app.ID); !errors.Is(err, service.ErrRoleNotFound) {
		t.Errorf("GetUserRoleForApp(superadmin) err = %v, want ErrRoleNotFound", err)
	}

	// A regular member is unaffected.
	if r, err := repo.FindByUserAndApp(ctx, member.ID, app.ID); err != nil || r.Role != model.AppRoleUser {
		t.Errorf("FindByUserAndApp(member) = %+v, %v", r, err)
	}
	if m, err := repo.GetUserRolesMap(ctx, member.ID); err != nil || m[app.ClientID] != string(model.AppRoleUser) {
		t.Errorf("GetUserRolesMap(member) = %v, %v", m, err)
	}
}

func TestUserAppRoles_NeverWrittenForASuperadmin(t *testing.T) {
	tx, app, sa, member := superadminRoleTx(t)
	repo := repository.NewUserAppRoleRepository(tx)
	ctx := context.Background()

	other := model.App{Name: "sa-test-2", ClientID: app.ClientID + "-2", Active: true}
	if err := tx.Create(&other).Error; err != nil {
		t.Fatal(err)
	}
	if err := repo.Create(ctx, &model.UserAppRole{UserID: sa.ID, AppID: other.ID, Role: model.AppRoleAdmin}); !errors.Is(err, repository.ErrSuperadminAppRole) {
		t.Errorf("Create(superadmin) err = %v, want ErrSuperadminAppRole", err)
	}
	var stray model.UserAppRole
	tx.Where("user_id = ? AND app_id = ?", sa.ID, app.ID).First(&stray)
	stray.Role = model.AppRoleViewer
	if err := repo.Update(ctx, &stray); !errors.Is(err, repository.ErrSuperadminAppRole) {
		t.Errorf("Update(superadmin) err = %v, want ErrSuperadminAppRole", err)
	}
	if err := repo.Create(ctx, &model.UserAppRole{UserID: member.ID, AppID: other.ID, Role: model.AppRoleEditor}); err != nil {
		t.Errorf("Create(member) err = %v", err)
	}

	// Delete stays possible, so a stray row can be cleaned up.
	if err := repo.Delete(ctx, sa.ID, app.ID); err != nil {
		t.Fatalf("Delete(superadmin) err = %v", err)
	}
	var n int64
	tx.Model(&model.UserAppRole{}).Where("user_id = ?", sa.ID).Count(&n)
	if n != 0 {
		t.Errorf("%d superadmin role row(s) left after Delete", n)
	}
}
