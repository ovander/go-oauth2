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

type globalAdminFixture struct {
	tx          *gorm.DB
	app         model.App
	superadmin  model.User // holds a stray app "admin" row
	socrateAdm  model.User // holds a stray app "user" row
	member      model.User // a regular user, app "manager"
	globalUsers []model.User
}

// globalAdminTx opens TEST_DATABASE_URL and returns a transaction rolled back at
// the end of the test. It holds one app, a Socrate superadmin and a Socrate admin
// each with a stray app-role row written directly (the way a data migration
// writes it, bypassing the admin API), and a regular member.
func globalAdminTx(t *testing.T) globalAdminFixture {
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
	f := globalAdminFixture{tx: db.Begin()}
	t.Cleanup(func() { f.tx.Rollback() })

	tag := fmt.Sprintf("%d", time.Now().UnixNano())
	f.app = model.App{Name: "ga-test", ClientID: "ga-test-" + tag, Active: true}
	f.superadmin = model.User{Email: "sa-" + tag + "@example.test", Role: model.UserRoleSuperadmin}
	f.socrateAdm = model.User{Email: "adm-" + tag + "@example.test", Role: model.UserRoleAdmin}
	f.member = model.User{Email: "member-" + tag + "@example.test", Role: model.UserRoleUser}
	for _, v := range []any{&f.app, &f.superadmin, &f.socrateAdm, &f.member} {
		if err := f.tx.Create(v).Error; err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	for _, r := range []model.UserAppRole{
		{UserID: f.superadmin.ID, AppID: f.app.ID, Role: model.AppRoleAdmin},
		{UserID: f.socrateAdm.ID, AppID: f.app.ID, Role: model.AppRoleUser},
		{UserID: f.member.ID, AppID: f.app.ID, Role: model.AppRoleManager},
	} {
		if err := f.tx.Create(&r).Error; err != nil {
			t.Fatalf("seed role: %v", err)
		}
	}
	f.globalUsers = []model.User{f.superadmin, f.socrateAdm}
	return f
}

func TestUserAppRoles_SocrateAdminRowsAreIgnoredOnEveryRead(t *testing.T) {
	f := globalAdminTx(t)
	repo := repository.NewUserAppRoleRepository(f.tx)
	svc := service.NewUserAppRoleService(repo)
	ctx := context.Background()

	for _, u := range f.globalUsers {
		t.Run(string(u.Role), func(t *testing.T) {
			if _, err := repo.FindByUserAndApp(ctx, u.ID, f.app.ID); !errors.Is(err, gorm.ErrRecordNotFound) {
				t.Errorf("FindByUserAndApp err = %v, want record not found", err)
			}
			if m, err := repo.GetUserRolesMap(ctx, u.ID); err != nil || len(m) != 0 {
				t.Errorf("GetUserRolesMap = %v, %v; want empty", m, err)
			}
			if rs, err := repo.FindByUser(ctx, u.ID); err != nil || len(rs) != 0 {
				t.Errorf("FindByUser = %d rows, %v; want none", len(rs), err)
			}
			if rs, err := repo.FindAllByUser(ctx, u.ID); err != nil || len(rs) != 0 {
				t.Errorf("FindAllByUser = %d rows, %v; want none", len(rs), err)
			}
			// The app-admin actions' membership gate (force password reset,
			// resend verification, role change) therefore refuses this target.
			if _, err := svc.GetUserRoleForApp(ctx, u.ID, f.app.ID); !errors.Is(err, service.ErrRoleNotFound) {
				t.Errorf("GetUserRoleForApp err = %v, want ErrRoleNotFound", err)
			}
		})
	}

	// The member list shows only the regular member; a regular member is unaffected.
	rs, total, err := repo.FindByApp(ctx, f.app.ID, 1, 50, "")
	if err != nil || total != 1 || len(rs) != 1 || rs[0].UserID != f.member.ID {
		t.Errorf("FindByApp = %d rows (total %d), %v; want only the regular member", len(rs), total, err)
	}
	if r, err := repo.FindByUserAndApp(ctx, f.member.ID, f.app.ID); err != nil || r.Role != model.AppRoleManager {
		t.Errorf("FindByUserAndApp(member) = %+v, %v", r, err)
	}
	if m, err := repo.GetUserRolesMap(ctx, f.member.ID); err != nil || m[f.app.ClientID] != string(model.AppRoleManager) {
		t.Errorf("GetUserRolesMap(member) = %v, %v", m, err)
	}
}

func TestUserAppRoles_NeverWrittenForASocrateAdmin(t *testing.T) {
	f := globalAdminTx(t)
	repo := repository.NewUserAppRoleRepository(f.tx)
	ctx := context.Background()

	other := model.App{Name: "ga-test-2", ClientID: f.app.ClientID + "-2", Active: true}
	if err := f.tx.Create(&other).Error; err != nil {
		t.Fatal(err)
	}
	for _, u := range f.globalUsers {
		for _, appRole := range model.ValidAppRoles {
			err := repo.Create(ctx, &model.UserAppRole{UserID: u.ID, AppID: other.ID, Role: appRole})
			if !errors.Is(err, repository.ErrGlobalAdminAppRole) {
				t.Errorf("Create(%s as app %s) err = %v, want ErrGlobalAdminAppRole", u.Role, appRole, err)
			}
		}
		var stray model.UserAppRole
		f.tx.Where("user_id = ? AND app_id = ?", u.ID, f.app.ID).First(&stray)
		stray.Role = model.AppRoleViewer
		if err := repo.Update(ctx, &stray); !errors.Is(err, repository.ErrGlobalAdminAppRole) {
			t.Errorf("Update(%s) err = %v, want ErrGlobalAdminAppRole", u.Role, err)
		}
		// Delete stays possible, so a stray row can be cleaned up.
		if err := repo.Delete(ctx, u.ID, f.app.ID); err != nil {
			t.Fatalf("Delete(%s) err = %v", u.Role, err)
		}
		var n int64
		f.tx.Model(&model.UserAppRole{}).Where("user_id = ?", u.ID).Count(&n)
		if n != 0 {
			t.Errorf("%s: %d role row(s) left after Delete", u.Role, n)
		}
	}
	if err := repo.Create(ctx, &model.UserAppRole{UserID: f.member.ID, AppID: other.ID, Role: model.AppRoleEditor}); err != nil {
		t.Errorf("Create(member) err = %v", err)
	}
}
