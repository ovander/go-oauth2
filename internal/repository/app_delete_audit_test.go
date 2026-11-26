package repository_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/ovander/go-oauth2/internal/database/migrate"
	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/repository"
)

// #260: deleting an app leaves the audit rows that name it untouched — their
// app_id, and so their row hash, which covers it — and the client_deleted
// event written after the delete is stored.
func TestAppDelete_LeavesItsAuditRowsIntact(t *testing.T) {
	db := auditScratchDB(t)
	if err := db.AutoMigrate(&model.User{}, &model.App{}, &model.UserAppRole{}, &model.AdminLog{},
		&model.AppActivityLog{}, &model.AuthorizationCode{}); err != nil {
		t.Fatalf("automigrate: %v", err)
	}
	if err := migrate.Run(db); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	ctx := context.Background()
	apps := repository.NewAppRepository(db)
	audit := repository.NewSecurityAuditLogRepositoryWithIntegrity(db, auditTestSecret)

	app := &model.App{ClientID: fmt.Sprint("deleted-", time.Now().UnixNano()), Name: "To delete", Active: true}
	if err := apps.Create(ctx, app); err != nil {
		t.Fatalf("create app: %v", err)
	}
	appID := app.ID
	created := &model.SecurityAuditLog{EventType: model.SecurityEventClientCreated, AppID: &appID, Success: true,
		Details: map[string]interface{}{"client_id": app.ClientID}, CreatedAt: time.Now()}
	if err := audit.Create(ctx, created); err != nil {
		t.Fatalf("audit client_created: %v", err)
	}

	admin := &model.User{Email: fmt.Sprint("admin-", time.Now().UnixNano(), "@example.test"), Name: "admin"}
	if err := db.Create(admin).Error; err != nil {
		t.Fatalf("create admin: %v", err)
	}
	adminLog := &model.AdminLog{AdminID: admin.ID, AppID: &appID, Action: model.AdminActionPolicyUpdated}
	if err := db.Create(adminLog).Error; err != nil {
		t.Fatalf("create admin log: %v", err)
	}

	if err := apps.Delete(ctx, appID); err != nil {
		t.Fatalf("delete app: %v", err)
	}

	// The admin-log row still names the app its action concerned (0038).
	var keptLog model.AdminLog
	if err := db.First(&keptLog, adminLog.ID).Error; err != nil {
		t.Fatalf("reload the admin log: %v", err)
	}
	if keptLog.AppID == nil {
		t.Fatalf("the admin log lost its app: app_id is NULL, want %d", appID)
	}
	if *keptLog.AppID != appID {
		t.Fatalf("the admin log names app %d, want %d", *keptLog.AppID, appID)
	}

	var row model.SecurityAuditLog
	if err := db.First(&row, created.ID).Error; err != nil {
		t.Fatalf("reload the audit row: %v", err)
	}
	if row.AppID == nil || *row.AppID != appID {
		t.Fatalf("the audit row lost its app: app_id = %v, want %d", row.AppID, appID)
	}
	if !repository.VerifyAuditRowHash(auditTestSecret, &row) {
		t.Fatal("the audit row no longer verifies after the app was deleted")
	}

	// The deletion event names the deleted app, and is stored.
	deleted := &model.SecurityAuditLog{EventType: model.SecurityEventClientDeleted, AppID: &appID, Success: true,
		Details: map[string]interface{}{"client_id": app.ClientID}, CreatedAt: time.Now()}
	if err := audit.Create(ctx, deleted); err != nil {
		t.Fatalf("audit client_deleted for the deleted app: %v", err)
	}
	var n int64
	if err := db.Model(&model.SecurityAuditLog{}).Where("event_type = ? AND app_id = ?", model.SecurityEventClientDeleted, appID).Count(&n).Error; err != nil {
		t.Fatal(err)
	}
	if n != 1 {
		t.Fatalf("client_deleted rows for the deleted app = %d, want 1", n)
	}
}
