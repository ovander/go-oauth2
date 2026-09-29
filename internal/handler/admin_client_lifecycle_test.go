// Package handler — tests for the OAuth client-lifecycle security events (#203).
//
// Create / Update / Delete / RotateSecret on a registered client must emit an
// alertable security audit event (client_created / client_updated /
// client_deleted / client_secret_rotated) so the monitoring console — not just
// the app owner's admin trail — sees high-risk client changes.
package handler

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ovander/go-oauth2/internal/dto"
	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/service"
)

// ---------------------------------------------------------------------------
// Capturing SecurityAuditService
// ---------------------------------------------------------------------------

type captureAuditService struct {
	events []service.SecurityEvent
}

func (c *captureAuditService) Log(_ context.Context, e service.SecurityEvent) error {
	c.events = append(c.events, e)
	return nil
}
func (c *captureAuditService) LogFromRequest(_ context.Context, _ *http.Request, e service.SecurityEvent) error {
	c.events = append(c.events, e)
	return nil
}
func (c *captureAuditService) GetByUser(_ context.Context, _ uint, _, _ int) ([]model.SecurityAuditLog, int64, error) {
	return nil, 0, nil
}
func (c *captureAuditService) GetByApp(_ context.Context, _ uint, _, _ int) ([]model.SecurityAuditLog, int64, error) {
	return nil, 0, nil
}
func (c *captureAuditService) GetByEventType(_ context.Context, _ model.SecurityEventType, _, _ int) ([]model.SecurityAuditLog, int64, error) {
	return nil, 0, nil
}
func (c *captureAuditService) GetBySeverity(_ context.Context, _ model.SecuritySeverity, _, _ int) ([]model.SecurityAuditLog, int64, error) {
	return nil, 0, nil
}
func (c *captureAuditService) GetByDateRange(_ context.Context, _, _ time.Time, _, _ int) ([]model.SecurityAuditLog, int64, error) {
	return nil, 0, nil
}
func (c *captureAuditService) GetByIPAddress(_ context.Context, _ string, _, _ int) ([]model.SecurityAuditLog, int64, error) {
	return nil, 0, nil
}
func (c *captureAuditService) GetFailedLoginsByUser(_ context.Context, _ uint, _ time.Time) ([]model.SecurityAuditLog, error) {
	return nil, nil
}
func (c *captureAuditService) GetFailedLoginsByIP(_ context.Context, _ string, _ time.Time) ([]model.SecurityAuditLog, error) {
	return nil, nil
}
func (c *captureAuditService) CountCriticalEventsSince(_ context.Context, _ time.Time) (int64, error) {
	return 0, nil
}
func (c *captureAuditService) CleanupOldLogs(_ context.Context, _ int) (int64, error) { return 0, nil }

var _ service.SecurityAuditService = (*captureAuditService)(nil)

// ---------------------------------------------------------------------------
// Configurable AppService (embeds the panic stub; overrides what we exercise)
// ---------------------------------------------------------------------------

type lifecycleAppService struct {
	panicAppService
	getByID func(ctx context.Context, id uint) (*model.App, error)
	create  func(ctx context.Context, req dto.CreateAppRequest, owner uint) (*model.App, string, error)
	update  func(ctx context.Context, id uint, req dto.UpdateAppRequest) (*model.App, error)
	del     func(ctx context.Context, id uint) error
	rotate  func(ctx context.Context, id uint) (*model.App, string, error)
}

func (s *lifecycleAppService) GetByID(ctx context.Context, id uint) (*model.App, error) {
	return s.getByID(ctx, id)
}
func (s *lifecycleAppService) Create(ctx context.Context, req dto.CreateAppRequest, owner uint) (*model.App, string, error) {
	return s.create(ctx, req, owner)
}
func (s *lifecycleAppService) Update(ctx context.Context, id uint, req dto.UpdateAppRequest) (*model.App, error) {
	return s.update(ctx, id, req)
}
func (s *lifecycleAppService) Delete(ctx context.Context, id uint) error { return s.del(ctx, id) }
func (s *lifecycleAppService) RotateSecret(ctx context.Context, id uint) (*model.App, string, error) {
	return s.rotate(ctx, id)
}

// newLifecycleHandler wires an AdminHandler with the given app service and a
// capturing audit service; email/activity services are nil (skipped).
func newLifecycleHandler(apps service.AppService, audit service.SecurityAuditService) *AdminHandler {
	return NewAdminHandler(
		apps,
		&adminTestUserService{},
		&panicUserAppRoleService{},
		&noopAdminLogService{},
		nil, // AppActivityLogService
		nil, // EmailService (skips credentials email)
		audit,
	)
}

func ptr(s string) *string { return &s }
func uintPtr(u uint) *uint { return &u }

// findEvent returns the first captured event of the given type, or nil.
func findEvent(cap *captureAuditService, t model.SecurityEventType) *service.SecurityEvent {
	for i := range cap.events {
		if cap.events[i].EventType == t {
			return &cap.events[i]
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestCreateApp_EmitsClientCreated(t *testing.T) {
	cap := &captureAuditService{}
	apps := &lifecycleAppService{
		create: func(_ context.Context, _ dto.CreateAppRequest, _ uint) (*model.App, string, error) {
			return &model.App{ID: 7, ClientID: "cid-7", Name: "Reporting", RedirectURIs: model.StringArray{"https://app/cb"}}, "the-secret", nil
		},
	}
	h := newLifecycleHandler(apps, cap)

	req := httptest.NewRequest(http.MethodPost, "/api/admin/apps", bytes.NewBufferString(`{"name":"Reporting"}`))
	req = req.WithContext(adminCtx(1, model.UserRoleSuperadmin))
	rr := httptest.NewRecorder()
	h.CreateApp(rr, req)

	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", rr.Code)
	}
	ev := findEvent(cap, model.SecurityEventClientCreated)
	if ev == nil {
		t.Fatal("expected a client_created event")
	}
	if ev.AppID == nil || *ev.AppID != 7 {
		t.Errorf("event AppID = %v, want 7", ev.AppID)
	}
	if ev.Details["client_id"] != "cid-7" {
		t.Errorf("event client_id = %v, want cid-7", ev.Details["client_id"])
	}
	if ev.Details["confidential"] != true {
		t.Errorf("confidential = %v, want true", ev.Details["confidential"])
	}
}

func TestUpdateApp_EmitsChangeSet(t *testing.T) {
	cap := &captureAuditService{}
	before := &model.App{ID: 9, ClientID: "cid-9", Name: "Svc", OwnerID: uintPtr(1),
		Active: true, RedirectURIs: model.StringArray{"https://good/cb"}}
	after := &model.App{ID: 9, ClientID: "cid-9", Name: "Svc", OwnerID: uintPtr(1),
		Active: false, RedirectURIs: model.StringArray{"https://evil/cb"}}
	apps := &lifecycleAppService{
		getByID: func(_ context.Context, _ uint) (*model.App, error) { return before, nil },
		update:  func(_ context.Context, _ uint, _ dto.UpdateAppRequest) (*model.App, error) { return after, nil },
	}
	h := newLifecycleHandler(apps, cap)

	req := httptest.NewRequest(http.MethodPut, "/api/admin/apps/9", bytes.NewBufferString(`{}`))
	req = chiCtxWithID(req.WithContext(adminCtx(1, model.UserRoleSuperadmin)), "9")
	rr := httptest.NewRecorder()
	h.UpdateApp(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d (body %s)", rr.Code, rr.Body.String())
	}
	ev := findEvent(cap, model.SecurityEventClientUpdated)
	if ev == nil {
		t.Fatal("expected a client_updated event")
	}
	changed, ok := ev.Details["changed"].([]string)
	if !ok {
		t.Fatalf("changed detail missing or wrong type: %T", ev.Details["changed"])
	}
	if !contains(changed, "redirect_uris") || !contains(changed, "active") {
		t.Errorf("changed = %v, want both redirect_uris and active", changed)
	}
	// The redirect-URI change must carry old→new so the SOC can see the flip.
	ru, ok := ev.Details["redirect_uris"].(map[string]interface{})
	if !ok {
		t.Fatalf("redirect_uris detail missing: %v", ev.Details["redirect_uris"])
	}
	if got := ru["new"].([]string); len(got) != 1 || got[0] != "https://evil/cb" {
		t.Errorf("redirect_uris new = %v, want [https://evil/cb]", got)
	}
}

func TestUpdateApp_NoChangeNoEvent(t *testing.T) {
	cap := &captureAuditService{}
	app := &model.App{ID: 9, ClientID: "cid-9", Name: "Svc", OwnerID: uintPtr(1), Active: true}
	apps := &lifecycleAppService{
		getByID: func(_ context.Context, _ uint) (*model.App, error) { return app, nil },
		// Update returns an identical app (no fields changed).
		update: func(_ context.Context, _ uint, _ dto.UpdateAppRequest) (*model.App, error) {
			cp := *app
			return &cp, nil
		},
	}
	h := newLifecycleHandler(apps, cap)

	req := httptest.NewRequest(http.MethodPut, "/api/admin/apps/9", bytes.NewBufferString(`{}`))
	req = chiCtxWithID(req.WithContext(adminCtx(1, model.UserRoleSuperadmin)), "9")
	h.UpdateApp(httptest.NewRecorder(), req)

	if findEvent(cap, model.SecurityEventClientUpdated) != nil {
		t.Fatal("a no-op update must not emit a client_updated event")
	}
}

func TestDeleteApp_EmitsClientDeleted(t *testing.T) {
	cap := &captureAuditService{}
	app := &model.App{ID: 4, ClientID: "cid-4", Name: "Old", OwnerID: uintPtr(1)}
	apps := &lifecycleAppService{
		getByID: func(_ context.Context, _ uint) (*model.App, error) { return app, nil },
		del:     func(_ context.Context, _ uint) error { return nil },
	}
	h := newLifecycleHandler(apps, cap)

	req := httptest.NewRequest(http.MethodDelete, "/api/admin/apps/4", nil)
	req = chiCtxWithID(req.WithContext(adminCtx(1, model.UserRoleSuperadmin)), "4")
	rr := httptest.NewRecorder()
	h.DeleteApp(rr, req)

	if rr.Code != http.StatusNoContent {
		t.Fatalf("expected 204, got %d", rr.Code)
	}
	if ev := findEvent(cap, model.SecurityEventClientDeleted); ev == nil {
		t.Fatal("expected a client_deleted event")
	} else if ev.Details["client_id"] != "cid-4" {
		t.Errorf("client_id = %v, want cid-4", ev.Details["client_id"])
	}
}

func TestRotateSecret_EmitsSecretRotated(t *testing.T) {
	cap := &captureAuditService{}
	app := &model.App{ID: 5, ClientID: "cid-5", Name: "Svc", OwnerID: uintPtr(1)}
	apps := &lifecycleAppService{
		getByID: func(_ context.Context, _ uint) (*model.App, error) { return app, nil },
		rotate:  func(_ context.Context, _ uint) (*model.App, string, error) { return app, "new-secret", nil },
	}
	h := newLifecycleHandler(apps, cap)

	req := httptest.NewRequest(http.MethodPost, "/api/admin/apps/5/rotate-secret", nil)
	req = chiCtxWithID(req.WithContext(adminCtx(1, model.UserRoleSuperadmin)), "5")
	rr := httptest.NewRecorder()
	h.RotateSecret(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Code)
	}
	if ev := findEvent(cap, model.SecurityEventClientSecretRotated); ev == nil {
		t.Fatal("expected a client_secret_rotated event")
	}
}

func TestClientLifecycle_NilAuditServiceIsSafe(t *testing.T) {
	apps := &lifecycleAppService{
		create: func(_ context.Context, _ dto.CreateAppRequest, _ uint) (*model.App, string, error) {
			return &model.App{ID: 1, ClientID: "cid-1", Name: "X"}, "", nil
		},
	}
	h := newLifecycleHandler(apps, nil) // nil audit service

	req := httptest.NewRequest(http.MethodPost, "/api/admin/apps", bytes.NewBufferString(`{"name":"X"}`))
	req = req.WithContext(adminCtx(1, model.UserRoleSuperadmin))
	rr := httptest.NewRecorder()
	h.CreateApp(rr, req) // must not panic
	if rr.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", rr.Code)
	}
}

// appChangeSet unit coverage: only changed fields are reported, old→new carried.
func TestAppChangeSet(t *testing.T) {
	before := &model.App{Name: "a", URL: ptr("https://a"), Active: true,
		RedirectURIs: model.StringArray{"https://a/cb"}, AllowTokenExchange: false}
	after := &model.App{Name: "a", URL: ptr("https://a"), Active: false,
		RedirectURIs: model.StringArray{"https://a/cb"}, AllowTokenExchange: true}

	changed, detail := appChangeSet(before, after)
	if contains(changed, "name") || contains(changed, "url") || contains(changed, "redirect_uris") {
		t.Errorf("unchanged fields reported: %v", changed)
	}
	if !contains(changed, "active") || !contains(changed, "allow_token_exchange") {
		t.Errorf("changed = %v, want active + allow_token_exchange", changed)
	}
	at, ok := detail["active"].(map[string]interface{})
	if !ok || at["old"] != true || at["new"] != false {
		t.Errorf("active detail = %v, want old=true new=false", detail["active"])
	}
}

// Severity: destructive client-lifecycle actions are warning-level, routine
// create/update stay info-level.
func TestClientLifecycleSeverity(t *testing.T) {
	cases := map[model.SecurityEventType]model.SecuritySeverity{
		model.SecurityEventClientCreated:       model.SecuritySeverityInfo,
		model.SecurityEventClientUpdated:       model.SecuritySeverityInfo,
		model.SecurityEventClientDeleted:       model.SecuritySeverityWarning,
		model.SecurityEventClientSecretRotated: model.SecuritySeverityWarning,
	}
	for ev, want := range cases {
		if got := model.GetSeverityForEvent(ev, true); got != want {
			t.Errorf("severity(%s) = %s, want %s", ev, got, want)
		}
	}
}

func contains(xs []string, want string) bool {
	for _, x := range xs {
		if x == want {
			return true
		}
	}
	return false
}
