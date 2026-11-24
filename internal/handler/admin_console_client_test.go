package handler

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/ovander/go-oauth2/internal/contextkeys"
	"github.com/ovander/go-oauth2/internal/dto"
	"github.com/ovander/go-oauth2/internal/model"
)

// consoleApps serves one operator-console client (id 1) and one ordinary app
// (id 2), and counts the changes that reach the service.
func consoleApps() (*lifecycleAppService, *int) {
	calls := 0
	apps := map[uint]*model.App{
		1: {ID: 1, ClientID: "admin-console", Name: "Admin console", RedirectURIs: model.StringArray{"https://admin/cb"}},
		2: {ID: 2, ClientID: "cid-2", Name: "Reporting", RedirectURIs: model.StringArray{"https://app/cb"}},
	}
	get := func(id uint) *model.App { cp := *apps[id]; return &cp }
	return &lifecycleAppService{
		getByID: func(_ context.Context, id uint) (*model.App, error) { return get(id), nil },
		update: func(_ context.Context, id uint, req dto.UpdateAppRequest) (*model.App, error) {
			calls++
			a := get(id)
			if req.RedirectURIs != nil {
				a.RedirectURIs = req.RedirectURIs
			}
			return a, nil
		},
		del: func(context.Context, uint) error { calls++; return nil },
		rotate: func(_ context.Context, id uint) (*model.App, string, error) {
			calls++
			return get(id), "new-secret", nil
		},
	}, &calls
}

// consoleRequest calls one app-changing handler on app id as a caller of the
// given role (no current user when role is empty).
func consoleRequest(h *AdminHandler, action, id string, role model.UserRole) *httptest.ResponseRecorder {
	method, body, call := http.MethodPut, `{"redirect_uris":["https://evil/cb"]}`, h.UpdateApp
	switch action {
	case "delete":
		method, body, call = http.MethodDelete, "", h.DeleteApp
	case "rotate":
		method, body, call = http.MethodPost, "", h.RotateSecret
	}
	r := httptest.NewRequest(method, "/api/admin/apps/"+id, bytes.NewBufferString(body))
	ctx := adminCtx(5, role)
	if role == "" {
		ctx = context.WithValue(context.Background(), contextkeys.UserIDKey, uint(5))
	}
	rc := chi.NewRouteContext()
	rc.URLParams.Add("id", id)
	r = r.WithContext(context.WithValue(ctx, chi.RouteCtxKey, rc))
	rr := httptest.NewRecorder()
	call(rr, r)
	return rr
}

var consoleActions = map[string]model.SecurityEventType{
	"update": model.SecurityEventClientUpdated,
	"delete": model.SecurityEventClientDeleted,
	"rotate": model.SecurityEventClientSecretRotated,
}

// Only a superadmin changes an operator-console client; the refused attempt
// is audited at critical severity and nothing reaches the service.
func TestConsoleClient_OnlyASuperadminChangesIt(t *testing.T) {
	for action, eventType := range consoleActions {
		for _, role := range []model.UserRole{model.UserRoleAdmin, ""} {
			t.Run(action+"/"+string(role), func(t *testing.T) {
				apps, calls := consoleApps()
				audit := &captureAuditService{}
				h := newLifecycleHandler(apps, audit)
				h.SetConsoleClientIDs([]string{"admin-console", "monitoring-console"})

				rr := consoleRequest(h, action, "1", role)
				if rr.Code != http.StatusForbidden || *calls != 0 {
					t.Fatalf("status %d (service calls %d), want 403 and no call; body %s", rr.Code, *calls, rr.Body.String())
				}
				ev := findEvent(audit, eventType)
				if ev == nil || ev.Success || ev.MinSeverity != model.SecuritySeverityCritical || ev.Details["console_client"] != true {
					t.Fatalf("refused attempt not audited as a critical console-client event: %+v", ev)
				}
			})
		}
	}
}

// A superadmin's change goes through and is audited at critical severity; an
// admin's change to an ordinary app is unaffected.
func TestConsoleClient_SuperadminChangeIsCritical(t *testing.T) {
	for action, eventType := range consoleActions {
		t.Run(action, func(t *testing.T) {
			apps, calls := consoleApps()
			audit := &captureAuditService{}
			h := newLifecycleHandler(apps, audit)
			h.SetConsoleClientIDs([]string{"admin-console"})

			if rr := consoleRequest(h, action, "1", model.UserRoleSuperadmin); rr.Code >= 300 || *calls != 1 {
				t.Fatalf("superadmin on a console: status %d, service calls %d", rr.Code, *calls)
			}
			ev := findEvent(audit, eventType)
			if ev == nil || !ev.Success || ev.MinSeverity != model.SecuritySeverityCritical || ev.Details["console_client"] != true {
				t.Fatalf("console change not audited as critical: %+v", ev)
			}

			audit.events = nil
			if rr := consoleRequest(h, action, "2", model.UserRoleAdmin); rr.Code >= 300 || *calls != 2 {
				t.Fatalf("admin on an ordinary app: status %d, service calls %d", rr.Code, *calls)
			}
			ev = findEvent(audit, eventType)
			if ev == nil || ev.MinSeverity != "" || ev.Details["console_client"] != nil {
				t.Fatalf("ordinary app event marked as a console change: %+v", ev)
			}
		})
	}
}
