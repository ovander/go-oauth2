// Package http — ADMIN_API_AUDIENCE_MODE also covers the app-management
// routes /api/apps/{app_id}/*, where a token issued to that app is accepted,
// through the real admin router.
package http

import (
	"context"
	nethttp "net/http"
	"net/http/httptest"
	"testing"

	"github.com/ovander/go-oauth2/internal/middleware"
	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/policy"
	"github.com/ovander/go-oauth2/internal/service"
)

func newAppAudienceRouter(t *testing.T, mode string) (*decideFixture, nethttp.Handler, *[]audienceMismatch) {
	t.Helper()
	f := newDecideFixture(t, policy.ModeShadow)
	apps := &decideApps{apps: map[uint]*model.App{
		1: {ID: 1, ClientID: "gpwa", Active: true},
		2: {ID: 2, ClientID: "ascenda", Active: true},
	}}
	var seen []audienceMismatch
	gate := middleware.RequireAppAudience(mode, []string{"admin-bff", "monitoring-bff", service.AdminPortalClientID},
		func(ctx context.Context, id uint) (string, error) {
			app, err := apps.FindByID(ctx, id)
			if err != nil {
				return "", err
			}
			return app.ClientID, nil
		},
		func(_ *nethttp.Request, clientID string, refused bool) {
			seen = append(seen, audienceMismatch{clientID, refused})
		})
	users := &decideUsers{users: map[uint]*model.User{1: f.root}}
	h := newAdminRouter(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		f.ts, users, nil, &decideRoles{}, apps, RouterConfig{AppAudience: gate})
	return f, h, &seen
}

// appCall reaches an unknown path under /api/apps/{app_id}: the role gates
// let a global admin through for any app, so past every gate it is a 404 and
// a 403 can only come from the audience check.
func appCall(h nethttp.Handler, appID, bearer string) int {
	req := httptest.NewRequest(nethttp.MethodGet, "/api/apps/"+appID+"/m03-probe", nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr.Code
}

func TestAppAudience_EnforceConfinesAnAppTokenToItsApp(t *testing.T) {
	f, h, seen := newAppAudienceRouter(t, middleware.AdminAudienceEnforce)

	if code := appCall(h, "2", rootTokenFor(t, f, "gpwa")); code != nethttp.StatusForbidden {
		t.Fatalf("superadmin token issued to gpwa, on ascenda → %d, want 403", code)
	}
	if len(*seen) != 1 || (*seen)[0] != (audienceMismatch{"gpwa", true}) {
		t.Errorf("reported = %+v, want one refused gpwa call", *seen)
	}
	if code := appCall(h, "1", rootTokenFor(t, f, "gpwa")); code != nethttp.StatusNotFound {
		t.Errorf("token issued to gpwa, on gpwa → %d, want it past the gate (404)", code)
	}
	for _, client := range []string{"admin-bff", "monitoring-bff", service.AdminPortalClientID} {
		if code := appCall(h, "2", rootTokenFor(t, f, client)); code != nethttp.StatusNotFound {
			t.Errorf("token issued to %s → %d, want it past the gate (404)", client, code)
		}
	}
	if len(*seen) != 1 {
		t.Errorf("an accepted token was reported: %+v", *seen)
	}
}

func TestAppAudience_ObserveReportsAndAllows(t *testing.T) {
	f, h, seen := newAppAudienceRouter(t, middleware.AdminAudienceObserve)
	if code := appCall(h, "2", rootTokenFor(t, f, "gpwa")); code != nethttp.StatusNotFound {
		t.Fatalf("observe → %d, want the call allowed (404)", code)
	}
	if len(*seen) != 1 || (*seen)[0] != (audienceMismatch{"gpwa", false}) {
		t.Errorf("reported = %+v, want one allowed gpwa call", *seen)
	}
}

// The service-account routes keep their own authentication: the audience
// check is not mounted on them.
func TestAppAudience_LeavesTheServiceRoutesAlone(t *testing.T) {
	f, h, seen := newAppAudienceRouter(t, middleware.AdminAudienceEnforce)
	req := httptest.NewRequest(nethttp.MethodGet, "/api/apps/2/service/users/1", nil)
	req.Header.Set("Authorization", "Bearer "+rootTokenFor(t, f, "gpwa"))
	h.ServeHTTP(httptest.NewRecorder(), req)
	if len(*seen) != 0 {
		t.Fatalf("the audience check ran on a service route: %+v", *seen)
	}
}
