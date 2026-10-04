// Package http — M-03: the admin API accepts only tokens issued to the
// operator consoles (or Socrate's own admin-portal token), through the real
// admin router.
package http

import (
	nethttp "net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ovander/go-oauth2/internal/middleware"
	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/policy"
	"github.com/ovander/go-oauth2/internal/service"
)

type audienceMismatch struct {
	clientID string
	refused  bool
}

func newAdminAudienceRouter(t *testing.T, mode string) (*decideFixture, nethttp.Handler, *[]audienceMismatch) {
	t.Helper()
	f := newDecideFixture(t, policy.ModeShadow)
	var seen []audienceMismatch
	gate := middleware.RequireAdminAudience(mode, []string{"admin-bff", "monitoring-bff", service.AdminPortalClientID},
		func(_ *nethttp.Request, clientID string, refused bool) {
			seen = append(seen, audienceMismatch{clientID, refused})
		})
	users := &decideUsers{users: map[uint]*model.User{1: f.root}}
	h := newAdminRouter(nil, nil, nil, nil, nil, nil, nil, nil, nil, nil,
		f.ts, users, nil, &decideRoles{}, &decideApps{}, RouterConfig{AdminAudience: gate})
	return f, h, &seen
}

// rootTokenFor is the superadmin's access token as issued to clientID.
func rootTokenFor(t *testing.T, f *decideFixture, clientID string) string {
	t.Helper()
	set, err := f.ts.GenerateTokenSetWithAuth(f.root, &model.App{ClientID: clientID}, string(model.AppRoleAdmin),
		"openid", nil, "", time.Now().Unix(), nil, "")
	if err != nil {
		t.Fatal(err)
	}
	return set.AccessToken
}

// adminCall reaches an unknown admin path: past every gate it is a 404, so a
// 403 can only come from a gate.
func adminCall(h nethttp.Handler, bearer string) int {
	req := httptest.NewRequest(nethttp.MethodGet, "/api/admin/m03-probe", nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr.Code
}

func TestAdminAudience_EnforceRefusesAnAppToken(t *testing.T) {
	f, h, seen := newAdminAudienceRouter(t, middleware.AdminAudienceEnforce)

	if code := adminCall(h, rootTokenFor(t, f, "gpwa")); code != nethttp.StatusForbidden {
		t.Fatalf("superadmin token issued to an app → %d, want 403", code)
	}
	if len(*seen) != 1 || (*seen)[0] != (audienceMismatch{"gpwa", true}) {
		t.Errorf("reported = %+v, want one refused gpwa call", *seen)
	}
	for _, client := range []string{"admin-bff", "monitoring-bff", service.AdminPortalClientID} {
		if code := adminCall(h, rootTokenFor(t, f, client)); code != nethttp.StatusNotFound {
			t.Errorf("token issued to %s → %d, want it past the gate (404)", client, code)
		}
	}
	if len(*seen) != 1 {
		t.Errorf("an accepted token was reported: %+v", *seen)
	}
}

func TestAdminAudience_ObserveReportsAndAllows(t *testing.T) {
	f, h, seen := newAdminAudienceRouter(t, middleware.AdminAudienceObserve)
	if code := adminCall(h, rootTokenFor(t, f, "gpwa")); code != nethttp.StatusNotFound {
		t.Fatalf("observe → %d, want the call allowed (404)", code)
	}
	if len(*seen) != 1 || (*seen)[0] != (audienceMismatch{"gpwa", false}) {
		t.Errorf("reported = %+v, want one allowed gpwa call", *seen)
	}
}

func TestAdminAudience_OffIsUnchanged(t *testing.T) {
	f, h, seen := newAdminAudienceRouter(t, middleware.AdminAudienceOff)
	if code := adminCall(h, rootTokenFor(t, f, "gpwa")); code != nethttp.StatusNotFound || len(*seen) != 0 {
		t.Fatalf("off → %d, %d reports; want 404 and none", code, len(*seen))
	}
}
