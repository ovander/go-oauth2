// Package http — the service-account member look-up,
// GET /api/apps/{app_id}/service/users/{user_id}, through the real admin
// router with real service-account and user tokens.
package http

import (
	"encoding/json"
	nethttp "net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ovander/go-oauth2/internal/handler"
	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/policy"
	"github.com/ovander/go-oauth2/internal/service"
)

func newServiceLookupRouter(t *testing.T) (*decideFixture, nethttp.Handler) {
	t.Helper()
	f := newDecideFixture(t, policy.ModeShadow)
	users := &decideUsers{users: map[uint]*model.User{10: f.alice, 11: f.bob, 1: f.root}}
	roles := &decideRoles{roles: map[[2]uint]model.AppRole{
		{10, 3}: model.AppRoleAdmin,
		{11, 4}: model.AppRoleUser,
	}}
	appUsers := handler.NewAppUsersHandler(service.NewUserService(users), service.NewUserAppRoleService(roles),
		nil, nil, nil, f.ts, "")
	h := newAdminRouter(nil, nil, nil, appUsers, nil, nil, nil, nil, nil, nil,
		f.ts, users, nil, roles, &decideApps{apps: map[uint]*model.App{3: f.billing, 4: f.crm}},
		RouterConfig{})
	return f, h
}

func lookup(h nethttp.Handler, appID, userID, bearer string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(nethttp.MethodGet, "/api/apps/"+appID+"/service/users/"+userID, nil)
	req.Header.Set("Authorization", "Bearer "+bearer)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr
}

func TestServiceUserLookup_ReturnsTheAppsOwnMember(t *testing.T) {
	f, h := newServiceLookupRouter(t)
	f.alice.Email, f.alice.Name = "alice@example.test", "Alice"

	rr := lookup(h, "3", "10", f.serviceToken(t, f.billing))
	if rr.Code != nethttp.StatusOK {
		t.Fatalf("member look-up → %d %s", rr.Code, rr.Body.String())
	}
	var got struct {
		ID    uint   `json:"id"`
		Email string `json:"email"`
		Name  string `json:"name"`
		Role  string `json:"role"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.ID != 10 || got.Email != "alice@example.test" || got.Name != "Alice" || got.Role != "admin" {
		t.Fatalf("member look-up body = %+v", got)
	}
}

// An app sees only its own members: a member of another app, a Socrate admin
// (never an app member) and an unknown id are all 404s.
func TestServiceUserLookup_OnlyTheAppsOwnMembers(t *testing.T) {
	f, h := newServiceLookupRouter(t)
	svc := f.serviceToken(t, f.billing)
	for name, id := range map[string]string{"other app's member": "11", "socrate admin": "1", "unknown": "999"} {
		if rr := lookup(h, "3", id, svc); rr.Code != nethttp.StatusNotFound {
			t.Errorf("%s → %d %s, want 404", name, rr.Code, rr.Body.String())
		}
	}
	if rr := lookup(h, "3", "not-a-number", svc); rr.Code != nethttp.StatusBadRequest {
		t.Errorf("non-numeric id → %d, want 400", rr.Code)
	}
}

func TestServiceUserLookup_TheCallerMustBeTheApp(t *testing.T) {
	f, h := newServiceLookupRouter(t)
	// CRM's service token cannot read billing's members.
	if rr := lookup(h, "3", "10", f.serviceToken(t, f.crm)); rr.Code != nethttp.StatusForbidden {
		t.Errorf("other app's service token → %d, want 403", rr.Code)
	}
	// A user's token is not a service-account token, even an app admin's.
	if rr := lookup(h, "3", "10", f.userToken(t, f.alice)); rr.Code != nethttp.StatusForbidden {
		t.Errorf("user token → %d, want 403", rr.Code)
	}
	if rr := lookup(h, "3", "10", "garbage"); rr.Code != nethttp.StatusUnauthorized {
		t.Errorf("garbage token → %d, want 401", rr.Code)
	}
	req := httptest.NewRequest(nethttp.MethodGet, "/api/apps/3/service/users/10", nil)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != nethttp.StatusUnauthorized || strings.Contains(rr.Body.String(), "alice") {
		t.Errorf("no token → %d %s, want 401", rr.Code, rr.Body.String())
	}
}

// v1.8.0: the single-member look-up carries token_version and locked, so a
// resource server can check a user token's revocation with its own service
// token. A list never carries them.
func TestServiceUserLookup_ReturnsTokenVersionAndLocked(t *testing.T) {
	f, h := newServiceLookupRouter(t)
	f.alice.TokenVersion = 7
	until := time.Now().Add(time.Hour)
	f.alice.LockedUntil = &until

	rr := lookup(h, "3", "10", f.serviceToken(t, f.billing))
	if rr.Code != nethttp.StatusOK {
		t.Fatalf("member look-up → %d %s", rr.Code, rr.Body.String())
	}
	var got struct {
		TokenVersion *int  `json:"token_version"`
		Locked       *bool `json:"locked"`
	}
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.TokenVersion == nil || *got.TokenVersion != 7 || got.Locked == nil || !*got.Locked {
		t.Fatalf("token_version / locked = %v / %v, want 7 / true", got.TokenVersion, got.Locked)
	}

	f.alice.LockedUntil = nil
	rr = lookup(h, "3", "10", f.serviceToken(t, f.billing))
	if err := json.Unmarshal(rr.Body.Bytes(), &got); err != nil || got.Locked == nil || *got.Locked {
		t.Fatalf("unlocked user: locked = %v (%v)", got.Locked, err)
	}
}
