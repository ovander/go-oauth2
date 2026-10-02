// Package http — the service-account profile update,
// PATCH /api/apps/{app_id}/service/users/{user_id}, through the real admin
// router with real service-account and user tokens.
package http

import (
	"context"
	"encoding/json"
	"errors"
	nethttp "net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/ovander/go-oauth2/internal/handler"
	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/policy"
	"github.com/ovander/go-oauth2/internal/repository"
	"github.com/ovander/go-oauth2/internal/service"
)

// updUsers is a user repository holding users by ID that records updates.
type updUsers struct {
	repository.UserRepository
	users map[uint]*model.User
}

func (r *updUsers) FindByID(_ context.Context, id uint) (*model.User, error) {
	if u, ok := r.users[id]; ok {
		c := *u
		return &c, nil
	}
	return nil, errors.New("user not found")
}

func (r *updUsers) Update(_ context.Context, u *model.User) error {
	c := *u
	r.users[u.ID] = &c
	return nil
}

type auditCall struct {
	adminID, appID, target uint
	action                 model.AdminAction
	details                map[string]interface{}
}

type recordingAudit struct {
	service.AdminLogService
	calls []auditCall
}

func (a *recordingAudit) LogAction(_ context.Context, adminID uint, appID, target *uint, action model.AdminAction, details map[string]interface{}) error {
	a.calls = append(a.calls, auditCall{adminID, *appID, *target, action, details})
	return nil
}

type updFixture struct {
	*decideFixture
	h     nethttp.Handler
	users *updUsers
	audit *recordingAudit
}

func newUpdFixture(t *testing.T) *updFixture {
	t.Helper()
	f := newDecideFixture(t, policy.ModeShadow)
	users := &updUsers{users: map[uint]*model.User{
		10: {ID: 10, Email: "alice@example.test", Name: "Alice", Role: model.UserRoleUser},
		11: {ID: 11, Email: "bob@example.test", Name: "Bob", Role: model.UserRoleUser},
		1:  {ID: 1, Email: "root@example.test", Name: "Root", Role: model.UserRoleSuperadmin},
	}}
	roles := &decideRoles{roles: map[[2]uint]model.AppRole{{10, 3}: model.AppRoleUser, {11, 4}: model.AppRoleUser}}
	audit := &recordingAudit{}
	appUsers := handler.NewAppUsersHandler(service.NewUserService(users), service.NewUserAppRoleService(roles),
		nil, audit, nil, f.ts, "")
	h := newAdminRouter(nil, nil, nil, appUsers, nil, nil, nil, nil, nil, nil,
		f.ts, users, nil, roles, &decideApps{apps: map[uint]*model.App{3: f.billing, 4: f.crm}}, RouterConfig{})
	return &updFixture{decideFixture: f, h: h, users: users, audit: audit}
}

func (f *updFixture) patch(appID, userID, bearer, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(nethttp.MethodPatch, "/api/apps/"+appID+"/service/users/"+userID, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+bearer)
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	f.h.ServeHTTP(rr, req)
	return rr
}

func TestServiceUserUpdate_UpdatesProfileFieldsAndAudits(t *testing.T) {
	f := newUpdFixture(t)
	rr := f.patch("3", "10", f.serviceToken(t, f.billing),
		`{"name":"Alice Doe","phone":"+32 2 000 00 00","avatar_url":"https://cdn.example.test/10.png"}`)
	if rr.Code != nethttp.StatusOK {
		t.Fatalf("update → %d %s", rr.Code, rr.Body.String())
	}
	var got struct {
		ID        uint   `json:"id"`
		Name      string `json:"name"`
		Email     string `json:"email"`
		Role      string `json:"role"`
		AvatarURL string `json:"avatar_url"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &got)
	if got.ID != 10 || got.Name != "Alice Doe" || got.Email != "alice@example.test" || got.Role != "user" ||
		got.AvatarURL != "https://cdn.example.test/10.png" {
		t.Fatalf("response = %+v", got)
	}
	stored := f.users.users[10]
	if stored.Name != "Alice Doe" || stored.Phone == nil || *stored.Phone != "+32 2 000 00 00" || stored.Email != "alice@example.test" {
		t.Fatalf("stored = %+v", stored)
	}
	if len(f.audit.calls) != 1 {
		t.Fatalf("audit calls = %d, want 1", len(f.audit.calls))
	}
	c := f.audit.calls[0]
	if c.adminID != 0 || c.appID != 3 || c.target != 10 || c.action != model.AdminActionUpdateProfile ||
		!reflect.DeepEqual(c.details["fields"], []string{"name", "phone", "avatar_url"}) {
		t.Fatalf("audit = %+v", c)
	}
}

// Email, password, role and anything else outside the profile are refused, and
// nothing is written.
func TestServiceUserUpdate_RefusesNonProfileFields(t *testing.T) {
	f := newUpdFixture(t)
	svc := f.serviceToken(t, f.billing)
	for _, body := range []string{
		`{"email":"evil@example.test"}`,
		`{"name":"x","password":"hunter2hunter2"}`,
		`{"role":"admin"}`,
		`{"is_verified":true}`,
		`{}`,
		`not json`,
	} {
		if rr := f.patch("3", "10", svc, body); rr.Code != nethttp.StatusBadRequest {
			t.Errorf("%s → %d %s, want 400", body, rr.Code, rr.Body.String())
		}
	}
	if u := f.users.users[10]; u.Name != "Alice" || u.Email != "alice@example.test" || len(f.audit.calls) != 0 {
		t.Fatalf("a refused request changed state: %+v, audit %d", u, len(f.audit.calls))
	}
	if rr := f.patch("3", "10", svc, `{"avatar_url":"javascript:alert(1)"}`); rr.Code != nethttp.StatusBadRequest ||
		!strings.Contains(rr.Body.String(), "invalid avatar_url") {
		t.Errorf("bad avatar → %d %s", rr.Code, rr.Body.String())
	}
}

// An app edits only its own members: another app's member, a Socrate admin
// and an unknown user are 404s, and the caller must be the app itself.
func TestServiceUserUpdate_OnlyTheAppsOwnMembers(t *testing.T) {
	f := newUpdFixture(t)
	svc := f.serviceToken(t, f.billing)
	for name, id := range map[string]string{"other app's member": "11", "socrate admin": "1", "unknown": "999"} {
		if rr := f.patch("3", id, svc, `{"name":"x"}`); rr.Code != nethttp.StatusNotFound {
			t.Errorf("%s → %d, want 404", name, rr.Code)
		}
	}
	if rr := f.patch("3", "10", f.serviceToken(t, f.crm), `{"name":"x"}`); rr.Code != nethttp.StatusForbidden {
		t.Errorf("other app's token → %d, want 403", rr.Code)
	}
	if rr := f.patch("3", "10", f.userToken(t, f.alice), `{"name":"x"}`); rr.Code != nethttp.StatusForbidden {
		t.Errorf("user token → %d, want 403", rr.Code)
	}
	if rr := f.patch("3", "10", "garbage", `{"name":"x"}`); rr.Code != nethttp.StatusUnauthorized {
		t.Errorf("garbage token → %d, want 401", rr.Code)
	}
	if f.users.users[10].Name != "Alice" || f.users.users[1].Name != "Root" || len(f.audit.calls) != 0 {
		t.Fatal("a refused request changed state")
	}
}
