package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"github.com/ovander/go-oauth2/internal/dto"
	"github.com/ovander/go-oauth2/internal/model"
)

// attrUserService serves GetByID from users and records Update.
type attrUserService struct {
	*adminTestUserService
	users   map[uint]*model.User
	updated bool
}

func (s *attrUserService) Update(_ context.Context, id uint, req dto.UpdateUserRequest) (*model.User, error) {
	s.updated = true
	u := *s.users[id]
	if req.Attributes != nil {
		u.Attributes = *req.Attributes
	}
	return &u, nil
}

// recordingAdminLog keeps the details of the last audit entry.
type recordingAdminLog struct {
	noopAdminLogService
	details map[string]interface{}
}

func (l *recordingAdminLog) LogAction(_ context.Context, _ uint, _ *uint, _ *uint, _ model.AdminAction, d map[string]interface{}) error {
	l.details = d
	return nil
}

func newAttrHandler(t *testing.T) (*AdminHandler, *attrUserService, *recordingAdminLog) {
	t.Helper()
	us := &attrUserService{users: map[uint]*model.User{
		7: {ID: 7, Email: "admin@example.com", Role: model.UserRoleAdmin},
		8: {ID: 8, Email: "root@example.com", Role: model.UserRoleSuperadmin},
		9: {ID: 9, Email: "user@example.com", Role: model.UserRoleUser,
			Attributes: model.JSONMap{"tier": "gold", "region": "eu", "legacy": true}},
	}}
	us.adminTestUserService = &adminTestUserService{getByID: func(_ context.Context, id uint) (*model.User, error) {
		u := *us.users[id]
		return &u, nil
	}}
	log := &recordingAdminLog{}
	h := newTestAdminHandler(us)
	h.adminLogService = log
	return h, us, log
}

func putAttributes(h *AdminHandler, callerID uint, role model.UserRole, target, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPut, "/api/admin/users/"+target+"/attributes", strings.NewReader(body))
	r = chiCtxWithID(r.WithContext(adminCtx(callerID, role)), target)
	rr := httptest.NewRecorder()
	h.UpdateUserAttributes(rr, r)
	return rr
}

// Policy rules read these attributes to constrain admins: an admin cannot
// change their own, and only a superadmin changes a superadmin's.
func TestUpdateUserAttributes_Guards(t *testing.T) {
	h, us, _ := newAttrHandler(t)
	if rr := putAttributes(h, 7, model.UserRoleAdmin, "7", `{"attributes":{"tier":"gold"}}`); rr.Code != http.StatusBadRequest || us.updated {
		t.Fatalf("own attributes: %d %s (updated %v), want 400 without update", rr.Code, rr.Body.String(), us.updated)
	}
	if rr := putAttributes(h, 7, model.UserRoleAdmin, "8", `{"attributes":{"tier":"gold"}}`); rr.Code != http.StatusForbidden || us.updated {
		t.Fatalf("admin on a superadmin: %d %s (updated %v), want 403 without update", rr.Code, rr.Body.String(), us.updated)
	}
	if rr := putAttributes(h, 1, model.UserRoleSuperadmin, "8", `{"attributes":{"tier":"gold"}}`); rr.Code != http.StatusOK || !us.updated {
		t.Fatalf("superadmin on a superadmin: %d %s", rr.Code, rr.Body.String())
	}
	us.updated = false
	if rr := putAttributes(h, 7, model.UserRoleAdmin, "9", `{"attributes":{"tier":"gold"}}`); rr.Code != http.StatusOK || !us.updated {
		t.Fatalf("admin on a user: %d %s", rr.Code, rr.Body.String())
	}
}

// The audit entry names the attributes added, changed and removed, never
// their values.
func TestUpdateUserAttributes_AuditsTheChange(t *testing.T) {
	h, _, log := newAttrHandler(t)
	rr := putAttributes(h, 7, model.UserRoleAdmin, "9", `{"attributes":{"tier":"platinum","region":"eu","team":"ops"}}`)
	if rr.Code != http.StatusOK {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	for key, want := range map[string][]string{"added": {"team"}, "changed": {"tier"}, "removed": {"legacy"}} {
		if got, _ := log.details[key].([]string); !reflect.DeepEqual(got, want) {
			t.Errorf("%s = %v, want %v", key, log.details[key], want)
		}
	}
	for _, v := range log.details {
		if s, ok := v.(string); ok && (s == "platinum" || s == "gold" || s == "ops") {
			t.Errorf("an attribute value reached the audit entry: %v", log.details)
		}
	}
}
