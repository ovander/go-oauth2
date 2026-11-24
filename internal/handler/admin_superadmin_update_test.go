package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/ovander/go-oauth2/internal/contextkeys"
	"github.com/ovander/go-oauth2/internal/dto"
	"github.com/ovander/go-oauth2/internal/model"
)

// updateSuperadminUserService records the update it receives.
type updateSuperadminUserService struct {
	*adminTestUserService
	called bool
	got    dto.UpdateSuperadminRequest
}

func (s *updateSuperadminUserService) UpdateSuperadmin(_ context.Context, id uint, req dto.UpdateSuperadminRequest) (*model.User, error) {
	s.called, s.got = true, req
	return &model.User{ID: id, Email: "other@example.com", Role: model.UserRoleSuperadmin}, nil
}

func putSuperadmin(h *AdminHandler, callerID uint, targetID, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPut, "/api/admin/superadmins/"+targetID, strings.NewReader(body))
	rctx := chi.NewRouteContext()
	rctx.URLParams.Add("id", targetID)
	ctx := context.WithValue(r.Context(), chi.RouteCtxKey, rctx)
	ctx = context.WithValue(ctx, contextkeys.UserIDKey, callerID)
	rr := httptest.NewRecorder()
	h.UpdateSuperadmin(rr, r.WithContext(ctx))
	return rr
}

// An admin cannot set their own password here: they use change-password,
// which asks for the current one. Other fields of their own account, and
// another superadmin's password, still go through.
func TestUpdateSuperadmin_OwnPasswordRefused(t *testing.T) {
	us := &updateSuperadminUserService{adminTestUserService: &adminTestUserService{}}
	h := newTestAdminHandler(us)

	rr := putSuperadmin(h, 7, "7", `{"password":"A-new-Passw0rd!x"}`)
	if rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "change-password") || us.called {
		t.Fatalf("own password: %d %s (service called %v), want 400 pointing to change-password", rr.Code, rr.Body.String(), us.called)
	}

	if rr := putSuperadmin(h, 7, "7", `{"name":"Me"}`); rr.Code != http.StatusOK || !us.called {
		t.Fatalf("own name: %d %s", rr.Code, rr.Body.String())
	}
	us.called = false
	if rr := putSuperadmin(h, 7, "9", `{"password":"A-new-Passw0rd!x"}`); rr.Code != http.StatusOK || !us.called || us.got.Password == nil {
		t.Fatalf("another superadmin's password: %d %s", rr.Code, rr.Body.String())
	}
}
