package handler

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ovander/go-oauth2/internal/model"
)

// sessionActionService records the session actions taken.
type sessionActionService struct {
	*attrUserService
	revoked, unlocked []uint
}

func (s *sessionActionService) RevokeTokens(_ context.Context, id uint) error {
	s.revoked = append(s.revoked, id)
	return nil
}

func (s *sessionActionService) Unlock(_ context.Context, id uint) error {
	s.unlocked = append(s.unlocked, id)
	return nil
}

// #366: one rule for every per-user admin action on a superadmin's account —
// only a superadmin may take it. An admin can no longer sign a superadmin out
// or unlock one; a superadmin still can, and an admin still acts on users.
func TestSuperadminTarget_SessionActions(t *testing.T) {
	_, attr, _ := newAttrHandler(t)
	us := &sessionActionService{attrUserService: attr}
	h := newTestAdminHandler(us)
	h.adminLogService = &recordingAdminLog{}

	for _, action := range []struct {
		name string
		call func(http.ResponseWriter, *http.Request)
		done func() []uint
	}{
		{"revoke-tokens", h.RevokeUserTokens, func() []uint { return us.revoked }},
		{"unlock", h.UnlockUser, func() []uint { return us.unlocked }},
	} {
		for _, tc := range []struct {
			name     string
			callerID uint
			role     model.UserRole
			target   string
			want     int
		}{
			{"admin on a superadmin", 7, model.UserRoleAdmin, "8", http.StatusForbidden},
			{"superadmin on a superadmin", 1, model.UserRoleSuperadmin, "8", http.StatusOK},
			{"admin on a user", 7, model.UserRoleAdmin, "9", http.StatusOK},
		} {
			before := len(action.done())
			r := httptest.NewRequest(http.MethodPost, "/api/admin/users/"+tc.target+"/"+action.name, nil)
			r = chiCtxWithID(r.WithContext(adminCtx(tc.callerID, tc.role)), tc.target)
			rr := httptest.NewRecorder()
			action.call(rr, r)
			taken := len(action.done()) > before
			if rr.Code != tc.want || taken != (tc.want == http.StatusOK) {
				t.Errorf("%s, %s: %d %s (taken %v), want %d", action.name, tc.name, rr.Code, rr.Body.String(), taken, tc.want)
			}
		}
	}
}
