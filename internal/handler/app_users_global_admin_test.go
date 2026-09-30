package handler

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ovander/go-oauth2/internal/dto"
	"github.com/ovander/go-oauth2/internal/model"
)

// TestCreateAppUser_RejectsEverySocrateAdmin: a Socrate admin or superadmin can
// never be made an app member, whatever the app role requested.
func TestCreateAppUser_RejectsEverySocrateAdmin(t *testing.T) {
	for _, global := range []model.UserRole{model.UserRoleSuperadmin, model.UserRoleAdmin} {
		for _, appRole := range model.ValidAppRoles {
			t.Run(fmt.Sprintf("%s as app %s", global, appRole), func(t *testing.T) {
				created := false
				us := &appUsersTestUserService{
					getByEmail: func(_ context.Context, _ string) (*model.User, error) {
						return &model.User{ID: 99, Email: "platform@example.com", Role: global}, nil
					},
					create: func(_ context.Context, _ dto.CreateUserRequest) (*model.User, error) {
						created = true
						return nil, nil
					},
				}
				h := newTestAppUsersHandler(us)
				rr := httptest.NewRecorder()
				h.CreateUser(rr, appUsersRequest(1, 1, fmt.Sprintf(`{"email":"platform@example.com","role":%q}`, appRole)))

				if rr.Code != http.StatusForbidden {
					t.Errorf("status = %d, want 403 (body: %s)", rr.Code, rr.Body.String())
				}
				if created {
					t.Error("no user may be created when the target is a Socrate admin")
				}
			})
		}
	}
}
