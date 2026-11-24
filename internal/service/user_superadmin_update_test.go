package service

import (
	"context"
	"errors"
	"testing"

	"github.com/ovander/go-oauth2/internal/dto"
	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/repository"
)

// superadminRepo keeps users and counts token-version bumps.
type superadminRepo struct {
	repository.UserRepository
	users  map[uint]*model.User
	bumped int
}

func (r *superadminRepo) FindByID(_ context.Context, id uint) (*model.User, error) {
	u, ok := r.users[id]
	if !ok {
		return nil, errors.New("record not found")
	}
	cp := *u
	return &cp, nil
}

func (r *superadminRepo) FindByEmail(_ context.Context, email string) (*model.User, error) {
	for _, u := range r.users {
		if u.Email == email {
			cp := *u
			return &cp, nil
		}
	}
	return nil, errors.New("record not found")
}

func (r *superadminRepo) Update(_ context.Context, u *model.User) error {
	cp := *u
	r.users[u.ID] = &cp
	return nil
}

func (r *superadminRepo) IncrementTokenVersion(_ context.Context, id uint) error {
	r.bumped++
	r.users[id].TokenVersion++
	return nil
}

func strp(s string) *string { return &s }

// Changing a superadmin's email or password revokes their existing sessions;
// a name change, or setting the email to its current value, does not.
func TestUpdateSuperadmin_CredentialChangesRevokeSessions(t *testing.T) {
	for name, tc := range map[string]struct {
		req        dto.UpdateSuperadminRequest
		wantBumped int
	}{
		"password":           {dto.UpdateSuperadminRequest{Password: strp("A-new-Passw0rd!x")}, 1},
		"email":              {dto.UpdateSuperadminRequest{Email: strp("new@example.com")}, 1},
		"email and password": {dto.UpdateSuperadminRequest{Email: strp("new@example.com"), Password: strp("A-new-Passw0rd!x")}, 1},
		"name only":          {dto.UpdateSuperadminRequest{Name: strp("Renamed")}, 0},
		"same email":         {dto.UpdateSuperadminRequest{Email: strp("root@example.com")}, 0},
	} {
		t.Run(name, func(t *testing.T) {
			repo := &superadminRepo{users: map[uint]*model.User{
				2: {ID: 2, Email: "root@example.com", Role: model.UserRoleSuperadmin},
			}}
			u, err := NewUserService(repo).UpdateSuperadmin(context.Background(), 2, tc.req)
			if err != nil {
				t.Fatal(err)
			}
			if repo.bumped != tc.wantBumped {
				t.Fatalf("token version bumped %d times, want %d", repo.bumped, tc.wantBumped)
			}
			if tc.req.Password != nil && u.PasswordChangedAt == nil {
				t.Error("password_changed_at not set")
			}
		})
	}
}
