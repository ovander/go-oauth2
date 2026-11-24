package service

import (
	"context"
	"errors"
	"testing"

	"github.com/ovander/go-oauth2/internal/dto"
	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/repository"
)

// superadminRepo keeps users. Update saves the whole row, as the GORM
// repository does; UpdateProfile writes only the profile columns.
type superadminRepo struct {
	repository.UserRepository
	users        map[uint]*model.User
	incrementErr error
	updateErr    error
	// beforeWrite runs between the service's read and its write, to
	// simulate a concurrent change.
	beforeWrite func()
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
	if r.beforeWrite != nil {
		r.beforeWrite()
	}
	if r.updateErr != nil {
		return r.updateErr
	}
	cp := *u
	r.users[u.ID] = &cp
	return nil
}

func (r *superadminRepo) UpdateProfile(_ context.Context, u *model.User, revokeSessions bool) error {
	if r.beforeWrite != nil {
		r.beforeWrite()
	}
	if r.updateErr != nil {
		return r.updateErr
	}
	s := r.users[u.ID]
	s.Name, s.Email, s.HashedPassword = u.Name, u.Email, u.HashedPassword
	s.PasswordChangedAt, s.UpdatedAt = u.PasswordChangedAt, u.UpdatedAt
	if revokeSessions {
		s.TokenVersion++
	}
	return nil
}

func (r *superadminRepo) IncrementTokenVersion(_ context.Context, id uint) error {
	if r.incrementErr != nil {
		return r.incrementErr
	}
	r.users[id].TokenVersion++
	return nil
}

// versionOf is the stored token version.
func (r *superadminRepo) versionOf(id uint) int { return r.users[id].TokenVersion }

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
			if got := repo.versionOf(2); got != tc.wantBumped {
				t.Fatalf("stored token version %d, want %d", got, tc.wantBumped)
			}
			if tc.req.Password != nil && u.PasswordChangedAt == nil {
				t.Error("password_changed_at not set")
			}
		})
	}
}

// The new credentials and the session revocation are one write: the stored
// token version moves with the password even if a separate increment would
// fail, and nothing is stored when the write fails.
func TestUpdateSuperadmin_RevocationIsPartOfTheSameWrite(t *testing.T) {
	repo := &superadminRepo{users: map[uint]*model.User{
		2: {ID: 2, Email: "root@example.com", Role: model.UserRoleSuperadmin, HashedPassword: "old"},
	}, incrementErr: errors.New("db down")}
	if _, err := NewUserService(repo).UpdateSuperadmin(context.Background(), 2, dto.UpdateSuperadminRequest{Password: strp("A-new-Passw0rd!x")}); err != nil {
		t.Fatalf("update: %v", err)
	}
	if repo.versionOf(2) != 1 || repo.users[2].HashedPassword == "old" {
		t.Fatalf("stored version %d, password changed %v; want 1, true", repo.versionOf(2), repo.users[2].HashedPassword != "old")
	}

	failing := &superadminRepo{users: map[uint]*model.User{
		2: {ID: 2, Email: "root@example.com", Role: model.UserRoleSuperadmin, HashedPassword: "old"},
	}, updateErr: errors.New("db down")}
	if _, err := NewUserService(failing).UpdateSuperadmin(context.Background(), 2, dto.UpdateSuperadminRequest{Password: strp("A-new-Passw0rd!x")}); err == nil {
		t.Fatal("a failed write must be reported")
	}
	if failing.users[2].HashedPassword != "old" || failing.versionOf(2) != 0 {
		t.Fatal("a failed write must change nothing")
	}
}

// Saving the edit does not undo a revocation or failed sign-in recorded
// between the service's read and its write (a full-row save would).
func TestUpdateSuperadmin_KeepsConcurrentChanges(t *testing.T) {
	for name, tc := range map[string]struct {
		req         dto.UpdateSuperadminRequest
		wantVersion int
	}{
		"name only": {dto.UpdateSuperadminRequest{Name: strp("Renamed")}, 1},
		"password":  {dto.UpdateSuperadminRequest{Password: strp("A-new-Passw0rd!x")}, 2},
	} {
		t.Run(name, func(t *testing.T) {
			repo := &superadminRepo{users: map[uint]*model.User{
				2: {ID: 2, Email: "root@example.com", Role: model.UserRoleSuperadmin},
			}}
			repo.beforeWrite = func() {
				repo.users[2].TokenVersion++
				repo.users[2].FailedLoginAttempts++
			}
			if _, err := NewUserService(repo).UpdateSuperadmin(context.Background(), 2, tc.req); err != nil {
				t.Fatal(err)
			}
			if got := repo.users[2]; got.TokenVersion != tc.wantVersion || got.FailedLoginAttempts != 1 {
				t.Fatalf("token version %d, failed attempts %d; want %d, 1", got.TokenVersion, got.FailedLoginAttempts, tc.wantVersion)
			}
		})
	}
}
