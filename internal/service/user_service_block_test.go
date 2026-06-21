// Package service — unit tests for UserService.Block.
//
// Block is the "permanent ban" operation added alongside DeleteUser / BlockUser
// admin-panel handlers.  These tests use an in-memory UserRepository stub so
// that no database is required.
package service

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/ovandermoten/go-oauth2/internal/model"
	"github.com/ovandermoten/go-oauth2/internal/repository"
)

// ---------------------------------------------------------------------------
// In-memory UserRepository stub
// ---------------------------------------------------------------------------

// memUserRepo is a minimal in-memory UserRepository that only implements the
// methods exercised by the Block code-path.
type memUserRepo struct {
	users map[uint]*model.User
	// lockCalled records whether LockAccount was called and with which args.
	lockCalled bool
	lockUserID uint
	lockUntil  *time.Time
}

func newMemUserRepo(us ...*model.User) *memUserRepo {
	m := &memUserRepo{users: make(map[uint]*model.User)}
	for _, u := range us {
		m.users[u.ID] = u
	}
	return m
}

// FindByID satisfies the path used by userService.GetByID.
func (r *memUserRepo) FindByID(_ context.Context, id uint) (*model.User, error) {
	u, ok := r.users[id]
	if !ok {
		return nil, errors.New("record not found")
	}
	return u, nil
}

func (r *memUserRepo) LockAccount(_ context.Context, userID uint, until *time.Time) error {
	r.lockCalled = true
	r.lockUserID = userID
	r.lockUntil = until
	if u, ok := r.users[userID]; ok {
		u.LockedUntil = until
	}
	return nil
}

// --- stubs for the rest of the interface (not exercised by Block) ---

func (r *memUserRepo) FindAll(_ context.Context, _, _ int) ([]model.User, int64, error) {
	panic("not implemented")
}
func (r *memUserRepo) FindByEmail(_ context.Context, _ string) (*model.User, error) {
	panic("not implemented")
}
func (r *memUserRepo) FindByRole(_ context.Context, _ model.UserRole) ([]model.User, error) {
	panic("not implemented")
}
func (r *memUserRepo) CountByRole(_ context.Context, _ model.UserRole) (int64, error) {
	panic("not implemented")
}
func (r *memUserRepo) Create(_ context.Context, _ *model.User) error { panic("not implemented") }
func (r *memUserRepo) Update(_ context.Context, _ *model.User) error { panic("not implemented") }
func (r *memUserRepo) Delete(_ context.Context, _ uint) error        { panic("not implemented") }
func (r *memUserRepo) IncrementTokenVersion(_ context.Context, _ uint) error {
	panic("not implemented")
}
func (r *memUserRepo) IncrementFailedLoginAttempts(_ context.Context, _ uint) error {
	panic("not implemented")
}
func (r *memUserRepo) ResetFailedLoginAttempts(_ context.Context, _ uint) error {
	panic("not implemented")
}

// Compile-time interface check.
var _ repository.UserRepository = (*memUserRepo)(nil)

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

func TestBlock_HappyPath(t *testing.T) {
	const targetID = uint(42)
	user := &model.User{ID: targetID, Email: "victim@example.com", Role: model.UserRoleUser}
	repo := newMemUserRepo(user)
	svc := NewUserService(repo)

	if err := svc.Block(context.Background(), targetID); err != nil {
		t.Fatalf("Block returned unexpected error: %v", err)
	}

	if !repo.lockCalled {
		t.Fatal("expected LockAccount to be called")
	}
	if repo.lockUserID != targetID {
		t.Errorf("LockAccount called with user %d, want %d", repo.lockUserID, targetID)
	}
	if repo.lockUntil == nil {
		t.Fatal("expected a non-nil lock timestamp")
	}
	// The far-future timestamp must be at least 90 years from now.
	minExpiry := time.Now().Add(90 * 365 * 24 * time.Hour)
	if repo.lockUntil.Before(minExpiry) {
		t.Errorf("locked_until %v is sooner than expected minimum %v", repo.lockUntil, minExpiry)
	}
}

func TestBlock_RejectsSuperadmin(t *testing.T) {
	const targetID = uint(1)
	user := &model.User{ID: targetID, Email: "super@example.com", Role: model.UserRoleSuperadmin}
	repo := newMemUserRepo(user)
	svc := NewUserService(repo)

	err := svc.Block(context.Background(), targetID)
	if err == nil {
		t.Fatal("expected error when blocking a superadmin, got nil")
	}
	if repo.lockCalled {
		t.Error("LockAccount must NOT be called when the target is a superadmin")
	}
}

func TestBlock_UserNotFound(t *testing.T) {
	repo := newMemUserRepo() // empty — no users
	svc := NewUserService(repo)

	err := svc.Block(context.Background(), 999)
	if err == nil {
		t.Fatal("expected error when blocking a non-existent user, got nil")
	}
	if repo.lockCalled {
		t.Error("LockAccount must NOT be called when the user does not exist")
	}
}

func TestBlock_RegularAdminCanBeBlocked(t *testing.T) {
	// A user with role=admin (not superadmin) can be blocked via this method.
	const targetID = uint(5)
	user := &model.User{ID: targetID, Email: "admin@example.com", Role: model.UserRoleAdmin}
	repo := newMemUserRepo(user)
	svc := NewUserService(repo)

	if err := svc.Block(context.Background(), targetID); err != nil {
		t.Fatalf("Block returned unexpected error for an admin user: %v", err)
	}
	if !repo.lockCalled {
		t.Fatal("expected LockAccount to be called for a regular admin")
	}
}
