package service

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ovander/go-oauth2/internal/dto"
	"github.com/ovander/go-oauth2/internal/hooks"
	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/repository"
	"github.com/ovander/go-oauth2/internal/shared/auth"
	"github.com/ovander/go-oauth2/pkg/logger"
	"gorm.io/gorm"
)

type UserService interface {
	List(ctx context.Context, page, pageSize int) ([]model.User, int64, error)
	GetByID(ctx context.Context, id uint) (*model.User, error)
	GetByEmail(ctx context.Context, email string) (*model.User, error)
	Create(ctx context.Context, req dto.CreateUserRequest) (*model.User, error)
	Update(ctx context.Context, id uint, req dto.UpdateUserRequest) (*model.User, error)
	UpdateProfile(ctx context.Context, userID uint, req dto.UpdateProfileRequest) (*model.User, error)
	Delete(ctx context.Context, id uint) error
	VerifyEmail(ctx context.Context, userID uint) error
	UpdatePassword(ctx context.Context, userID uint, newPassword string) error
	IncrementTokenVersion(ctx context.Context, userID uint) error
	RevokeTokens(ctx context.Context, userID uint) error
	Unlock(ctx context.Context, userID uint) error
	// Block sets locked_until to a far-future date, permanently barring login
	// until an admin explicitly unlocks the account.  Superadmins cannot be
	// blocked via this method (use DeleteSuperadmin for that).
	Block(ctx context.Context, userID uint) error

	// Superadmin management
	ListSuperadmins(ctx context.Context) ([]model.User, error)
	CountSuperadmins(ctx context.Context) (int64, error)
	CreateSuperadmin(ctx context.Context, req dto.CreateSuperadminRequest) (*model.User, error)
	UpdateSuperadmin(ctx context.Context, id uint, req dto.UpdateSuperadminRequest) (*model.User, error)
	DeleteSuperadmin(ctx context.Context, id uint, currentUserID uint) error
}

type userService struct {
	repo repository.UserRepository
}

func NewUserService(repo repository.UserRepository) UserService {
	logger.WithFields(logger.Fields{
		"service": "user",
	}).Debug("✅ User service initialized")

	return &userService{repo: repo}
}

func (s *userService) List(ctx context.Context, page, pageSize int) ([]model.User, int64, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	return s.repo.FindAll(ctx, page, pageSize)
}

func (s *userService) GetByID(ctx context.Context, id uint) (*model.User, error) {
	user, err := s.repo.FindByID(ctx, id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return user, nil
}

func (s *userService) GetByEmail(ctx context.Context, email string) (*model.User, error) {
	user, err := s.repo.FindByEmail(ctx, email)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrUserNotFound
		}
		return nil, err
	}
	return user, nil
}

func (s *userService) Create(ctx context.Context, req dto.CreateUserRequest) (*model.User, error) {
	// Check if email already exists
	existing, err := s.repo.FindByEmail(ctx, req.Email)
	if err == nil && existing != nil {
		return nil, ErrEmailAlreadyExists
	}

	// Validate password
	if err := auth.ValidatePassword(req.Password); err != nil {
		return nil, err
	}

	// Hash password
	hashedPassword, err := auth.HashPassword(req.Password)
	if err != nil {
		return nil, err
	}

	role := model.UserRoleUser
	if req.Role != "" {
		role = model.UserRole(req.Role)
	}

	user := &model.User{
		Email:          req.Email,
		Name:           req.Name,
		HashedPassword: hashedPassword,
		Role:           role,
		IsVerified:     false,
		TokenVersion:   1,
		Source:         "manual",
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}

	if err := s.repo.Create(ctx, user); err != nil {
		return nil, err
	}
	hooks.RunUserProvisioned(ctx, hooks.UserProvisioned{User: user, Source: "admin"})

	return user, nil
}

func (s *userService) Update(ctx context.Context, id uint, req dto.UpdateUserRequest) (*model.User, error) {
	user, err := s.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	if req.Name != nil {
		user.Name = *req.Name
	}
	if req.Email != nil {
		// Check if new email already exists
		existing, err := s.repo.FindByEmail(ctx, *req.Email)
		if err == nil && existing != nil && existing.ID != id {
			return nil, ErrEmailAlreadyExists
		}
		user.Email = *req.Email
	}
	if req.Title != nil {
		user.Title = req.Title
	}
	if req.Division != nil {
		user.Division = req.Division
	}
	if req.Company != nil {
		user.Company = req.Company
	}
	if req.Country != nil {
		user.Country = req.Country
	}
	if req.Phone != nil {
		user.Phone = req.Phone
	}
	if req.JobTitle != nil {
		user.JobTitle = req.JobTitle
	}
	if req.Department != nil {
		user.Department = req.Department
	}
	if req.Language != nil {
		user.Language = req.Language
	}
	if req.Timezone != nil {
		user.Timezone = req.Timezone
	}
	// A2: replace the attribute set wholesale — an empty object clears it.
	if req.Attributes != nil {
		if err := validateUserAttributes(*req.Attributes); err != nil {
			return nil, err
		}
		user.Attributes = *req.Attributes
	}

	user.UpdatedAt = time.Now()

	if err := s.repo.Update(ctx, user); err != nil {
		return nil, err
	}

	return user, nil
}

// Attribute bounds (A2). Attributes are projected into tokens via claim
// mappings, so an unbounded attribute set would be an unbounded token; these
// limits are the first line of defence, with the issuance-time size cap
// (auth.MaxCustomClaimsBytes) as the second.
const (
	MaxUserAttributes    = 32
	MaxUserAttributeName = 64
	MaxUserAttributeSize = 4096
)

// validateUserAttributes bounds the attribute set an admin may store on a user.
func validateUserAttributes(attrs model.JSONMap) error {
	if len(attrs) > MaxUserAttributes {
		return fmt.Errorf("%w: at most %d attributes", ErrInvalidUserAttributes, MaxUserAttributes)
	}
	for name := range attrs {
		if name == "" {
			return fmt.Errorf("%w: empty attribute name", ErrInvalidUserAttributes)
		}
		if len(name) > MaxUserAttributeName {
			return fmt.Errorf("%w: attribute name %q exceeds %d characters", ErrInvalidUserAttributes, name, MaxUserAttributeName)
		}
	}
	encoded, err := json.Marshal(map[string]any(attrs))
	if err != nil {
		return fmt.Errorf("%w: not serializable: %s", ErrInvalidUserAttributes, err)
	}
	if len(encoded) > MaxUserAttributeSize {
		return fmt.Errorf("%w: attribute set exceeds %d bytes", ErrInvalidUserAttributes, MaxUserAttributeSize)
	}
	return nil
}

func (s *userService) UpdateProfile(ctx context.Context, userID uint, req dto.UpdateProfileRequest) (*model.User, error) {
	user, err := s.GetByID(ctx, userID)
	if err != nil {
		return nil, err
	}

	if req.Name != nil {
		user.Name = *req.Name
	}
	if req.Title != nil {
		user.Title = req.Title
	}
	if req.Division != nil {
		user.Division = req.Division
	}
	if req.Company != nil {
		user.Company = req.Company
	}
	if req.Country != nil {
		user.Country = req.Country
	}
	if req.Phone != nil {
		user.Phone = req.Phone
	}
	if req.JobTitle != nil {
		user.JobTitle = req.JobTitle
	}
	if req.Department != nil {
		user.Department = req.Department
	}
	if req.Language != nil {
		user.Language = req.Language
	}
	if req.Timezone != nil {
		user.Timezone = req.Timezone
	}

	user.UpdatedAt = time.Now()

	if err := s.repo.Update(ctx, user); err != nil {
		return nil, err
	}

	return user, nil
}

func (s *userService) Delete(ctx context.Context, id uint) error {
	_, err := s.GetByID(ctx, id)
	if err != nil {
		return err
	}
	return s.repo.Delete(ctx, id)
}

func (s *userService) VerifyEmail(ctx context.Context, userID uint) error {
	user, err := s.GetByID(ctx, userID)
	if err != nil {
		return err
	}

	user.IsVerified = true
	now := time.Now()
	user.ConfirmedAt = &now
	user.UpdatedAt = now

	return s.repo.Update(ctx, user)
}

func (s *userService) UpdatePassword(ctx context.Context, userID uint, newPassword string) error {
	user, err := s.GetByID(ctx, userID)
	if err != nil {
		return err
	}

	// Validate password
	if err := auth.ValidatePassword(newPassword); err != nil {
		return err
	}

	// Hash password
	hashedPassword, err := auth.HashPassword(newPassword)
	if err != nil {
		return err
	}

	user.HashedPassword = hashedPassword
	user.UpdatedAt = time.Now()

	if err := s.repo.Update(ctx, user); err != nil {
		return err
	}

	// Invalidate all existing tokens
	return s.repo.IncrementTokenVersion(ctx, userID)
}

func (s *userService) IncrementTokenVersion(ctx context.Context, userID uint) error {
	return s.repo.IncrementTokenVersion(ctx, userID)
}

func (s *userService) RevokeTokens(ctx context.Context, userID uint) error {
	// Incrementing token version invalidates all existing tokens
	return s.repo.IncrementTokenVersion(ctx, userID)
}

func (s *userService) Unlock(ctx context.Context, userID uint) error {
	user, err := s.GetByID(ctx, userID)
	if err != nil {
		return err
	}

	user.LockedUntil = nil
	user.FailedLoginAttempts = 0
	user.UpdatedAt = time.Now()

	return s.repo.Update(ctx, user)
}

func (s *userService) Block(ctx context.Context, userID uint) error {
	user, err := s.GetByID(ctx, userID)
	if err != nil {
		return err
	}

	if user.Role == model.UserRoleSuperadmin {
		return errors.New("cannot block a superadmin; remove the account instead")
	}

	// Lock until far future — effectively permanent until an admin calls Unlock.
	farFuture := time.Now().Add(100 * 365 * 24 * time.Hour)
	until := &farFuture
	if err := s.repo.LockAccount(ctx, userID, until); err != nil {
		return err
	}
	// P3-3: blocking is a revocation event. Bump the token version so every
	// outstanding access/refresh token is rejected by the version check
	// (AuthMiddleware, introspection, the refresh grant) rather than staying
	// valid until it expires.
	return s.repo.IncrementTokenVersion(ctx, userID)
}

// Superadmin management

func (s *userService) ListSuperadmins(ctx context.Context) ([]model.User, error) {
	return s.repo.FindByRole(ctx, model.UserRoleSuperadmin)
}

func (s *userService) CountSuperadmins(ctx context.Context) (int64, error) {
	return s.repo.CountByRole(ctx, model.UserRoleSuperadmin)
}

func (s *userService) CreateSuperadmin(ctx context.Context, req dto.CreateSuperadminRequest) (*model.User, error) {
	// Check if email already exists
	existing, err := s.repo.FindByEmail(ctx, req.Email)
	if err == nil && existing != nil {
		return nil, ErrEmailAlreadyExists
	}

	// Validate password
	if err := auth.ValidatePassword(req.Password); err != nil {
		return nil, err
	}

	// Hash password
	hashedPassword, err := auth.HashPassword(req.Password)
	if err != nil {
		return nil, err
	}

	user := &model.User{
		Email:          req.Email,
		Name:           req.Name,
		HashedPassword: hashedPassword,
		Role:           model.UserRoleSuperadmin,
		IsVerified:     true, // Superadmins are auto-verified
		TokenVersion:   1,
		Source:         "admin",
		CreatedAt:      time.Now(),
		UpdatedAt:      time.Now(),
	}

	if err := s.repo.Create(ctx, user); err != nil {
		return nil, err
	}
	hooks.RunUserProvisioned(ctx, hooks.UserProvisioned{User: user, Source: "superadmin"})

	return user, nil
}

func (s *userService) UpdateSuperadmin(ctx context.Context, id uint, req dto.UpdateSuperadminRequest) (*model.User, error) {
	user, err := s.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	// Verify the user is a superadmin
	if user.Role != model.UserRoleSuperadmin {
		return nil, ErrNotAdmin
	}

	if req.Name != nil {
		user.Name = *req.Name
	}
	if req.Email != nil {
		// Check if new email already exists
		existing, err := s.repo.FindByEmail(ctx, *req.Email)
		if err == nil && existing != nil && existing.ID != id {
			return nil, ErrEmailAlreadyExists
		}
		user.Email = *req.Email
	}
	if req.Password != nil {
		// Validate password
		if err := auth.ValidatePassword(*req.Password); err != nil {
			return nil, err
		}
		// Hash password
		hashedPassword, err := auth.HashPassword(*req.Password)
		if err != nil {
			return nil, err
		}
		user.HashedPassword = hashedPassword
	}

	user.UpdatedAt = time.Now()

	if err := s.repo.Update(ctx, user); err != nil {
		return nil, err
	}

	return user, nil
}

func (s *userService) DeleteSuperadmin(ctx context.Context, id uint, currentUserID uint) error {
	// Cannot delete yourself
	if id == currentUserID {
		return ErrCannotDeleteSelf
	}

	user, err := s.GetByID(ctx, id)
	if err != nil {
		return err
	}

	// Verify the user is a superadmin
	if user.Role != model.UserRoleSuperadmin {
		return ErrNotAdmin
	}

	// Cannot delete the last superadmin
	count, err := s.CountSuperadmins(ctx)
	if err != nil {
		return err
	}
	if count <= 1 {
		return ErrCannotDeleteLastSuperadmin
	}

	return s.repo.Delete(ctx, id)
}
