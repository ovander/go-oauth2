package service

import (
	"context"
	"errors"
	"time"

	"github.com/ovandermoten/go-oauth2/internal/dto"
	"github.com/ovandermoten/go-oauth2/internal/model"
	"github.com/ovandermoten/go-oauth2/internal/repository"
	"github.com/ovandermoten/go-oauth2/internal/shared/auth"
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
}

type userService struct {
	repo repository.UserRepository
}

func NewUserService(repo repository.UserRepository) UserService {
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

	user.UpdatedAt = time.Now()

	if err := s.repo.Update(ctx, user); err != nil {
		return nil, err
	}

	return user, nil
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
