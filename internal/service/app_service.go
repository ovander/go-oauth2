package service

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/ovandermoten/go-oauth2/internal/dto"
	"github.com/ovandermoten/go-oauth2/internal/model"
	"github.com/ovandermoten/go-oauth2/internal/repository"
	"github.com/ovandermoten/go-oauth2/internal/shared/auth"
	"github.com/ovandermoten/go-oauth2/pkg/logger"
	"gorm.io/gorm"
)

type AppService interface {
	List(ctx context.Context) ([]model.App, error)
	GetByID(ctx context.Context, id uint) (*model.App, error)
	GetByClientID(ctx context.Context, clientID string) (*model.App, error)
	GetByOwnerID(ctx context.Context, ownerID uint) ([]model.App, error)
	Create(ctx context.Context, req dto.CreateAppRequest, ownerID uint) (*model.App, string, error)
	Update(ctx context.Context, id uint, req dto.UpdateAppRequest) (*model.App, error)
	Delete(ctx context.Context, id uint) error
	RotateSecret(ctx context.Context, id uint) (*model.App, string, error)
	ValidateClientCredentials(ctx context.Context, clientID, clientSecret string) (*model.App, error)
	GetAllAppURLs(ctx context.Context) ([]string, error)
}

type appService struct {
	repo repository.AppRepository
}

func NewAppService(repo repository.AppRepository) AppService {
	logger.WithFields(logger.Fields{
		"service": "app",
	}).Info("✅ App service initialized")

	return &appService{repo: repo}
}

func (s *appService) List(ctx context.Context) ([]model.App, error) {
	return s.repo.FindAll(ctx)
}

func (s *appService) GetByID(ctx context.Context, id uint) (*model.App, error) {
	app, err := s.repo.FindByID(ctx, id)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrAppNotFound
		}
		return nil, err
	}
	return app, nil
}

func (s *appService) GetByClientID(ctx context.Context, clientID string) (*model.App, error) {
	app, err := s.repo.FindByClientID(ctx, clientID)
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return nil, ErrAppNotFound
		}
		return nil, err
	}
	return app, nil
}

func (s *appService) GetByOwnerID(ctx context.Context, ownerID uint) ([]model.App, error) {
	return s.repo.FindByOwnerID(ctx, ownerID)
}

func (s *appService) Create(ctx context.Context, req dto.CreateAppRequest, ownerID uint) (*model.App, string, error) {
	// Generate client ID
	clientID, err := generateSecureToken(16)
	if err != nil {
		return nil, "", err
	}

	// Check if client ID already exists
	existing, _ := s.repo.FindByClientID(ctx, clientID)
	if existing != nil {
		// Regenerate client ID
		clientID, err = generateSecureToken(16)
		if err != nil {
			return nil, "", err
		}
	}

	// Generate client secret
	clientSecret, err := generateSecureToken(32)
	if err != nil {
		return nil, "", err
	}

	// Hash the client secret (bcrypt — see H-03 fix)
	clientSecretHash, err := auth.HashClientSecret(clientSecret)
	if err != nil {
		return nil, "", fmt.Errorf("failed to hash client secret: %w", err)
	}

	app := &model.App{
		Name:             req.Name,
		ClientID:         clientID,
		ClientSecretHash: clientSecretHash,
		Active:           true,
		URL:              req.URL,
		RedirectURIs:     model.StringArray(req.RedirectURIs),
		OwnerID:          &ownerID,
		CreatedAt:        time.Now(),
		UpdatedAt:        time.Now(),
	}

	if err := s.repo.Create(ctx, app); err != nil {
		return nil, "", err
	}

	return app, clientSecret, nil
}

func (s *appService) Update(ctx context.Context, id uint, req dto.UpdateAppRequest) (*model.App, error) {
	app, err := s.GetByID(ctx, id)
	if err != nil {
		return nil, err
	}

	if req.Name != nil {
		app.Name = *req.Name
	}
	if req.URL != nil {
		app.URL = req.URL
	}
	if req.RedirectURIs != nil {
		app.RedirectURIs = model.StringArray(req.RedirectURIs)
	}
	if req.Active != nil {
		app.Active = *req.Active
	}

	app.UpdatedAt = time.Now()

	if err := s.repo.Update(ctx, app); err != nil {
		return nil, err
	}

	return app, nil
}

func (s *appService) Delete(ctx context.Context, id uint) error {
	_, err := s.GetByID(ctx, id)
	if err != nil {
		return err
	}
	return s.repo.Delete(ctx, id)
}

func (s *appService) RotateSecret(ctx context.Context, id uint) (*model.App, string, error) {
	app, err := s.GetByID(ctx, id)
	if err != nil {
		return nil, "", err
	}

	// Generate new client secret
	clientSecret, err := generateSecureToken(32)
	if err != nil {
		return nil, "", err
	}

	// Hash the new client secret (bcrypt — see H-03 fix)
	newHash, err := auth.HashClientSecret(clientSecret)
	if err != nil {
		return nil, "", fmt.Errorf("failed to hash client secret: %w", err)
	}
	app.ClientSecretHash = newHash
	app.UpdatedAt = time.Now()

	if err := s.repo.Update(ctx, app); err != nil {
		return nil, "", err
	}

	return app, clientSecret, nil
}

func (s *appService) ValidateClientCredentials(ctx context.Context, clientID, clientSecret string) (*model.App, error) {
	app, err := s.GetByClientID(ctx, clientID)
	if err != nil {
		return nil, err
	}

	if !app.Active {
		return nil, ErrAppNotFound
	}

	if !auth.CheckClientSecret(clientSecret, app.ClientSecretHash) {
		return nil, ErrInvalidCredentials
	}

	return app, nil
}

func (s *appService) GetAllAppURLs(ctx context.Context) ([]string, error) {
	return s.repo.GetAllRedirectURIs(ctx)
}

func generateSecureToken(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(bytes), nil
}
