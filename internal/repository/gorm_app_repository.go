package repository

import (
	"context"

	"github.com/ovandermoten/go-oauth2/internal/model"
	"gorm.io/gorm"
)

type AppRepository interface {
	FindAll(ctx context.Context) ([]model.App, error)
	FindByID(ctx context.Context, id uint) (*model.App, error)
	FindByClientID(ctx context.Context, clientID string) (*model.App, error)
	FindByOwnerID(ctx context.Context, ownerID uint) ([]model.App, error)
	Create(ctx context.Context, app *model.App) error
	Update(ctx context.Context, app *model.App) error
	Delete(ctx context.Context, id uint) error
	GetAllRedirectURIs(ctx context.Context) ([]string, error)
}

type appRepository struct {
	db *gorm.DB
}

func NewAppRepository(db *gorm.DB) AppRepository {
	return &appRepository{db: db}
}

func (r *appRepository) FindAll(ctx context.Context) ([]model.App, error) {
	var apps []model.App
	if err := r.db.WithContext(ctx).Where("active = ?", true).Find(&apps).Error; err != nil {
		return nil, err
	}
	return apps, nil
}

func (r *appRepository) FindByID(ctx context.Context, id uint) (*model.App, error) {
	var app model.App
	if err := r.db.WithContext(ctx).First(&app, id).Error; err != nil {
		return nil, err
	}
	return &app, nil
}

func (r *appRepository) FindByClientID(ctx context.Context, clientID string) (*model.App, error) {
	var app model.App
	if err := r.db.WithContext(ctx).Where("client_id = ?", clientID).First(&app).Error; err != nil {
		return nil, err
	}
	return &app, nil
}

func (r *appRepository) FindByOwnerID(ctx context.Context, ownerID uint) ([]model.App, error) {
	var apps []model.App
	if err := r.db.WithContext(ctx).Where("owner_id = ?", ownerID).Find(&apps).Error; err != nil {
		return nil, err
	}
	return apps, nil
}

func (r *appRepository) Create(ctx context.Context, app *model.App) error {
	return r.db.WithContext(ctx).Create(app).Error
}

func (r *appRepository) Update(ctx context.Context, app *model.App) error {
	return r.db.WithContext(ctx).Save(app).Error
}

func (r *appRepository) Delete(ctx context.Context, id uint) error {
	return r.db.WithContext(ctx).Delete(&model.App{}, id).Error
}

func (r *appRepository) GetAllRedirectURIs(ctx context.Context) ([]string, error) {
	var apps []model.App
	if err := r.db.WithContext(ctx).Select("url").Where("active = ? AND url IS NOT NULL", true).Find(&apps).Error; err != nil {
		return nil, err
	}

	urls := make([]string, 0, len(apps))
	for _, app := range apps {
		if app.URL != nil {
			urls = append(urls, *app.URL)
		}
	}
	return urls, nil
}
