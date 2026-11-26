package repository

import (
	"context"

	"github.com/ovander/go-oauth2/internal/model"
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
	// Wrap everything in a single transaction so cleanup and the final DELETE
	// are atomic.  Several child tables reference apps.id with FK constraints
	// that PostgreSQL enforces — we must satisfy them before deleting the row.
	//
	// Tables and their strategy:
	//   user_app_roles        NOT NULL FK, no CASCADE  → hard delete rows
	//   authorization_codes   NOT NULL, no FK          → hard delete (safety)
	//   admin_logs            no FK (migration 0038)   → untouched: its rows keep
	//                         naming the app the admin action concerned
	//   security_audit_logs   no FK (migration 0036)   → untouched: its rows are
	//                         hash-stamped over app_id, and keep naming the app (#260)
	//   app_activity_logs     NOT NULL FK, CASCADE     → auto-cascades, no action needed
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// 1. Hard-delete rows that cannot outlive the app
		if err := tx.Where("app_id = ?", id).Delete(&model.UserAppRole{}).Error; err != nil {
			return err
		}
		if err := tx.Where("app_id = ?", id).Delete(&model.AuthorizationCode{}).Error; err != nil {
			return err
		}
		// 2. Delete the app itself (app_activity_logs cascades automatically)
		return tx.Delete(&model.App{}, id).Error
	})
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
