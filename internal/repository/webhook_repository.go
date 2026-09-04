package repository

import (
	"context"
	"time"

	"github.com/ovandermoten/go-oauth2/internal/model"
	"gorm.io/gorm"
)

// WebhookRepository stores webhook subscriptions and the delivery outbox.
type WebhookRepository interface {
	// Subscriptions
	CreateSubscription(ctx context.Context, sub *model.WebhookSubscription) error
	UpdateSubscription(ctx context.Context, sub *model.WebhookSubscription) error
	DeleteSubscription(ctx context.Context, id uint) error
	FindSubscriptionByID(ctx context.Context, id uint) (*model.WebhookSubscription, error)
	// ListSubscriptions returns every subscription, newest first. appID filters
	// to one client's subscriptions when non-nil.
	ListSubscriptions(ctx context.Context, appID *uint) ([]model.WebhookSubscription, error)
	// ListActiveSubscriptions returns the active subscriptions, for the
	// dispatcher's routing cache.
	ListActiveSubscriptions(ctx context.Context) ([]model.WebhookSubscription, error)

	// Deliveries
	ListDeliveries(ctx context.Context, subscriptionID *uint, status string, page, pageSize int) ([]model.WebhookDelivery, int64, error)
	FindDeliveryByID(ctx context.Context, id uint) (*model.WebhookDelivery, error)
	// RequeueDelivery resets a delivery to pending and due now, so an operator
	// can replay a dead one after fixing the target.
	RequeueDelivery(ctx context.Context, id uint) error
	// CountByStatus reports the outbox depth per status, for the admin API and
	// the dispatcher's gauges.
	CountByStatus(ctx context.Context) (map[string]int64, error)
	// DeleteDeliveredOlderThan prunes successfully delivered rows. Dead rows are
	// never pruned automatically — they are the operator's evidence.
	DeleteDeliveredOlderThan(ctx context.Context, before time.Time) (int64, error)
}

type gormWebhookRepository struct {
	db *gorm.DB
}

// NewWebhookRepository creates a GORM-backed webhook repository.
func NewWebhookRepository(db *gorm.DB) WebhookRepository {
	return &gormWebhookRepository{db: db}
}

func (r *gormWebhookRepository) CreateSubscription(ctx context.Context, sub *model.WebhookSubscription) error {
	now := time.Now()
	if sub.CreatedAt.IsZero() {
		sub.CreatedAt = now
	}
	sub.UpdatedAt = now
	return r.db.WithContext(ctx).Create(sub).Error
}

func (r *gormWebhookRepository) UpdateSubscription(ctx context.Context, sub *model.WebhookSubscription) error {
	sub.UpdatedAt = time.Now()
	return r.db.WithContext(ctx).Save(sub).Error
}

func (r *gormWebhookRepository) DeleteSubscription(ctx context.Context, id uint) error {
	// The subscription's deliveries go with it: a delivery to a target that no
	// longer exists can never be sent, and keeping it would leave the outbox
	// with unclaimable rows.
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Where("subscription_id = ?", id).Delete(&model.WebhookDelivery{}).Error; err != nil {
			return err
		}
		return tx.Delete(&model.WebhookSubscription{}, id).Error
	})
}

func (r *gormWebhookRepository) FindSubscriptionByID(ctx context.Context, id uint) (*model.WebhookSubscription, error) {
	var sub model.WebhookSubscription
	if err := r.db.WithContext(ctx).First(&sub, id).Error; err != nil {
		return nil, err
	}
	return &sub, nil
}

func (r *gormWebhookRepository) ListSubscriptions(ctx context.Context, appID *uint) ([]model.WebhookSubscription, error) {
	var subs []model.WebhookSubscription
	q := r.db.WithContext(ctx).Order("id DESC")
	if appID != nil {
		q = q.Where("app_id = ?", *appID)
	}
	if err := q.Find(&subs).Error; err != nil {
		return nil, err
	}
	return subs, nil
}

func (r *gormWebhookRepository) ListActiveSubscriptions(ctx context.Context) ([]model.WebhookSubscription, error) {
	var subs []model.WebhookSubscription
	if err := r.db.WithContext(ctx).Where("active = ?", true).Order("id").Find(&subs).Error; err != nil {
		return nil, err
	}
	return subs, nil
}

func (r *gormWebhookRepository) ListDeliveries(ctx context.Context, subscriptionID *uint, status string, page, pageSize int) ([]model.WebhookDelivery, int64, error) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	q := r.db.WithContext(ctx).Model(&model.WebhookDelivery{})
	if subscriptionID != nil {
		q = q.Where("subscription_id = ?", *subscriptionID)
	}
	if status != "" {
		q = q.Where("status = ?", status)
	}

	var total int64
	if err := q.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	var deliveries []model.WebhookDelivery
	if err := q.Order("id DESC").Offset((page - 1) * pageSize).Limit(pageSize).Find(&deliveries).Error; err != nil {
		return nil, 0, err
	}
	return deliveries, total, nil
}

func (r *gormWebhookRepository) FindDeliveryByID(ctx context.Context, id uint) (*model.WebhookDelivery, error) {
	var d model.WebhookDelivery
	if err := r.db.WithContext(ctx).First(&d, id).Error; err != nil {
		return nil, err
	}
	return &d, nil
}

func (r *gormWebhookRepository) RequeueDelivery(ctx context.Context, id uint) error {
	return r.db.WithContext(ctx).Model(&model.WebhookDelivery{}).
		Where("id = ?", id).
		Updates(map[string]any{
			"status":          model.WebhookDeliveryPending,
			"attempts":        0,
			"next_attempt_at": time.Now(),
			"last_error":      "",
			"updated_at":      time.Now(),
		}).Error
}

func (r *gormWebhookRepository) CountByStatus(ctx context.Context) (map[string]int64, error) {
	type row struct {
		Status string
		N      int64
	}
	var rows []row
	if err := r.db.WithContext(ctx).
		Model(&model.WebhookDelivery{}).
		Select("status, count(*) as n").
		Group("status").
		Scan(&rows).Error; err != nil {
		return nil, err
	}
	out := make(map[string]int64, len(rows))
	for _, r := range rows {
		out[r.Status] = r.N
	}
	return out, nil
}

func (r *gormWebhookRepository) DeleteDeliveredOlderThan(ctx context.Context, before time.Time) (int64, error) {
	res := r.db.WithContext(ctx).
		Where("status = ? AND updated_at < ?", model.WebhookDeliveryDelivered, before).
		Delete(&model.WebhookDelivery{})
	return res.RowsAffected, res.Error
}
