package repository

import (
	"context"
	"time"

	"github.com/ovander/go-oauth2/internal/model"
	"gorm.io/gorm"
	"gorm.io/gorm/clause"
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
	// ClaimDue atomically takes up to limit deliveries that are pending and due,
	// marking them so no other instance can claim the same rows. Claiming uses
	// FOR UPDATE SKIP LOCKED, so running several instances is safe from day one:
	// each gets a disjoint batch instead of contending or double-sending.
	ClaimDue(ctx context.Context, limit int, leaseUntil time.Time) ([]model.WebhookDelivery, error)
	// MarkDelivered records a successful attempt (terminal).
	MarkDelivered(ctx context.Context, id uint, statusCode int) error
	// MarkFailed records a failed attempt: either scheduled for another try at
	// nextAttempt, or dead when the attempts are exhausted.
	MarkFailed(ctx context.Context, id uint, statusCode int, reason string, nextAttempt time.Time, dead bool) error
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

// MaxLastErrorLen bounds the stored failure reason so a chatty target cannot
// grow the row without limit. The column is varchar(500).
const MaxLastErrorLen = 500

func (r *gormWebhookRepository) ClaimDue(ctx context.Context, limit int, leaseUntil time.Time) ([]model.WebhookDelivery, error) {
	if limit <= 0 {
		limit = 20
	}

	var claimed []model.WebhookDelivery
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		// SELECT ... FOR UPDATE SKIP LOCKED is what makes this multi-instance
		// safe: rows another instance is already working on are skipped rather
		// than waited on, so two dispatchers never send the same delivery.
		var due []model.WebhookDelivery
		if err := tx.
			Clauses(clause.Locking{Strength: "UPDATE", Options: "SKIP LOCKED"}).
			Where("status = ? AND next_attempt_at <= ?", model.WebhookDeliveryPending, time.Now()).
			Order("next_attempt_at").
			Limit(limit).
			Find(&due).Error; err != nil {
			return err
		}
		if len(due) == 0 {
			return nil
		}

		ids := make([]uint, len(due))
		for i := range due {
			ids[i] = due[i].ID
		}
		// Push the next attempt out by the lease while we work. If this process
		// dies mid-flight the row simply becomes due again after the lease —
		// no delivery is lost, and at worst it is retried (webhook delivery is
		// at-least-once, which is why the payload carries a stable event_id for
		// the subscriber to deduplicate on).
		if err := tx.Model(&model.WebhookDelivery{}).
			Where("id IN ?", ids).
			Updates(map[string]any{
				"next_attempt_at": leaseUntil,
				"updated_at":      time.Now(),
			}).Error; err != nil {
			return err
		}

		claimed = due
		return nil
	})
	if err != nil {
		return nil, err
	}
	return claimed, nil
}

func (r *gormWebhookRepository) MarkDelivered(ctx context.Context, id uint, statusCode int) error {
	now := time.Now()
	return r.db.WithContext(ctx).Model(&model.WebhookDelivery{}).
		Where("id = ?", id).
		Updates(map[string]any{
			"status":           model.WebhookDeliveryDelivered,
			"last_status_code": statusCode,
			"last_error":       "",
			"delivered_at":     now,
			"attempts":         gorm.Expr("attempts + 1"),
			"updated_at":       now,
		}).Error
}

func (r *gormWebhookRepository) MarkFailed(ctx context.Context, id uint, statusCode int, reason string, nextAttempt time.Time, dead bool) error {
	if len(reason) > MaxLastErrorLen {
		reason = reason[:MaxLastErrorLen]
	}
	status := model.WebhookDeliveryPending
	if dead {
		status = model.WebhookDeliveryDead
	}
	now := time.Now()
	return r.db.WithContext(ctx).Model(&model.WebhookDelivery{}).
		Where("id = ?", id).
		Updates(map[string]any{
			"status":           status,
			"last_status_code": statusCode,
			"last_error":       reason,
			"next_attempt_at":  nextAttempt,
			"attempts":         gorm.Expr("attempts + 1"),
			"updated_at":       now,
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
