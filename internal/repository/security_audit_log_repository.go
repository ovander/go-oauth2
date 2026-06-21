package repository

import (
	"context"
	"errors"
	"time"

	"github.com/ovandermoten/go-oauth2/internal/model"
	"gorm.io/gorm"
)

// SecurityAuditLogRepository defines operations for security audit logs
type SecurityAuditLogRepository interface {
	Create(ctx context.Context, log *model.SecurityAuditLog) error
	FindByUser(ctx context.Context, userID uint, page, pageSize int) ([]model.SecurityAuditLog, int64, error)
	FindByApp(ctx context.Context, appID uint, page, pageSize int) ([]model.SecurityAuditLog, int64, error)
	FindByEventType(ctx context.Context, eventType model.SecurityEventType, page, pageSize int) ([]model.SecurityAuditLog, int64, error)
	FindBySeverity(ctx context.Context, severity model.SecuritySeverity, page, pageSize int) ([]model.SecurityAuditLog, int64, error)
	FindByDateRange(ctx context.Context, start, end time.Time, page, pageSize int) ([]model.SecurityAuditLog, int64, error)
	FindByIPAddress(ctx context.Context, ipAddress string, page, pageSize int) ([]model.SecurityAuditLog, int64, error)
	FindFailedLoginsByUser(ctx context.Context, userID uint, since time.Time) ([]model.SecurityAuditLog, error)
	FindFailedLoginsByIP(ctx context.Context, ipAddress string, since time.Time) ([]model.SecurityAuditLog, error)
	CountBySeveritySince(ctx context.Context, severity model.SecuritySeverity, since time.Time) (int64, error)
	DeleteOlderThan(ctx context.Context, before time.Time) (int64, error)
}

type gormSecurityAuditLogRepository struct {
	db *gorm.DB
	// secret keys the per-row integrity HMAC (RFC-007). Nil/empty disables
	// integrity stamping, preserving prior behaviour.
	secret []byte
}

// NewSecurityAuditLogRepository creates a new GORM-based security audit log
// repository with integrity stamping disabled.
func NewSecurityAuditLogRepository(db *gorm.DB) SecurityAuditLogRepository {
	return NewSecurityAuditLogRepositoryWithIntegrity(db, nil)
}

// NewSecurityAuditLogRepositoryWithIntegrity creates a repository that stamps a
// tamper-evidence HMAC (keyed by secret) on every audit row at write time
// (RFC-007). A nil/empty secret disables stamping.
func NewSecurityAuditLogRepositoryWithIntegrity(db *gorm.DB, secret []byte) SecurityAuditLogRepository {
	return &gormSecurityAuditLogRepository{db: db, secret: secret}
}

// auditChainLockKey is a fixed advisory-lock key used to serialize audit-row
// appends so the RFC-007 hash chain cannot fork under concurrent writes.
const auditChainLockKey = int64(0x4155444954434841) // "AUDITCHA"

func (r *gormSecurityAuditLogRepository) Create(ctx context.Context, log *model.SecurityAuditLog) error {
	if log.CreatedAt.IsZero() {
		log.CreatedAt = time.Now()
	}
	// RFC-007: reduce to microseconds (PostgreSQL precision) so the stored
	// timestamp equals what the integrity hash is computed over and what a
	// later read returns — keeping VerifyAuditRowHash stable across a round trip.
	log.CreatedAt = log.CreatedAt.UTC().Truncate(time.Microsecond)

	// No integrity secret: preserve prior (unchained, unstamped) behaviour.
	if len(r.secret) == 0 {
		return r.db.WithContext(ctx).Create(log).Error
	}

	// RFC-007: chain the row to the current tip and stamp the HMAC inside a
	// transaction. A transaction-scoped advisory lock serializes concurrent
	// audit appends so the chain links to a single, stable predecessor and does
	// not fork. The lock is released automatically at commit/rollback.
	return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec("SELECT pg_advisory_xact_lock(?)", auditChainLockKey).Error; err != nil {
			return err
		}
		var tip model.SecurityAuditLog
		err := tx.Where("row_hash <> ''").Order("id DESC").Limit(1).Take(&tip).Error
		switch {
		case err == nil:
			log.PrevHash = tip.RowHash
		case errors.Is(err, gorm.ErrRecordNotFound):
			log.PrevHash = "" // genesis row
		default:
			return err
		}
		log.RowHash = computeAuditRowHash(r.secret, log)
		return tx.Create(log).Error
	})
}

func (r *gormSecurityAuditLogRepository) FindByUser(ctx context.Context, userID uint, page, pageSize int) ([]model.SecurityAuditLog, int64, error) {
	var logs []model.SecurityAuditLog
	var total int64

	query := r.db.WithContext(ctx).Model(&model.SecurityAuditLog{}).Where("user_id = ?", userID)

	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	offset := (page - 1) * pageSize
	if err := query.Preload("App").Order("created_at DESC").Offset(offset).Limit(pageSize).Find(&logs).Error; err != nil {
		return nil, 0, err
	}

	return logs, total, nil
}

func (r *gormSecurityAuditLogRepository) FindByApp(ctx context.Context, appID uint, page, pageSize int) ([]model.SecurityAuditLog, int64, error) {
	var logs []model.SecurityAuditLog
	var total int64

	query := r.db.WithContext(ctx).Model(&model.SecurityAuditLog{}).Where("app_id = ?", appID)

	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	offset := (page - 1) * pageSize
	if err := query.Preload("User").Order("created_at DESC").Offset(offset).Limit(pageSize).Find(&logs).Error; err != nil {
		return nil, 0, err
	}

	return logs, total, nil
}

func (r *gormSecurityAuditLogRepository) FindByEventType(ctx context.Context, eventType model.SecurityEventType, page, pageSize int) ([]model.SecurityAuditLog, int64, error) {
	var logs []model.SecurityAuditLog
	var total int64

	query := r.db.WithContext(ctx).Model(&model.SecurityAuditLog{}).Where("event_type = ?", eventType)

	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	offset := (page - 1) * pageSize
	if err := query.Preload("User").Preload("App").Order("created_at DESC").Offset(offset).Limit(pageSize).Find(&logs).Error; err != nil {
		return nil, 0, err
	}

	return logs, total, nil
}

func (r *gormSecurityAuditLogRepository) FindBySeverity(ctx context.Context, severity model.SecuritySeverity, page, pageSize int) ([]model.SecurityAuditLog, int64, error) {
	var logs []model.SecurityAuditLog
	var total int64

	query := r.db.WithContext(ctx).Model(&model.SecurityAuditLog{}).Where("severity = ?", severity)

	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	offset := (page - 1) * pageSize
	if err := query.Preload("User").Preload("App").Order("created_at DESC").Offset(offset).Limit(pageSize).Find(&logs).Error; err != nil {
		return nil, 0, err
	}

	return logs, total, nil
}

func (r *gormSecurityAuditLogRepository) FindByDateRange(ctx context.Context, start, end time.Time, page, pageSize int) ([]model.SecurityAuditLog, int64, error) {
	var logs []model.SecurityAuditLog
	var total int64

	query := r.db.WithContext(ctx).Model(&model.SecurityAuditLog{}).Where("created_at BETWEEN ? AND ?", start, end)

	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	offset := (page - 1) * pageSize
	if err := query.Preload("User").Preload("App").Order("created_at DESC").Offset(offset).Limit(pageSize).Find(&logs).Error; err != nil {
		return nil, 0, err
	}

	return logs, total, nil
}

func (r *gormSecurityAuditLogRepository) FindByIPAddress(ctx context.Context, ipAddress string, page, pageSize int) ([]model.SecurityAuditLog, int64, error) {
	var logs []model.SecurityAuditLog
	var total int64

	query := r.db.WithContext(ctx).Model(&model.SecurityAuditLog{}).Where("ip_address = ?", ipAddress)

	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	offset := (page - 1) * pageSize
	if err := query.Preload("User").Preload("App").Order("created_at DESC").Offset(offset).Limit(pageSize).Find(&logs).Error; err != nil {
		return nil, 0, err
	}

	return logs, total, nil
}

func (r *gormSecurityAuditLogRepository) FindFailedLoginsByUser(ctx context.Context, userID uint, since time.Time) ([]model.SecurityAuditLog, error) {
	var logs []model.SecurityAuditLog
	err := r.db.WithContext(ctx).
		Where("user_id = ? AND event_type = ? AND created_at >= ?", userID, model.SecurityEventLoginFailed, since).
		Order("created_at DESC").
		Find(&logs).Error
	return logs, err
}

func (r *gormSecurityAuditLogRepository) FindFailedLoginsByIP(ctx context.Context, ipAddress string, since time.Time) ([]model.SecurityAuditLog, error) {
	var logs []model.SecurityAuditLog
	err := r.db.WithContext(ctx).
		Where("ip_address = ? AND event_type = ? AND created_at >= ?", ipAddress, model.SecurityEventLoginFailed, since).
		Order("created_at DESC").
		Find(&logs).Error
	return logs, err
}

func (r *gormSecurityAuditLogRepository) CountBySeveritySince(ctx context.Context, severity model.SecuritySeverity, since time.Time) (int64, error) {
	var count int64
	err := r.db.WithContext(ctx).
		Model(&model.SecurityAuditLog{}).
		Where("severity = ? AND created_at >= ?", severity, since).
		Count(&count).Error
	return count, err
}

func (r *gormSecurityAuditLogRepository) DeleteOlderThan(ctx context.Context, before time.Time) (int64, error) {
	result := r.db.WithContext(ctx).
		Where("created_at < ?", before).
		Delete(&model.SecurityAuditLog{})
	return result.RowsAffected, result.Error
}
