package repository

import (
	"context"
	"sync"
	"sync/atomic"
	"time"

	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/pkg/logger"
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

// AuditOutboxWriter is called with the audit row and the *open transaction*
// that is inserting it, so anything it writes commits or rolls back with that
// row (A3). It is how the webhook outbox gets its transactional guarantee: a
// delivery can never exist without the audit entry that produced it.
//
// The writer is called after the audit row has been inserted, inside a
// savepoint. A writer that returns an error rolls back only its own writes —
// the audit row still commits, because losing a security audit entry over a
// failed webhook enqueue would be the worse trade.
type AuditOutboxWriter interface {
	WriteOutbox(ctx context.Context, tx *gorm.DB, log *model.SecurityAuditLog) error
}

// AuditOutboxSetter is implemented by audit repositories that can carry an
// outbox writer. Bootstrap type-asserts for it, so the decorators that wrap the
// repository (metrics) need no knowledge of the outbox.
type AuditOutboxSetter interface {
	SetOutboxWriter(w AuditOutboxWriter)
}

type gormSecurityAuditLogRepository struct {
	db *gorm.DB
	// secret keys the per-row integrity HMAC (RFC-007). Nil/empty disables
	// integrity stamping, preserving prior behaviour.
	secret []byte
	// outbox, when set, enqueues webhook deliveries in the same transaction as
	// the audit row (A3). Nil (the default) keeps the prior behaviour exactly.
	outbox AuditOutboxWriter

	// The chain head (#364): whether its table exists (looked up once), and
	// whether this repository has seen or written it, after which its absence
	// can only mean it was deleted.
	headMu      sync.Mutex
	headChecked bool
	headTable   bool
	headSeen    atomic.Bool
}

// SetOutboxWriter installs the transactional outbox writer. Called once at
// bootstrap, before the repository serves traffic.
func (r *gormSecurityAuditLogRepository) SetOutboxWriter(w AuditOutboxWriter) {
	r.outbox = w
}

// outboxSavepoint names the savepoint that isolates outbox writes from the
// audit-row insert.
const outboxSavepoint = "socrate_webhook_outbox"

// writeOutbox enqueues the deliveries for one audit row inside a savepoint, so
// a failure there cannot poison the transaction carrying the audit row.
func (r *gormSecurityAuditLogRepository) writeOutbox(ctx context.Context, tx *gorm.DB, log *model.SecurityAuditLog) {
	if r.outbox == nil {
		return
	}
	if err := tx.SavePoint(outboxSavepoint).Error; err != nil {
		logger.WithFields(logger.Fields{"error": err.Error()}).
			Warn("A3: could not open the webhook outbox savepoint; audit row written without enqueueing deliveries")
		return
	}
	if err := r.outbox.WriteOutbox(ctx, tx, log); err != nil {
		if rbErr := tx.RollbackTo(outboxSavepoint).Error; rbErr != nil {
			logger.WithFields(logger.Fields{"error": rbErr.Error()}).
				Error("A3: could not roll back the webhook outbox savepoint")
		}
		logger.WithFields(logger.Fields{
			"error":      err.Error(),
			"event_type": string(log.EventType),
		}).Error("A3: webhook enqueue failed; the audit row is kept and the event is not delivered")
	}
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
	return r.createRows(ctx, []*model.SecurityAuditLog{log})
}

// normalizeAuditCreatedAt stamps a missing CreatedAt and reduces it to
// microseconds (PostgreSQL precision), so the stored timestamp equals what the
// integrity hash is computed over and what a later read returns — keeping
// VerifyAuditRowHash stable across a round trip (RFC-007).
func normalizeAuditCreatedAt(log *model.SecurityAuditLog) {
	if log.CreatedAt.IsZero() {
		log.CreatedAt = time.Now()
	}
	log.CreatedAt = log.CreatedAt.UTC().Truncate(time.Microsecond)
}

// createRows appends logs, in order, in one transaction. Create writes one row;
// the asynchronous appender writes a batch, so a burst of events costs one
// chain lock and one commit instead of one each.
func (r *gormSecurityAuditLogRepository) createRows(ctx context.Context, logs []*model.SecurityAuditLog) error {
	if len(logs) == 0 {
		return nil
	}
	for _, log := range logs {
		normalizeAuditCreatedAt(log)
	}

	// No integrity secret and no outbox: preserve prior (unchained, unstamped,
	// single-statement) behaviour exactly.
	if len(r.secret) == 0 && r.outbox == nil {
		if len(logs) == 1 {
			return r.db.WithContext(ctx).Create(logs[0]).Error
		}
		return r.db.WithContext(ctx).Create(logs).Error
	}

	// Outbox without integrity stamping: one transaction, each audit row
	// before its own outbox entries.
	if len(r.secret) == 0 {
		return r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
			for _, log := range logs {
				if err := tx.Create(log).Error; err != nil {
					return err
				}
				r.writeOutbox(ctx, tx, log)
			}
			return nil
		})
	}

	// RFC-007: chain each row to its predecessor and stamp the HMAC inside a
	// transaction. A transaction-scoped advisory lock serializes concurrent
	// audit appends so the chain links to a single, stable predecessor and does
	// not fork. The lock is released automatically at commit/rollback. Rows
	// are inserted in order, so ascending ids follow the chain. The
	// predecessor is the chain head (#364), which the transaction moves to the
	// last row it appends.
	useHead := r.hasHeadTable(ctx)
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec("SELECT pg_advisory_xact_lock(?)", auditChainLockKey).Error; err != nil {
			return err
		}
		prev, problem, err := r.chainPredecessor(tx, useHead)
		if err != nil {
			return err
		}
		if problem != "" {
			// The head was deleted or rewritten: say so in the chain itself,
			// before the rows of this append.
			logger.WithFields(logger.Fields{"chain_head": problem}).
				Error("RFC-007: audit chain head missing or invalid; re-anchored at the newest stamped row")
			violation := &model.SecurityAuditLog{
				EventType: model.SecurityEventAuditIntegrityViolation,
				Severity:  model.SecuritySeverityCritical,
				Details:   map[string]interface{}{"chain_head": problem},
			}
			normalizeAuditCreatedAt(violation)
			logs = append([]*model.SecurityAuditLog{violation}, logs...)
		}
		for _, log := range logs {
			log.PrevHash = prev
			log.RowHash = computeAuditRowHash(r.secret, log)
			if err := tx.Create(log).Error; err != nil {
				return err
			}
			// A3: enqueue the webhook deliveries for this row in the same
			// transaction, after the row exists so the delivery can reference it.
			r.writeOutbox(ctx, tx, log)
			prev = log.RowHash
		}
		if useHead {
			last := logs[len(logs)-1]
			return r.writeHead(tx, last.ID, last.RowHash)
		}
		return nil
	})
	if err == nil && useHead {
		r.headSeen.Store(true)
	}
	return err
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

// DeleteOlderThan removes the rows created before the cutoff. With integrity
// stamping on, it keeps the newest row even when it is older: the chain head
// names it, and its absence would read as the newest rows having been removed
// (#364).
func (r *gormSecurityAuditLogRepository) DeleteOlderThan(ctx context.Context, before time.Time) (int64, error) {
	q := r.db.WithContext(ctx).Where("created_at < ?", before)
	if len(r.secret) > 0 {
		q = q.Where("id < (SELECT MAX(id) FROM security_audit_logs)")
	}
	result := q.Delete(&model.SecurityAuditLog{})
	return result.RowsAffected, result.Error
}
