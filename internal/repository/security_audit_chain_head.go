package repository

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/pkg/logger"
	"gorm.io/gorm"
)

// Audit chain head (#364).
//
// The chain alone cannot show that its newest rows were deleted, or had their
// hash blanked: what remains still links up, and the next row used to link to
// the newest row still carrying a hash. The head is therefore kept outside the
// audit table, in audit_chain_head: one row holding the id and hash of the
// newest chained row, with an HMAC keyed like the row hashes, so it cannot be
// rewritten without SECRET_KEY_BASE. Every append links to the head and moves
// it in the same transaction, and the integrity scanner checks that the row the
// head names is still there, unchanged.
//
// What it cannot show: someone with write access to the database who saved an
// earlier head can restore it together with deleting the rows written after
// it. The scheduled scan logs the head it saw, outside the database, which is
// where such a rollback becomes visible.

// auditChainHeadTable is created by migration 0033.
const auditChainHeadTable = "audit_chain_head"

// auditChainHead is the single row (id = 1) of audit_chain_head.
type auditChainHead struct {
	ID       int16  `gorm:"column:id;primaryKey"`
	LastID   uint   `gorm:"column:last_id"`
	LastHash string `gorm:"column:last_hash"`
	MAC      string `gorm:"column:mac"`
}

func (auditChainHead) TableName() string { return auditChainHeadTable }

// Problems AuditChainHeadProblem reports.
const (
	// ChainHeadMissing: stamped rows exist but the head row does not.
	ChainHeadMissing = "head_missing"
	// ChainHeadInvalid: the head's HMAC does not match its content.
	ChainHeadInvalid = "head_invalid"
	// ChainHeadRowRemoved: the row the head names no longer exists, which is
	// what deleting the newest rows produces.
	ChainHeadRowRemoved = "head_row_removed"
	// ChainHeadRowChanged: the row the head names no longer carries the hash
	// the head recorded, which is what blanking or rewriting it produces.
	ChainHeadRowChanged = "head_row_changed"
)

// auditChainHeadMAC authenticates a head. The message is domain-separated from
// the row hashes, which are computed over a JSON object.
func auditChainHeadMAC(secret []byte, lastID uint, lastHash string) string {
	mac := hmac.New(sha256.New, secret)
	_, _ = fmt.Fprintf(mac, "socrate-audit-chain-head\x00%d\x00%s", lastID, lastHash)
	return hex.EncodeToString(mac.Sum(nil))
}

func (r *gormSecurityAuditLogRepository) headValid(h *auditChainHead) bool {
	return hmac.Equal([]byte(h.MAC), []byte(auditChainHeadMAC(r.secret, h.LastID, h.LastHash)))
}

// hasHeadTable reports, once per repository, whether migration 0033 has
// created audit_chain_head. Without it the chain is written as before 0033.
func (r *gormSecurityAuditLogRepository) hasHeadTable(ctx context.Context) bool {
	r.headOnce.Do(func() {
		var ok bool
		if err := r.db.WithContext(ctx).Raw("SELECT to_regclass(?) IS NOT NULL", auditChainHeadTable).Scan(&ok).Error; err != nil {
			logger.WithFields(logger.Fields{"error": err.Error()}).
				Error("RFC-007: could not look for the audit_chain_head table; the chain head is not anchored")
			return
		}
		if !ok {
			logger.Warn("RFC-007: the audit_chain_head table does not exist; the chain head is not anchored (run the migrations)")
		}
		r.headTable = ok
	})
	return r.headTable
}

// readHead returns the head row, or nil when there is none.
func readHead(tx *gorm.DB) (*auditChainHead, error) {
	var h auditChainHead
	err := tx.Where("id = 1").Take(&h).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &h, nil
}

// newestStamped returns the newest row carrying a hash, or nil when there is
// none.
func newestStamped(tx *gorm.DB) (*model.SecurityAuditLog, error) {
	var tip model.SecurityAuditLog
	err := tx.Where("row_hash <> ''").Order("id DESC").Limit(1).Take(&tip).Error
	if errors.Is(err, gorm.ErrRecordNotFound) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &tip, nil
}

// chainPredecessor returns the hash the next appended row links to, and a
// head problem to record first ("" when none). Called under the chain lock.
//
// A valid head wins over the table: if the newest rows were deleted or
// blanked, the next row still links to the hash they had, so the gap shows as
// a broken link. The newest stamped row is used instead only when it is newer
// than the head (written by an instance that predates the head, during a
// rolling upgrade), or when there is no usable head.
func (r *gormSecurityAuditLogRepository) chainPredecessor(tx *gorm.DB, useHead bool) (string, string, error) {
	tip, err := newestStamped(tx)
	if err != nil {
		return "", "", err
	}
	problem := ""
	if useHead {
		head, err := readHead(tx)
		if err != nil {
			return "", "", err
		}
		switch {
		case head != nil && r.headValid(head):
			if tip == nil || tip.ID <= head.LastID {
				return head.LastHash, "", nil
			}
		case head != nil:
			problem = ChainHeadInvalid
		case r.headSeen.Load():
			// The head existed, so only its deletion explains its absence.
			problem = ChainHeadMissing
		}
	}
	if tip == nil {
		return "", problem, nil
	}
	return tip.RowHash, problem, nil
}

// writeHead moves the head to the given row. Called under the chain lock, in
// the transaction that appended the row.
func (r *gormSecurityAuditLogRepository) writeHead(tx *gorm.DB, lastID uint, lastHash string) error {
	return tx.Exec(`INSERT INTO `+auditChainHeadTable+` (id, last_id, last_hash, mac, updated_at)
		VALUES (1, ?, ?, ?, ?)
		ON CONFLICT (id) DO UPDATE SET last_id = EXCLUDED.last_id, last_hash = EXCLUDED.last_hash,
			mac = EXCLUDED.mac, updated_at = EXCLUDED.updated_at`,
		lastID, lastHash, auditChainHeadMAC(r.secret, lastID, lastHash), time.Now().UTC()).Error
}

// AuditChainAnchorer anchors the chain head at startup.
type AuditChainAnchorer interface {
	// EnsureAuditChainHead writes the head when there is none (the first
	// start after migration 0033, or an empty log), at the newest stamped row.
	// From then on, a head that disappears is reported as tampering.
	EnsureAuditChainHead(ctx context.Context) error
}

// EnsureAuditChainHead implements AuditChainAnchorer. A no-op without an
// integrity secret or before migration 0033.
func (r *gormSecurityAuditLogRepository) EnsureAuditChainHead(ctx context.Context) error {
	if len(r.secret) == 0 || !r.hasHeadTable(ctx) {
		return nil
	}
	err := r.db.WithContext(ctx).Transaction(func(tx *gorm.DB) error {
		if err := tx.Exec("SELECT pg_advisory_xact_lock(?)", auditChainLockKey).Error; err != nil {
			return err
		}
		head, err := readHead(tx)
		if err != nil || head != nil {
			return err
		}
		tip, err := newestStamped(tx)
		if err != nil {
			return err
		}
		var id uint
		hash := ""
		if tip != nil {
			id, hash = tip.ID, tip.RowHash
		}
		if err := r.writeHead(tx, id, hash); err != nil {
			return err
		}
		logger.WithFields(logger.Fields{"row_id": id}).Info("RFC-007: audit chain head anchored")
		return nil
	})
	if err == nil {
		r.headSeen.Store(true)
	}
	return err
}

// AuditChainWindow is the range of audit rows a scan covers, in id order.
type AuditChainWindow struct {
	// FirstID is the first row created at or after the scan's start; 0 when
	// there is none.
	FirstID uint
	// LastID is the newest row when the window was read.
	LastID uint
	// Before is the row just before FirstID (nil when none): the first row in
	// the window is link-checked against it.
	Before *model.SecurityAuditLog
	// Started says whether a stamped row exists before FirstID, so that an
	// unstamped row in the window breaks the chain.
	Started bool
}

// AuditChainReader reads the audit chain for the integrity scanner (#364): in
// id order, the order the chain is written in, so the link between two pages
// is checked too.
type AuditChainReader interface {
	AuditChainWindow(ctx context.Context, since time.Time) (AuditChainWindow, error)
	// AuditChainRows returns up to limit rows with afterID < id <= upTo, in
	// ascending id order.
	AuditChainRows(ctx context.Context, afterID, upTo uint, limit int) ([]model.SecurityAuditLog, error)
	// AuditChainHeadProblem checks the head against the row it names. It
	// returns the head's row id and hash, and one of the ChainHead* problems
	// ("" when consistent).
	AuditChainHeadProblem(ctx context.Context) (headID uint, headHash string, problem string, err error)
}

// AuditChainWindow implements AuditChainReader.
func (r *gormSecurityAuditLogRepository) AuditChainWindow(ctx context.Context, since time.Time) (AuditChainWindow, error) {
	var w AuditChainWindow
	db := r.db.WithContext(ctx)
	var first, last sql.NullInt64
	if err := db.Model(&model.SecurityAuditLog{}).Where("created_at >= ?", since).Select("MIN(id)").Scan(&first).Error; err != nil {
		return w, err
	}
	if !first.Valid {
		return w, nil
	}
	if err := db.Model(&model.SecurityAuditLog{}).Select("MAX(id)").Scan(&last).Error; err != nil {
		return w, err
	}
	w.FirstID, w.LastID = uint(first.Int64), uint(last.Int64)
	var before model.SecurityAuditLog
	err := db.Where("id < ?", w.FirstID).Order("id DESC").Limit(1).Take(&before).Error
	switch {
	case err == nil:
		w.Before = &before
	case !errors.Is(err, gorm.ErrRecordNotFound):
		return w, err
	}
	if err := db.Raw("SELECT EXISTS (SELECT 1 FROM security_audit_logs WHERE id < ? AND row_hash <> '')", w.FirstID).
		Scan(&w.Started).Error; err != nil {
		return w, err
	}
	return w, nil
}

// AuditChainRows implements AuditChainReader.
func (r *gormSecurityAuditLogRepository) AuditChainRows(ctx context.Context, afterID, upTo uint, limit int) ([]model.SecurityAuditLog, error) {
	var rows []model.SecurityAuditLog
	err := r.db.WithContext(ctx).Where("id > ? AND id <= ?", afterID, upTo).
		Order("id ASC").Limit(limit).Find(&rows).Error
	return rows, err
}

// AuditChainHeadProblem implements AuditChainReader. Rows appended after the
// head are not a problem in themselves (an instance that predates the head
// wrote them); the walk over the rows checks their links and hashes.
func (r *gormSecurityAuditLogRepository) AuditChainHeadProblem(ctx context.Context) (uint, string, string, error) {
	if len(r.secret) == 0 {
		return 0, "", "", nil
	}
	db := r.db.WithContext(ctx)
	if !r.hasHeadTable(ctx) {
		tip, err := newestStamped(db)
		if err != nil || tip == nil {
			return 0, "", "", err
		}
		return 0, "", ChainHeadMissing, nil
	}
	head, err := readHead(db)
	if err != nil {
		return 0, "", "", err
	}
	if head == nil {
		tip, err := newestStamped(db)
		if err != nil || tip == nil {
			return 0, "", "", err
		}
		return 0, "", ChainHeadMissing, nil
	}
	if !r.headValid(head) {
		return head.LastID, head.LastHash, ChainHeadInvalid, nil
	}
	if head.LastID == 0 {
		return 0, "", "", nil // anchored on an empty log
	}
	var row model.SecurityAuditLog
	err = db.Where("id = ?", head.LastID).Take(&row).Error
	switch {
	case errors.Is(err, gorm.ErrRecordNotFound):
		return head.LastID, head.LastHash, ChainHeadRowRemoved, nil
	case err != nil:
		return 0, "", "", err
	case row.RowHash != head.LastHash:
		return head.LastID, head.LastHash, ChainHeadRowChanged, nil
	}
	return head.LastID, head.LastHash, "", nil
}
