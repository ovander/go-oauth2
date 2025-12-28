package repository

import (
	"context"
	"time"

	"github.com/ovandermoten/go-oauth2/internal/model"
	"gorm.io/gorm"
)

// ==========================================
// Alert Rule Repository
// ==========================================

// AlertRuleRepository provides access to alert rule data
type AlertRuleRepository interface {
	Create(ctx context.Context, rule *model.AlertRule) error
	Update(ctx context.Context, rule *model.AlertRule) error
	Delete(ctx context.Context, id uint) error
	FindByID(ctx context.Context, id uint) (*model.AlertRule, error)
	FindAll(ctx context.Context) ([]model.AlertRule, error)
	FindEnabled(ctx context.Context) ([]model.AlertRule, error)
	FindByEventType(ctx context.Context, eventType string) ([]model.AlertRule, error)
}

type alertRuleRepository struct {
	db *gorm.DB
}

func NewAlertRuleRepository(db *gorm.DB) AlertRuleRepository {
	return &alertRuleRepository{db: db}
}

func (r *alertRuleRepository) Create(ctx context.Context, rule *model.AlertRule) error {
	return r.db.WithContext(ctx).Create(rule).Error
}

func (r *alertRuleRepository) Update(ctx context.Context, rule *model.AlertRule) error {
	return r.db.WithContext(ctx).Save(rule).Error
}

func (r *alertRuleRepository) Delete(ctx context.Context, id uint) error {
	return r.db.WithContext(ctx).Delete(&model.AlertRule{}, id).Error
}

func (r *alertRuleRepository) FindByID(ctx context.Context, id uint) (*model.AlertRule, error) {
	var rule model.AlertRule
	err := r.db.WithContext(ctx).First(&rule, id).Error
	if err != nil {
		return nil, err
	}
	return &rule, nil
}

func (r *alertRuleRepository) FindAll(ctx context.Context) ([]model.AlertRule, error) {
	var rules []model.AlertRule
	err := r.db.WithContext(ctx).Order("inserted_at DESC").Find(&rules).Error
	return rules, err
}

func (r *alertRuleRepository) FindEnabled(ctx context.Context) ([]model.AlertRule, error) {
	var rules []model.AlertRule
	err := r.db.WithContext(ctx).Where("enabled = ?", true).Find(&rules).Error
	return rules, err
}

func (r *alertRuleRepository) FindByEventType(ctx context.Context, eventType string) ([]model.AlertRule, error) {
	var rules []model.AlertRule
	err := r.db.WithContext(ctx).Where("event_type = ? AND enabled = ?", eventType, true).Find(&rules).Error
	return rules, err
}

// ==========================================
// Triggered Alert Repository
// ==========================================

// TriggeredAlertRepository provides access to triggered alert data
type TriggeredAlertRepository interface {
	Create(ctx context.Context, alert *model.TriggeredAlert) error
	Update(ctx context.Context, alert *model.TriggeredAlert) error
	FindByID(ctx context.Context, id uint) (*model.TriggeredAlert, error)
	FindAll(ctx context.Context, page, pageSize int) ([]model.TriggeredAlert, int64, error)
	FindByRuleID(ctx context.Context, ruleID uint, page, pageSize int) ([]model.TriggeredAlert, int64, error)
	FindUnacknowledged(ctx context.Context, page, pageSize int) ([]model.TriggeredAlert, int64, error)
	FindBySeverity(ctx context.Context, severity model.AlertSeverity, page, pageSize int) ([]model.TriggeredAlert, int64, error)
	FindByDateRange(ctx context.Context, from, to time.Time, page, pageSize int) ([]model.TriggeredAlert, int64, error)
	CountUnacknowledged(ctx context.Context) (int64, error)
	Acknowledge(ctx context.Context, id uint, acknowledgedBy uint, note string) error
}

type triggeredAlertRepository struct {
	db *gorm.DB
}

func NewTriggeredAlertRepository(db *gorm.DB) TriggeredAlertRepository {
	return &triggeredAlertRepository{db: db}
}

func (r *triggeredAlertRepository) Create(ctx context.Context, alert *model.TriggeredAlert) error {
	return r.db.WithContext(ctx).Create(alert).Error
}

func (r *triggeredAlertRepository) Update(ctx context.Context, alert *model.TriggeredAlert) error {
	return r.db.WithContext(ctx).Save(alert).Error
}

func (r *triggeredAlertRepository) FindByID(ctx context.Context, id uint) (*model.TriggeredAlert, error) {
	var alert model.TriggeredAlert
	err := r.db.WithContext(ctx).Preload("Rule").First(&alert, id).Error
	if err != nil {
		return nil, err
	}
	return &alert, nil
}

func (r *triggeredAlertRepository) FindAll(ctx context.Context, page, pageSize int) ([]model.TriggeredAlert, int64, error) {
	var alerts []model.TriggeredAlert
	var total int64

	offset := (page - 1) * pageSize

	r.db.WithContext(ctx).Model(&model.TriggeredAlert{}).Count(&total)
	err := r.db.WithContext(ctx).
		Preload("Rule").
		Order("inserted_at DESC").
		Offset(offset).
		Limit(pageSize).
		Find(&alerts).Error

	return alerts, total, err
}

func (r *triggeredAlertRepository) FindByRuleID(ctx context.Context, ruleID uint, page, pageSize int) ([]model.TriggeredAlert, int64, error) {
	var alerts []model.TriggeredAlert
	var total int64

	offset := (page - 1) * pageSize

	r.db.WithContext(ctx).Model(&model.TriggeredAlert{}).Where("rule_id = ?", ruleID).Count(&total)
	err := r.db.WithContext(ctx).
		Preload("Rule").
		Where("rule_id = ?", ruleID).
		Order("inserted_at DESC").
		Offset(offset).
		Limit(pageSize).
		Find(&alerts).Error

	return alerts, total, err
}

func (r *triggeredAlertRepository) FindUnacknowledged(ctx context.Context, page, pageSize int) ([]model.TriggeredAlert, int64, error) {
	var alerts []model.TriggeredAlert
	var total int64

	offset := (page - 1) * pageSize

	r.db.WithContext(ctx).Model(&model.TriggeredAlert{}).Where("acknowledged = ?", false).Count(&total)
	err := r.db.WithContext(ctx).
		Preload("Rule").
		Where("acknowledged = ?", false).
		Order("inserted_at DESC").
		Offset(offset).
		Limit(pageSize).
		Find(&alerts).Error

	return alerts, total, err
}

func (r *triggeredAlertRepository) FindBySeverity(ctx context.Context, severity model.AlertSeverity, page, pageSize int) ([]model.TriggeredAlert, int64, error) {
	var alerts []model.TriggeredAlert
	var total int64

	offset := (page - 1) * pageSize

	r.db.WithContext(ctx).Model(&model.TriggeredAlert{}).Where("severity = ?", severity).Count(&total)
	err := r.db.WithContext(ctx).
		Preload("Rule").
		Where("severity = ?", severity).
		Order("inserted_at DESC").
		Offset(offset).
		Limit(pageSize).
		Find(&alerts).Error

	return alerts, total, err
}

func (r *triggeredAlertRepository) FindByDateRange(ctx context.Context, from, to time.Time, page, pageSize int) ([]model.TriggeredAlert, int64, error) {
	var alerts []model.TriggeredAlert
	var total int64

	offset := (page - 1) * pageSize

	r.db.WithContext(ctx).Model(&model.TriggeredAlert{}).
		Where("inserted_at >= ? AND inserted_at <= ?", from, to).
		Count(&total)
	err := r.db.WithContext(ctx).
		Preload("Rule").
		Where("inserted_at >= ? AND inserted_at <= ?", from, to).
		Order("inserted_at DESC").
		Offset(offset).
		Limit(pageSize).
		Find(&alerts).Error

	return alerts, total, err
}

func (r *triggeredAlertRepository) CountUnacknowledged(ctx context.Context) (int64, error) {
	var count int64
	err := r.db.WithContext(ctx).Model(&model.TriggeredAlert{}).Where("acknowledged = ?", false).Count(&count).Error
	return count, err
}

func (r *triggeredAlertRepository) Acknowledge(ctx context.Context, id uint, acknowledgedBy uint, note string) error {
	now := time.Now()
	return r.db.WithContext(ctx).Model(&model.TriggeredAlert{}).
		Where("id = ?", id).
		Updates(map[string]interface{}{
			"acknowledged":     true,
			"acknowledged_by":  acknowledgedBy,
			"acknowledged_at":  now,
			"acknowledge_note": note,
		}).Error
}

// ==========================================
// Blocked IP Repository
// ==========================================

// BlockedIPRepository provides access to blocked IP data
type BlockedIPRepository interface {
	Create(ctx context.Context, blockedIP *model.BlockedIP) error
	Delete(ctx context.Context, id uint) error
	FindByID(ctx context.Context, id uint) (*model.BlockedIP, error)
	FindByIP(ctx context.Context, ipAddress string) (*model.BlockedIP, error)
	FindAll(ctx context.Context) ([]model.BlockedIP, error)
	FindActive(ctx context.Context) ([]model.BlockedIP, error)
	IsBlocked(ctx context.Context, ipAddress string) (bool, error)
	CleanupExpired(ctx context.Context) (int64, error)
}

type blockedIPRepository struct {
	db *gorm.DB
}

func NewBlockedIPRepository(db *gorm.DB) BlockedIPRepository {
	return &blockedIPRepository{db: db}
}

func (r *blockedIPRepository) Create(ctx context.Context, blockedIP *model.BlockedIP) error {
	return r.db.WithContext(ctx).Create(blockedIP).Error
}

func (r *blockedIPRepository) Delete(ctx context.Context, id uint) error {
	return r.db.WithContext(ctx).Delete(&model.BlockedIP{}, id).Error
}

func (r *blockedIPRepository) FindByID(ctx context.Context, id uint) (*model.BlockedIP, error) {
	var ip model.BlockedIP
	err := r.db.WithContext(ctx).Preload("Blocker").First(&ip, id).Error
	if err != nil {
		return nil, err
	}
	return &ip, nil
}

func (r *blockedIPRepository) FindByIP(ctx context.Context, ipAddress string) (*model.BlockedIP, error) {
	var ip model.BlockedIP
	err := r.db.WithContext(ctx).Preload("Blocker").Where("ip_address = ?", ipAddress).First(&ip).Error
	if err != nil {
		return nil, err
	}
	return &ip, nil
}

func (r *blockedIPRepository) FindAll(ctx context.Context) ([]model.BlockedIP, error) {
	var ips []model.BlockedIP
	err := r.db.WithContext(ctx).Preload("Blocker").Order("blocked_at DESC").Find(&ips).Error
	return ips, err
}

func (r *blockedIPRepository) FindActive(ctx context.Context) ([]model.BlockedIP, error) {
	var ips []model.BlockedIP
	now := time.Now()
	err := r.db.WithContext(ctx).
		Preload("Blocker").
		Where("permanent = ? OR expires_at > ?", true, now).
		Order("blocked_at DESC").
		Find(&ips).Error
	return ips, err
}

func (r *blockedIPRepository) IsBlocked(ctx context.Context, ipAddress string) (bool, error) {
	var count int64
	now := time.Now()
	err := r.db.WithContext(ctx).Model(&model.BlockedIP{}).
		Where("ip_address = ? AND (permanent = ? OR expires_at > ?)", ipAddress, true, now).
		Count(&count).Error
	return count > 0, err
}

func (r *blockedIPRepository) CleanupExpired(ctx context.Context) (int64, error) {
	now := time.Now()
	result := r.db.WithContext(ctx).
		Where("permanent = ? AND expires_at <= ?", false, now).
		Delete(&model.BlockedIP{})
	return result.RowsAffected, result.Error
}
