package repository

import (
	"context"
	"fmt"
	"time"

	"github.com/ovander/go-oauth2/internal/model"
	"gorm.io/gorm"
)

// Alert-rule group_by values: the security_audit_logs column the events of a
// rule are counted by. An empty group_by counts them all together.
const (
	AlertGroupByIPAddress = "ip_address"
	AlertGroupByUserID    = "user_id"
	AlertGroupByAppID     = "app_id"
)

// alertGroupExpr maps a group_by value to the SQL expression of its group key,
// and the condition an event needs to belong to a group. It is the only way a
// group_by reaches the query: anything else is refused.
var alertGroupExpr = map[string]struct{ key, cond string }{
	"":                    {"''", "TRUE"},
	AlertGroupByIPAddress: {"ip_address", "ip_address <> ''"},
	AlertGroupByUserID:    {"CAST(user_id AS TEXT)", "user_id IS NOT NULL"},
	AlertGroupByAppID:     {"CAST(app_id AS TEXT)", "app_id IS NOT NULL"},
}

// ValidAlertGroupBy reports whether groupBy is a group_by the alert-rule
// evaluation supports.
func ValidAlertGroupBy(groupBy string) bool {
	_, ok := alertGroupExpr[groupBy]
	return ok
}

// AlertEvaluationRepository is what the alert-rule evaluation reads and writes
// (#258).
type AlertEvaluationRepository interface {
	// CountEventsByGroup counts the security events of eventType recorded at
	// or after since, per group of groupBy ("" counts them all as one group,
	// whose key is ""). An event without a value for groupBy (no user, no
	// app, no IP) belongs to no group.
	CountEventsByGroup(ctx context.Context, eventType string, since time.Time, groupBy string) (map[string]int64, error)
	// AlertsForRuleSince returns the alerts rule ruleID triggered at or after
	// since.
	AlertsForRuleSince(ctx context.Context, ruleID uint, since time.Time) ([]model.TriggeredAlert, error)
}

type alertEvaluationRepository struct {
	db *gorm.DB
}

// NewAlertEvaluationRepository returns the GORM AlertEvaluationRepository.
func NewAlertEvaluationRepository(db *gorm.DB) AlertEvaluationRepository {
	return &alertEvaluationRepository{db: db}
}

func (r *alertEvaluationRepository) CountEventsByGroup(ctx context.Context, eventType string, since time.Time, groupBy string) (map[string]int64, error) {
	expr, ok := alertGroupExpr[groupBy]
	if !ok {
		return nil, fmt.Errorf("unsupported alert group_by %q", groupBy)
	}
	var rows []struct {
		GroupKey string
		Count    int64
	}
	err := r.db.WithContext(ctx).Model(&model.SecurityAuditLog{}).
		Select(expr.key+" AS group_key, COUNT(*) AS count").
		Where("event_type = ? AND created_at >= ?", eventType, since).
		Where(expr.cond).
		Group("group_key").
		Scan(&rows).Error
	if err != nil {
		return nil, err
	}
	counts := make(map[string]int64, len(rows))
	for _, row := range rows {
		counts[row.GroupKey] = row.Count
	}
	return counts, nil
}

func (r *alertEvaluationRepository) AlertsForRuleSince(ctx context.Context, ruleID uint, since time.Time) ([]model.TriggeredAlert, error) {
	var alerts []model.TriggeredAlert
	err := r.db.WithContext(ctx).
		Where("rule_id = ? AND inserted_at >= ?", ruleID, since).
		Find(&alerts).Error
	return alerts, err
}
