package migrate

import (
	"encoding/json"
	"time"

	"gorm.io/gorm"
)

// defaultAlertRule is one rule migration 0037 seeds (#258).
type defaultAlertRule struct {
	name, description, eventType string
	threshold, window            int
	groupBy, severity            string
}

// defaultAlertRules are the alert rules migration 0037 seeds. Each watches an
// event the server records, is enabled, and notifies by email; it has no
// recipient, so nobody is emailed until an operator adds one. Nothing is
// evaluated until ALERT_RULES_MODE is observe or enforce.
//
// Frozen with the migration, as literals: change the seeded rules with a new
// migration.
var defaultAlertRules = []defaultAlertRule{
	{"Brute force from one IP", "Many failed sign-ins from one address: password guessing or credential stuffing.",
		"login_failed", 10, 5, "ip_address", "error"},
	{"Account under attack", "Repeated failed sign-ins on one account, possibly from many addresses.",
		"login_failed", 5, 10, "user_id", "warning"},
	{"Account locked", "An account was locked after too many failed sign-ins.",
		"account_locked", 1, 5, "user_id", "warning"},
	{"Refresh token reused", "A refresh token was used again after rotation: it has probably been stolen.",
		"refresh_token_reuse", 1, 5, "", "critical"},
	{"Revoked token still in use", "Revoked tokens keep being presented from one address.",
		"revoked_token_used", 3, 10, "ip_address", "error"},
	{"Client secret guessing", "Many failed client authentications from one address.",
		"client_auth_failed", 10, 5, "ip_address", "warning"},
	{"Audit log tampering", "The audit-log integrity scan found a row that does not verify.",
		"audit_integrity_violation", 1, 60, "", "critical"},
}

// createAlertRulesTable is alert_rules as the AlertRule model defined it when
// migration 0037 was written, without the foreign key from created_by to
// users: on a fresh install the migrations run before the models are migrated,
// so users may not exist yet, and AutoMigrate adds the key afterwards.
const createAlertRulesTable = `CREATE TABLE IF NOT EXISTS alert_rules (
	id bigserial PRIMARY KEY,
	name varchar(100) NOT NULL,
	description text,
	event_type varchar(50) NOT NULL,
	condition jsonb NOT NULL,
	severity varchar(20) NOT NULL,
	enabled boolean DEFAULT true,
	actions jsonb NOT NULL,
	recipients jsonb,
	webhook_url varchar(500),
	created_by bigint,
	inserted_at timestamptz,
	updated_at timestamptz
)`

// seedDefaultAlertRules is migration 0037: it adds defaultAlertRules when
// alert_rules is empty, so a fresh install gets them and a server whose
// operators already wrote rules is left as it is. It touches no other table,
// and writes the frozen schema and values above, whatever the models become.
func seedDefaultAlertRules(db *gorm.DB) error {
	for _, stmt := range []string{
		createAlertRulesTable,
		`CREATE INDEX IF NOT EXISTS idx_alert_rules_event_type ON alert_rules (event_type)`,
		`CREATE INDEX IF NOT EXISTS idx_alert_rules_created_by ON alert_rules (created_by)`,
	} {
		if err := db.Exec(stmt).Error; err != nil {
			return err
		}
	}
	var n int64
	if err := db.Raw(`SELECT count(*) FROM alert_rules`).Scan(&n).Error; err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	now := time.Now()
	for _, r := range defaultAlertRules {
		cond := map[string]interface{}{"threshold": r.threshold, "window_minutes": r.window}
		if r.groupBy != "" {
			cond["group_by"] = r.groupBy
		}
		condJSON, err := json.Marshal(cond)
		if err != nil {
			return err
		}
		if err := db.Exec(`INSERT INTO alert_rules
			(name, description, event_type, condition, severity, enabled, actions, inserted_at, updated_at)
			VALUES (?, ?, ?, ?, ?, true, '["email"]', ?, ?)`,
			r.name, r.description, r.eventType, string(condJSON), r.severity, now, now).Error; err != nil {
			return err
		}
	}
	return nil
}
