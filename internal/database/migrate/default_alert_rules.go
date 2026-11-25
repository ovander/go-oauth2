package migrate

import (
	"github.com/ovander/go-oauth2/internal/model"
	"gorm.io/gorm"
)

// defaultAlertRules are the alert rules migration 0037 seeds (#258). Each
// watches an event the server records, is enabled, and notifies by email; it
// has no recipient, so nobody is emailed until an operator adds one. Nothing
// is evaluated until ALERT_RULES_MODE is observe or enforce.
//
// Frozen with the migration: change the seeded rules with a new migration.
func defaultAlertRules() []model.AlertRule {
	rule := func(name, description string, event model.SecurityEventType, threshold, window int, groupBy string, severity model.AlertSeverity) model.AlertRule {
		cond := map[string]interface{}{"threshold": threshold, "window_minutes": window}
		if groupBy != "" {
			cond["group_by"] = groupBy
		}
		return model.AlertRule{
			Name: name, Description: description, EventType: string(event), Condition: cond,
			Severity: severity, Enabled: true, Actions: []string{string(model.AlertActionEmail)},
		}
	}
	return []model.AlertRule{
		rule("Brute force from one IP",
			"Many failed sign-ins from one address: password guessing or credential stuffing.",
			model.SecurityEventLoginFailed, 10, 5, "ip_address", model.AlertSeverityError),
		rule("Account under attack",
			"Repeated failed sign-ins on one account, possibly from many addresses.",
			model.SecurityEventLoginFailed, 5, 10, "user_id", model.AlertSeverityWarning),
		rule("Account locked",
			"An account was locked after too many failed sign-ins.",
			model.SecurityEventAccountLocked, 1, 5, "user_id", model.AlertSeverityWarning),
		rule("Refresh token reused",
			"A refresh token was used again after rotation: it has probably been stolen.",
			model.SecurityEventRefreshTokenReuse, 1, 5, "", model.AlertSeverityCritical),
		rule("Revoked token still in use",
			"Revoked tokens keep being presented from one address.",
			model.SecurityEventRevokedTokenUsed, 3, 10, "ip_address", model.AlertSeverityError),
		rule("Client secret guessing",
			"Many failed client authentications from one address.",
			model.SecurityEventClientAuthFailed, 10, 5, "ip_address", model.AlertSeverityWarning),
		rule("Audit log tampering",
			"The audit-log integrity scan found a row that does not verify.",
			model.SecurityEventAuditIntegrityViolation, 1, 60, "", model.AlertSeverityCritical),
	}
}

// seedDefaultAlertRules is migration 0037: it adds defaultAlertRules when
// alert_rules is empty, so a fresh install gets them and a server whose
// operators already wrote rules is left as it is. On a fresh install the
// migrations run before the models are migrated, so it creates the table.
func seedDefaultAlertRules(db *gorm.DB) error {
	if !db.Migrator().HasTable(&model.AlertRule{}) {
		if err := db.AutoMigrate(&model.User{}, &model.AlertRule{}); err != nil {
			return err
		}
	}
	var n int64
	if err := db.Model(&model.AlertRule{}).Count(&n).Error; err != nil {
		return err
	}
	if n > 0 {
		return nil
	}
	rules := defaultAlertRules()
	return db.Create(&rules).Error
}
