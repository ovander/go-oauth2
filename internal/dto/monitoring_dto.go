package dto

import (
	"time"

	"github.com/ovandermoten/go-oauth2/internal/model"
)

// ==========================================
// Security Events
// ==========================================

// SecurityEventResponse represents a security event in API responses
type SecurityEventResponse struct {
	ID        uint                   `json:"id"`
	UserID    *uint                  `json:"user_id,omitempty"`
	UserEmail string                 `json:"user_email,omitempty"`
	AppID     *uint                  `json:"app_id,omitempty"`
	AppName   string                 `json:"app_name,omitempty"`
	EventType string                 `json:"event_type"`
	Severity  string                 `json:"severity"`
	IPAddress string                 `json:"ip_address,omitempty"`
	UserAgent string                 `json:"user_agent,omitempty"`
	Details   map[string]interface{} `json:"details,omitempty"`
	Success   bool                   `json:"success"`
	CreatedAt time.Time              `json:"created_at"`
}

// SecurityEventsListResponse contains a paginated list of security events
type SecurityEventsListResponse struct {
	Events   []SecurityEventResponse `json:"events"`
	Total    int64                   `json:"total"`
	Page     int                     `json:"page"`
	PageSize int                     `json:"page_size"`
}

// ==========================================
// Threat Intelligence
// ==========================================

// ThreatSummary contains aggregate threat statistics
type ThreatSummary struct {
	TotalEvents     int64 `json:"total_events"`
	CriticalEvents  int64 `json:"critical_events"`
	ErrorEvents     int64 `json:"error_events"`
	WarningEvents   int64 `json:"warning_events"`
	UniqueAttackers int64 `json:"unique_attackers"`
}

// ThreatTypeStats represents statistics for a specific threat type
type ThreatTypeStats struct {
	Type          string `json:"type"`
	Count         int64  `json:"count"`
	UniqueIPs     int64  `json:"unique_ips"`
	AffectedUsers int64  `json:"affected_users"`
	AffectedApps  int64  `json:"affected_apps"`
}

// SuspiciousIPInfo contains information about a suspicious IP
type SuspiciousIPInfo struct {
	IPAddress  string    `json:"ip_address"`
	EventCount int64     `json:"event_count"`
	EventTypes []string  `json:"event_types"`
	FirstSeen  time.Time `json:"first_seen"`
	LastSeen   time.Time `json:"last_seen"`
}

// LockedAccountInfo contains information about a locked account
type LockedAccountInfo struct {
	UserID         uint       `json:"user_id"`
	Email          string     `json:"email"`
	LockedAt       time.Time  `json:"locked_at"`
	LockedUntil    *time.Time `json:"locked_until,omitempty"`
	FailedAttempts int        `json:"failed_attempts"`
}

// ThreatMetricsResponse contains aggregated threat intelligence
type ThreatMetricsResponse struct {
	TimeRange      string              `json:"time_range"`
	Summary        ThreatSummary       `json:"summary"`
	TopThreats     []ThreatTypeStats   `json:"top_threats"`
	SuspiciousIPs  []SuspiciousIPInfo  `json:"suspicious_ips"`
	LockedAccounts []LockedAccountInfo `json:"locked_accounts"`
}

// ==========================================
// Sessions
// ==========================================

// SessionResponse represents an active session
type SessionResponse struct {
	ID           string    `json:"id"`
	UserID       uint      `json:"user_id"`
	UserEmail    string    `json:"user_email"`
	AppID        uint      `json:"app_id"`
	AppName      string    `json:"app_name"`
	IPAddress    string    `json:"ip_address"`
	UserAgent    string    `json:"user_agent"`
	CreatedAt    time.Time `json:"created_at"`
	LastActivity time.Time `json:"last_activity"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// SessionsListResponse contains a paginated list of sessions
type SessionsListResponse struct {
	Sessions []SessionResponse `json:"sessions"`
	Total    int64             `json:"total"`
	Page     int               `json:"page"`
	PageSize int               `json:"page_size"`
}

// ==========================================
// Token Analytics
// ==========================================

// TokenCounts contains token counts by type
type TokenCounts struct {
	AccessTokens  int64 `json:"access_tokens"`
	RefreshTokens int64 `json:"refresh_tokens"`
	IDTokens      int64 `json:"id_tokens"`
}

// TokenAppStats contains token statistics for an app
type TokenAppStats struct {
	AppID     uint   `json:"app_id"`
	AppName   string `json:"app_name"`
	Issued    int64  `json:"issued"`
	Refreshed int64  `json:"refreshed"`
	Revoked   int64  `json:"revoked"`
}

// TokenHourlyStats contains token statistics for an hour
type TokenHourlyStats struct {
	Hour      time.Time `json:"hour"`
	Issued    int64     `json:"issued"`
	Refreshed int64     `json:"refreshed"`
	Revoked   int64     `json:"revoked"`
}

// TokenStatsResponse contains token statistics
type TokenStatsResponse struct {
	Period               string             `json:"period"`
	Issued               TokenCounts        `json:"issued"`
	Refreshed            int64              `json:"refreshed"`
	Revoked              int64              `json:"revoked"`
	ExpiredUsageAttempts int64              `json:"expired_usage_attempts"`
	InvalidUsageAttempts int64              `json:"invalid_usage_attempts"`
	ByApp                []TokenAppStats    `json:"by_app"`
	ByHour               []TokenHourlyStats `json:"by_hour"`
}

// ActiveTokensResponse contains active token counts
type ActiveTokensResponse struct {
	TotalActiveTokens int64            `json:"total_active_tokens"`
	ByType            map[string]int64 `json:"by_type"`
	ByApp             []TokenAppStats  `json:"by_app"`
}

// ==========================================
// Alert Rules
// ==========================================

// AlertRuleRequest represents a request to create/update an alert rule
type AlertRuleRequest struct {
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	EventType   string                 `json:"event_type"`
	Condition   map[string]interface{} `json:"condition"`
	Severity    string                 `json:"severity"`
	Enabled     *bool                  `json:"enabled,omitempty"`
	Actions     []string               `json:"actions"`
	Recipients  []string               `json:"recipients,omitempty"`
	WebhookURL  string                 `json:"webhook_url,omitempty"`
}

// AlertRuleResponse represents an alert rule in API responses
type AlertRuleResponse struct {
	ID          uint                   `json:"id"`
	Name        string                 `json:"name"`
	Description string                 `json:"description,omitempty"`
	EventType   string                 `json:"event_type"`
	Condition   map[string]interface{} `json:"condition"`
	Severity    string                 `json:"severity"`
	Enabled     bool                   `json:"enabled"`
	Actions     []string               `json:"actions"`
	Recipients  []string               `json:"recipients,omitempty"`
	WebhookURL  string                 `json:"webhook_url,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
	UpdatedAt   time.Time              `json:"updated_at"`
}

// AlertRulesListResponse contains a list of alert rules
type AlertRulesListResponse struct {
	Rules []AlertRuleResponse `json:"rules"`
	Total int64               `json:"total"`
}

// ==========================================
// Triggered Alerts
// ==========================================

// TriggeredAlertResponse represents a triggered alert in API responses
type TriggeredAlertResponse struct {
	ID              uint                   `json:"id"`
	RuleID          uint                   `json:"rule_id"`
	RuleName        string                 `json:"rule_name"`
	Severity        string                 `json:"severity"`
	Message         string                 `json:"message"`
	Details         map[string]interface{} `json:"details,omitempty"`
	Acknowledged    bool                   `json:"acknowledged"`
	AcknowledgedBy  *uint                  `json:"acknowledged_by,omitempty"`
	AcknowledgedAt  *time.Time             `json:"acknowledged_at,omitempty"`
	AcknowledgeNote string                 `json:"acknowledge_note,omitempty"`
	TriggeredAt     time.Time              `json:"triggered_at"`
}

// AlertsHistoryResponse contains alert history
type AlertsHistoryResponse struct {
	Alerts         []TriggeredAlertResponse `json:"alerts"`
	Total          int64                    `json:"total"`
	Unacknowledged int64                    `json:"unacknowledged"`
	Page           int                      `json:"page"`
	PageSize       int                      `json:"page_size"`
}

// AcknowledgeAlertRequest represents a request to acknowledge an alert
type AcknowledgeAlertRequest struct {
	Note string `json:"note,omitempty"`
}

// ==========================================
// Blocked IPs
// ==========================================

// BlockIPRequest represents a request to block an IP
type BlockIPRequest struct {
	IPAddress     string `json:"ip_address"`
	Reason        string `json:"reason,omitempty"`
	DurationHours int    `json:"duration_hours,omitempty"`
	Permanent     bool   `json:"permanent,omitempty"`
}

// BlockedIPResponse represents a blocked IP in API responses
type BlockedIPResponse struct {
	ID             uint       `json:"id"`
	IPAddress      string     `json:"ip_address"`
	Reason         string     `json:"reason,omitempty"`
	BlockedBy      *uint      `json:"blocked_by,omitempty"`
	BlockedByEmail string     `json:"blocked_by_email,omitempty"`
	BlockedAt      time.Time  `json:"blocked_at"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
	Permanent      bool       `json:"permanent"`
}

// BlockedIPsListResponse contains a list of blocked IPs
type BlockedIPsListResponse struct {
	BlockedIPs []BlockedIPResponse `json:"blocked_ips"`
	Total      int64               `json:"total"`
}

// IPReputationResponse contains IP reputation information
type IPReputationResponse struct {
	IPAddress           string                  `json:"ip_address"`
	IsBlocked           bool                    `json:"is_blocked"`
	RiskScore           int                     `json:"risk_score"`
	Events24h           int64                   `json:"events_24h"`
	Events7d            int64                   `json:"events_7d"`
	FailedLogins24h     int64                   `json:"failed_logins_24h"`
	UniqueUsersTargeted int64                   `json:"unique_users_targeted"`
	FirstSeen           *time.Time              `json:"first_seen,omitempty"`
	LastSeen            *time.Time              `json:"last_seen,omitempty"`
	RecentEvents        []SecurityEventResponse `json:"recent_events"`
}

// ==========================================
// Geographic Analytics
// ==========================================

// GeoCountryStats contains login statistics by country
type GeoCountryStats struct {
	CountryCode string `json:"country_code"`
	CountryName string `json:"country_name"`
	LoginCount  int64  `json:"login_count"`
	UniqueUsers int64  `json:"unique_users"`
	FailedCount int64  `json:"failed_count"`
}

// GeoCityStats contains login statistics by city
type GeoCityStats struct {
	City        string  `json:"city"`
	CountryCode string  `json:"country_code"`
	Latitude    float64 `json:"latitude"`
	Longitude   float64 `json:"longitude"`
	LoginCount  int64   `json:"login_count"`
	FailedCount int64   `json:"failed_count"`
}

// GeoAnomaly represents a geographic anomaly
type GeoAnomaly struct {
	UserID       uint      `json:"user_id"`
	UserEmail    string    `json:"user_email"`
	Description  string    `json:"description"`
	UsualCountry string    `json:"usual_country"`
	LoginCountry string    `json:"login_country"`
	CreatedAt    time.Time `json:"created_at"`
}

// GeoAnalyticsResponse contains geographic analytics
type GeoAnalyticsResponse struct {
	Period        string            `json:"period"`
	GeoConfigured bool              `json:"geo_configured"`
	ByCountry     []GeoCountryStats `json:"by_country"`
	ByCity        []GeoCityStats    `json:"by_city"`
	Anomalies     []GeoAnomaly      `json:"anomalies"`
}

// ==========================================
// Real-time Events
// ==========================================

// WebSocketMessage represents a message sent via WebSocket
type WebSocketMessage struct {
	Type string      `json:"type"`
	Data interface{} `json:"data"`
}

// EventSubscription represents a subscription request for events
type EventSubscription struct {
	Filters EventFilters `json:"filters,omitempty"`
}

// EventFilters contains filters for event subscriptions
type EventFilters struct {
	Severity   []string `json:"severity,omitempty"`
	EventTypes []string `json:"event_types,omitempty"`
	AppIDs     []uint   `json:"app_ids,omitempty"`
}

// ==========================================
// Helper Functions
// ==========================================

// FromSecurityAuditLog converts a model to a DTO
func FromSecurityAuditLog(log *model.SecurityAuditLog) SecurityEventResponse {
	resp := SecurityEventResponse{
		ID:        log.ID,
		UserID:    log.UserID,
		AppID:     log.AppID,
		EventType: string(log.EventType),
		Severity:  string(log.Severity),
		IPAddress: log.IPAddress,
		UserAgent: log.UserAgent,
		Details:   log.Details,
		Success:   log.Success,
		CreatedAt: log.CreatedAt,
	}
	if log.User != nil {
		resp.UserEmail = log.User.Email
	}
	if log.App != nil {
		resp.AppName = log.App.Name
	}
	return resp
}

// FromAlertRule converts a model to a DTO
func FromAlertRule(rule *model.AlertRule) AlertRuleResponse {
	return AlertRuleResponse{
		ID:          rule.ID,
		Name:        rule.Name,
		Description: rule.Description,
		EventType:   rule.EventType,
		Condition:   rule.Condition,
		Severity:    string(rule.Severity),
		Enabled:     rule.Enabled,
		Actions:     rule.Actions,
		Recipients:  rule.Recipients,
		WebhookURL:  rule.WebhookURL,
		CreatedAt:   rule.CreatedAt,
		UpdatedAt:   rule.UpdatedAt,
	}
}

// FromTriggeredAlert converts a model to a DTO
func FromTriggeredAlert(alert *model.TriggeredAlert) TriggeredAlertResponse {
	resp := TriggeredAlertResponse{
		ID:              alert.ID,
		RuleID:          alert.RuleID,
		Severity:        string(alert.Severity),
		Message:         alert.Message,
		Details:         alert.Details,
		Acknowledged:    alert.Acknowledged,
		AcknowledgedBy:  alert.AcknowledgedBy,
		AcknowledgedAt:  alert.AcknowledgedAt,
		AcknowledgeNote: alert.AcknowledgeNote,
		TriggeredAt:     alert.TriggeredAt,
	}
	if alert.Rule != nil {
		resp.RuleName = alert.Rule.Name
	}
	return resp
}

// FromBlockedIP converts a model to a DTO
func FromBlockedIP(ip *model.BlockedIP) BlockedIPResponse {
	resp := BlockedIPResponse{
		ID:        ip.ID,
		IPAddress: ip.IPAddress,
		Reason:    ip.Reason,
		BlockedBy: ip.BlockedBy,
		BlockedAt: ip.BlockedAt,
		ExpiresAt: ip.ExpiresAt,
		Permanent: ip.Permanent,
	}
	if ip.Blocker != nil {
		resp.BlockedByEmail = ip.Blocker.Email
	}
	return resp
}

// ==========================================
// Report Generation
// ==========================================

// ReportRequest represents a request to generate a report
type ReportRequest struct {
	Type     string       `json:"type"`
	Period   ReportPeriod `json:"period"`
	Format   string       `json:"format"`
	Sections []string     `json:"sections,omitempty"`
}

// ReportPeriod represents a time period for reports
type ReportPeriod struct {
	From time.Time `json:"from"`
	To   time.Time `json:"to"`
}

// ReportResponse represents a generated report status
type ReportResponse struct {
	ReportID            string     `json:"report_id"`
	Status              string     `json:"status"`
	Type                string     `json:"type"`
	Format              string     `json:"format"`
	DownloadURL         string     `json:"download_url,omitempty"`
	EstimatedCompletion *time.Time `json:"estimated_completion,omitempty"`
	CreatedAt           time.Time  `json:"created_at"`
	CompletedAt         *time.Time `json:"completed_at,omitempty"`
	ExpiresAt           *time.Time `json:"expires_at,omitempty"`
}

// SecurityReportData represents the data in a security report
type SecurityReportData struct {
	GeneratedAt time.Time      `json:"generated_at"`
	Period      ReportPeriod   `json:"period"`
	Overview    ReportOverview `json:"overview"`
	Threats     ReportThreats  `json:"threats"`
	Users       ReportUsers    `json:"users"`
	Apps        ReportApps     `json:"apps"`
}

// ReportOverview contains high-level statistics
type ReportOverview struct {
	TotalEvents      int64 `json:"total_events"`
	CriticalEvents   int64 `json:"critical_events"`
	SuccessfulLogins int64 `json:"successful_logins"`
	FailedLogins     int64 `json:"failed_logins"`
	UniqueUsers      int64 `json:"unique_users"`
	BlockedIPs       int64 `json:"blocked_ips"`
	AlertsTriggered  int64 `json:"alerts_triggered"`
}

// ReportThreats contains threat-related statistics
type ReportThreats struct {
	TopAttackTypes     []ThreatTypeStats  `json:"top_attack_types"`
	SuspiciousIPs      []SuspiciousIPInfo `json:"suspicious_ips"`
	BruteForceAttempts int64              `json:"brute_force_attempts"`
}

// ReportUsers contains user-related statistics
type ReportUsers struct {
	TotalUsers     int64               `json:"total_users"`
	ActiveUsers    int64               `json:"active_users"`
	NewUsers       int64               `json:"new_users"`
	LockedAccounts []LockedAccountInfo `json:"locked_accounts"`
}

// ReportApps contains app-related statistics
type ReportApps struct {
	TotalApps  int64           `json:"total_apps"`
	ActiveApps int64           `json:"active_apps"`
	TopApps    []TokenAppStats `json:"top_apps"`
}
