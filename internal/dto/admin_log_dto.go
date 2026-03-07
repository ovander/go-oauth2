package dto

import (
	"time"

	"github.com/ovandermoten/go-oauth2/internal/model"
)

// ==========================================
// Admin Audit Logs
// ==========================================

// AdminAuditLogResponse is the per-entry shape expected by the admin frontend.
//
// Mapping from model.AdminLog:
//
//	target_type  – inferred: "user" when TargetUserID != nil,
//	               "application" when AppID != nil, otherwise "settings"
//	target_id    – TargetUserID ?? AppID (whichever is set)
//	target_name  – TargetUser.Email ?? App.Name (from Preloaded relations)
//	changes      – AdminLog.Details (stored as jsonb, arbitrary key/value map)
//	ip_address   – not stored in AdminLog; always empty string for legacy rows
type AdminAuditLogResponse struct {
	ID          uint                   `json:"id"`
	AdminID     uint                   `json:"admin_id"`
	AdminEmail  string                 `json:"admin_email"`
	Action      string                 `json:"action"`
	TargetType  string                 `json:"target_type"`
	TargetID    *uint                  `json:"target_id,omitempty"`
	TargetName  string                 `json:"target_name,omitempty"`
	Changes     map[string]interface{} `json:"changes,omitempty"`
	IPAddress   string                 `json:"ip_address,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
}

// AdminAuditListResponse is the paginated envelope returned by GET /api/admin/logs.
type AdminAuditListResponse struct {
	Logs       []AdminAuditLogResponse `json:"logs"`
	TotalCount int64                   `json:"total_count"`
	Page       int                     `json:"page"`
	PageSize   int                     `json:"page_size"`
}

// FromAdminLog converts a model.AdminLog (with preloaded Admin, App, TargetUser)
// into the DTO shape the frontend expects.
func FromAdminLog(log *model.AdminLog) AdminAuditLogResponse {
	resp := AdminAuditLogResponse{
		ID:        log.ID,
		AdminID:   log.AdminID,
		Action:    string(log.Action),
		Changes:   log.Details,
		CreatedAt: log.CreatedAt,
	}

	// Admin email from preloaded relation.
	if log.Admin != nil {
		resp.AdminEmail = log.Admin.Email
	}

	// Derive target_type, target_id, target_name.
	switch {
	case log.TargetUserID != nil:
		resp.TargetType = "user"
		resp.TargetID = log.TargetUserID
		if log.TargetUser != nil {
			resp.TargetName = log.TargetUser.Email
		}
	case log.AppID != nil:
		resp.TargetType = "application"
		resp.TargetID = log.AppID
		if log.App != nil {
			resp.TargetName = log.App.Name
		}
	default:
		resp.TargetType = "settings"
	}

	return resp
}

// ==========================================
// Server Settings / Config
// ==========================================

// ServerConfigFeatures reflects the feature-flag subset of the config.
type ServerConfigFeatures struct {
	MFAEnabled            bool `json:"mfa_enabled"`
	PasswordPolicyEnabled bool `json:"password_policy_enabled"`
	AuditLoggingEnabled   bool `json:"audit_logging_enabled"`
}

// ServerConfigResponse is the shape returned by GET /api/admin/settings/config.
type ServerConfigResponse struct {
	IssuerURL          string               `json:"issuer_url"`
	AccessTokenTTL     int                  `json:"access_token_ttl"`    // seconds
	RefreshTokenTTL    int                  `json:"refresh_token_ttl"`   // seconds
	RateLimitRequests  int                  `json:"rate_limit_requests"` // login limit
	RateLimitWindow    int                  `json:"rate_limit_window"`   // seconds
	Environment        string               `json:"environment"`
	Version            string               `json:"version"`
	Features           ServerConfigFeatures `json:"features"`
}

// ConnectionTestResponse is returned by the test-db and test-cache endpoints.
type ConnectionTestResponse struct {
	Status    string `json:"status"`    // "ok" or "error"
	LatencyMs int64  `json:"latency_ms"`
	Error     string `json:"error,omitempty"`
}
