package handler

import (
	"net/http"
	"time"

	"github.com/ovandermoten/go-oauth2/config"
	"github.com/ovandermoten/go-oauth2/internal/dto"
	"gorm.io/gorm"
)

// SettingsHandler serves the server-configuration and health-probe endpoints.
//
// Routes (all under /api/admin, protected by AuthMiddleware):
//
//	GET /api/admin/settings/config      – read-only view of runtime config
//	GET /api/admin/settings/test-db     – ping the database, return latency
//	GET /api/admin/settings/test-cache  – stub (no cache layer); always "ok"
type SettingsHandler struct {
	cfg *config.Config
	db  *gorm.DB
}

// NewSettingsHandler creates the handler.
func NewSettingsHandler(cfg *config.Config, db *gorm.DB) *SettingsHandler {
	return &SettingsHandler{cfg: cfg, db: db}
}

// ==========================================
// GET /api/admin/settings/config
// ==========================================

// GetConfig returns a read-only view of the runtime server configuration.
// Sensitive fields (database URL, SMTP credentials, secret keys) are never
// included in the response.
func (h *SettingsHandler) GetConfig(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, dto.ServerConfigResponse{
		IssuerURL:         h.cfg.OAuthIssuer,
		AccessTokenTTL:    int(h.cfg.AccessTokenTTL.Seconds()),
		RefreshTokenTTL:   int(h.cfg.RefreshTokenTTL.Seconds()),
		RateLimitRequests: h.cfg.RateLimitLogin,
		RateLimitWindow:   int(h.cfg.RateLimitLoginWindow.Seconds()),
		Environment:       h.cfg.Environment,
		Version:           "1.0.0",
		Features: dto.ServerConfigFeatures{
			// MFA self-service (TOTP) enrollment endpoints are available
			// (RFC-011 / EPIC-9). Login step-up enforcement is a later slice.
			MFAEnabled: true,
			// Password policy is enforced via auth.ValidatePassword.
			PasswordPolicyEnabled: true,
			// Audit logging is always active (admin_logs + security_audit_logs).
			AuditLoggingEnabled: true,
		},
	})
}

// ==========================================
// GET /api/admin/settings/test-db
// ==========================================

// TestDB pings the database and returns the round-trip latency in milliseconds.
func (h *SettingsHandler) TestDB(w http.ResponseWriter, r *http.Request) {
	start := time.Now()

	sqlDB, err := h.db.DB()
	if err != nil {
		writeJSON(w, dto.ConnectionTestResponse{
			Status: "error",
			Error:  "could not obtain sql.DB handle: " + err.Error(),
		})
		return
	}

	if err := sqlDB.PingContext(r.Context()); err != nil {
		writeJSON(w, dto.ConnectionTestResponse{
			Status:    "error",
			LatencyMs: time.Since(start).Milliseconds(),
			Error:     err.Error(),
		})
		return
	}

	writeJSON(w, dto.ConnectionTestResponse{
		Status:    "ok",
		LatencyMs: time.Since(start).Milliseconds(),
	})
}

// ==========================================
// GET /api/admin/settings/test-cache
// ==========================================

// TestCache is a stub — this server does not use an external cache layer
// (Redis, Memcached, etc.).  It returns "ok" with 0 latency so the admin
// UI does not show a misleading error.  Wire a real probe here if a cache
// is added in the future.
func (h *SettingsHandler) TestCache(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, dto.ConnectionTestResponse{
		Status:    "ok",
		LatencyMs: 0,
	})
}
