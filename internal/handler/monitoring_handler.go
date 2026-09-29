package handler

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/ovander/go-oauth2/internal/dto"
	"github.com/ovander/go-oauth2/internal/middleware"
	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/repository"
	"github.com/ovander/go-oauth2/internal/service"
	"github.com/ovander/go-oauth2/pkg/logger"
	"gorm.io/gorm"
)

// MonitoringHandler handles security monitoring endpoints
type MonitoringHandler struct {
	db                 *gorm.DB
	alertRuleRepo      repository.AlertRuleRepository
	triggeredAlertRepo repository.TriggeredAlertRepository
	blockedIPRepo      repository.BlockedIPRepository
	securityAuditRepo  repository.SecurityAuditLogRepository
	geoIPService       service.GeoIPService

	// auditScanningEnabled mirrors AuditIntegrityScanInterval > 0: whether the
	// background tamper-evidence scanner actually runs. Set via
	// SetAuditScanningEnabled at wiring time; false by default.
	auditScanningEnabled bool
}

// SetAuditScanningEnabled records whether the background audit-integrity
// scanner is running, so GetAuditIntegrity does not report "verified" for a log
// that is merely stamped but never checked (F8).
func (h *MonitoringHandler) SetAuditScanningEnabled(enabled bool) {
	h.auditScanningEnabled = enabled
}

// NewMonitoringHandler creates a new monitoring handler
func NewMonitoringHandler(
	db *gorm.DB,
	alertRuleRepo repository.AlertRuleRepository,
	triggeredAlertRepo repository.TriggeredAlertRepository,
	blockedIPRepo repository.BlockedIPRepository,
	securityAuditRepo repository.SecurityAuditLogRepository,
	geoIPService service.GeoIPService,
) *MonitoringHandler {
	return &MonitoringHandler{
		db:                 db,
		alertRuleRepo:      alertRuleRepo,
		triggeredAlertRepo: triggeredAlertRepo,
		blockedIPRepo:      blockedIPRepo,
		securityAuditRepo:  securityAuditRepo,
		geoIPService:       geoIPService,
	}
}

// ==========================================
// Security Events API
// ==========================================

// GET /api/admin/security/events
func (h *MonitoringHandler) GetSecurityEvents(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse query parameters
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	offset := (page - 1) * pageSize

	// Build query
	query := h.db.WithContext(ctx).Model(&model.SecurityAuditLog{})

	// Apply filters
	if eventTypes := r.URL.Query().Get("event_type"); eventTypes != "" {
		types := strings.Split(eventTypes, ",")
		query = query.Where("event_type IN ?", types)
	}

	if severity := r.URL.Query().Get("severity"); severity != "" {
		severities := strings.Split(severity, ",")
		query = query.Where("severity IN ?", severities)
	}

	if userID := r.URL.Query().Get("user_id"); userID != "" {
		if id, err := strconv.ParseUint(userID, 10, 64); err == nil {
			query = query.Where("user_id = ?", id)
		}
	}

	if appID := r.URL.Query().Get("app_id"); appID != "" {
		if id, err := strconv.ParseUint(appID, 10, 64); err == nil {
			query = query.Where("app_id = ?", id)
		}
	}

	if ipAddress := r.URL.Query().Get("ip_address"); ipAddress != "" {
		query = query.Where("ip_address = ?", ipAddress)
	}

	switch r.URL.Query().Get("success") {
	case "true":
		query = query.Where("success = ?", true)
	case "false":
		query = query.Where("success = ?", false)
	}

	if from := r.URL.Query().Get("from"); from != "" {
		if t, err := time.Parse(time.RFC3339, from); err == nil {
			query = query.Where("created_at >= ?", t)
		}
	}

	if to := r.URL.Query().Get("to"); to != "" {
		if t, err := time.Parse(time.RFC3339, to); err == nil {
			query = query.Where("created_at <= ?", t)
		}
	}

	// Get total count
	var total int64
	query.Count(&total)

	// Get events
	var events []model.SecurityAuditLog
	err := query.
		Preload("User").
		Preload("App").
		Order("created_at DESC").
		Offset(offset).
		Limit(pageSize).
		Find(&events).Error

	if err != nil {
		writeError(w, "failed to query events", http.StatusInternalServerError)
		return
	}

	// Convert to response DTOs
	response := make([]dto.SecurityEventResponse, len(events))
	for i, event := range events {
		response[i] = dto.FromSecurityAuditLog(&event)
	}

	writeJSON(w, dto.SecurityEventsListResponse{
		Events:   response,
		Total:    total,
		Page:     page,
		PageSize: pageSize,
	})
}

// GET /api/admin/security/threats
func (h *MonitoringHandler) GetThreatMetrics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse time range
	timeRange := r.URL.Query().Get("period")
	if timeRange == "" {
		timeRange = "24h"
	}

	var since time.Time
	switch timeRange {
	case "15m":
		since = time.Now().Add(-15 * time.Minute)
	case "1h":
		since = time.Now().Add(-1 * time.Hour)
	case "24h":
		since = time.Now().Add(-24 * time.Hour)
	case "7d":
		since = time.Now().AddDate(0, 0, -7)
	case "30d":
		since = time.Now().AddDate(0, 0, -30)
	default:
		since = time.Now().Add(-24 * time.Hour)
	}

	// Get summary counts
	var summary dto.ThreatSummary
	h.db.WithContext(ctx).Model(&model.SecurityAuditLog{}).
		Where("created_at >= ?", since).
		Count(&summary.TotalEvents)

	h.db.WithContext(ctx).Model(&model.SecurityAuditLog{}).
		Where("created_at >= ? AND severity = ?", since, "critical").
		Count(&summary.CriticalEvents)

	h.db.WithContext(ctx).Model(&model.SecurityAuditLog{}).
		Where("created_at >= ? AND severity = ?", since, "error").
		Count(&summary.ErrorEvents)

	h.db.WithContext(ctx).Model(&model.SecurityAuditLog{}).
		Where("created_at >= ? AND severity = ?", since, "warning").
		Count(&summary.WarningEvents)

	h.db.WithContext(ctx).Model(&model.SecurityAuditLog{}).
		Where("created_at >= ? AND success = ?", since, false).
		Distinct("ip_address").
		Count(&summary.UniqueAttackers)

	// Get top threat types
	type threatCount struct {
		EventType string
		Count     int64
	}
	var threatCounts []threatCount
	h.db.WithContext(ctx).Model(&model.SecurityAuditLog{}).
		Select("event_type, count(*) as count").
		Where("created_at >= ? AND success = ?", since, false).
		Group("event_type").
		Order("count DESC").
		Limit(5).
		Scan(&threatCounts)

	topThreats := make([]dto.ThreatTypeStats, len(threatCounts))
	for i, tc := range threatCounts {
		var uniqueIPs, affectedUsers int64
		h.db.WithContext(ctx).Model(&model.SecurityAuditLog{}).
			Where("created_at >= ? AND event_type = ?", since, tc.EventType).
			Distinct("ip_address").
			Count(&uniqueIPs)
		h.db.WithContext(ctx).Model(&model.SecurityAuditLog{}).
			Where("created_at >= ? AND event_type = ? AND user_id IS NOT NULL", since, tc.EventType).
			Distinct("user_id").
			Count(&affectedUsers)

		topThreats[i] = dto.ThreatTypeStats{
			Type:          tc.EventType,
			Count:         tc.Count,
			UniqueIPs:     uniqueIPs,
			AffectedUsers: affectedUsers,
		}
	}

	// Get suspicious IPs (top IPs with failed events)
	type ipCount struct {
		IPAddress string
		Count     int64
	}
	var ipCounts []ipCount
	h.db.WithContext(ctx).Model(&model.SecurityAuditLog{}).
		Select("ip_address, count(*) as count").
		Where("created_at >= ? AND success = ?", since, false).
		Group("ip_address").
		Having("count(*) > 5").
		Order("count DESC").
		Limit(10).
		Scan(&ipCounts)

	suspiciousIPs := make([]dto.SuspiciousIPInfo, len(ipCounts))
	for i, ic := range ipCounts {
		// Get event types for this IP
		var eventTypes []string
		h.db.WithContext(ctx).Model(&model.SecurityAuditLog{}).
			Select("DISTINCT event_type").
			Where("created_at >= ? AND ip_address = ?", since, ic.IPAddress).
			Pluck("event_type", &eventTypes)

		// Get first and last seen
		var firstSeen, lastSeen time.Time
		h.db.WithContext(ctx).Model(&model.SecurityAuditLog{}).
			Select("MIN(created_at)").
			Where("ip_address = ?", ic.IPAddress).
			Scan(&firstSeen)
		h.db.WithContext(ctx).Model(&model.SecurityAuditLog{}).
			Select("MAX(created_at)").
			Where("ip_address = ?", ic.IPAddress).
			Scan(&lastSeen)

		suspiciousIPs[i] = dto.SuspiciousIPInfo{
			IPAddress:  ic.IPAddress,
			EventCount: ic.Count,
			EventTypes: eventTypes,
			FirstSeen:  firstSeen,
			LastSeen:   lastSeen,
		}
	}

	// Get locked accounts
	type lockedUser struct {
		ID                  uint
		Email               string
		LockedUntil         *time.Time
		FailedLoginAttempts int
	}
	var lockedUsers []lockedUser
	h.db.WithContext(ctx).Table("users").
		Select("id, email, locked_until, failed_login_attempts").
		Where("locked_until > ?", time.Now()).
		Scan(&lockedUsers)

	lockedAccounts := make([]dto.LockedAccountInfo, len(lockedUsers))
	for i, u := range lockedUsers {
		lockedAccounts[i] = dto.LockedAccountInfo{
			UserID:         u.ID,
			Email:          u.Email,
			LockedAt:       time.Now(), // Approximate
			LockedUntil:    u.LockedUntil,
			FailedAttempts: u.FailedLoginAttempts,
		}
	}

	writeJSON(w, dto.ThreatMetricsResponse{
		TimeRange:      timeRange,
		Summary:        summary,
		TopThreats:     topThreats,
		SuspiciousIPs:  suspiciousIPs,
		LockedAccounts: lockedAccounts,
	})
}

// ==========================================
// Audit Integrity API (RFC-007)
// ==========================================

// GET /api/admin/security/audit-integrity
//
// Read-only tamper-evidence health for the security audit log over a period:
// stamping/chaining coverage plus any integrity violations the scheduled
// scanner has recorded. The signing key is intentionally NOT consulted here —
// verification is the scanner's job; this endpoint surfaces its findings.
func (h *MonitoringHandler) GetAuditIntegrity(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	period := r.URL.Query().Get("period")
	if period == "" {
		period = "24h"
	}
	var since time.Time
	switch period {
	case "15m":
		since = time.Now().Add(-15 * time.Minute)
	case "1h":
		since = time.Now().Add(-1 * time.Hour)
	case "24h":
		since = time.Now().Add(-24 * time.Hour)
	case "7d":
		since = time.Now().AddDate(0, 0, -7)
	case "30d":
		since = time.Now().AddDate(0, 0, -30)
	default:
		since = time.Now().Add(-24 * time.Hour)
		period = "24h"
	}

	var total, stamped, chained, violations int64
	h.db.WithContext(ctx).Model(&model.SecurityAuditLog{}).
		Where("created_at >= ?", since).Count(&total)
	h.db.WithContext(ctx).Model(&model.SecurityAuditLog{}).
		Where("created_at >= ? AND row_hash <> ''", since).Count(&stamped)
	h.db.WithContext(ctx).Model(&model.SecurityAuditLog{}).
		Where("created_at >= ? AND prev_hash <> ''", since).Count(&chained)
	h.db.WithContext(ctx).Model(&model.SecurityAuditLog{}).
		Where("created_at >= ? AND event_type = ?", since, model.SecurityEventAuditIntegrityViolation).
		Count(&violations)

	// Recent violation events (within the period) for context.
	var rows []model.SecurityAuditLog
	h.db.WithContext(ctx).
		Where("created_at >= ? AND event_type = ?", since, model.SecurityEventAuditIntegrityViolation).
		Order("created_at DESC").Limit(10).Find(&rows)

	recent := make([]dto.AuditIntegrityViolation, len(rows))
	var lastViolationAt *time.Time
	for i, row := range rows {
		kind := "unknown"
		if row.Details != nil {
			if _, ok := row.Details["tampered_row_id"]; ok {
				kind = "hmac"
			} else if _, ok := row.Details["chain_break_row_id"]; ok {
				kind = "chain"
			}
		}
		recent[i] = dto.AuditIntegrityViolation{
			EventID:    row.ID,
			Kind:       kind,
			Details:    row.Details,
			DetectedAt: row.CreatedAt,
		}
	}
	if len(rows) > 0 {
		t := rows[0].CreatedAt
		lastViolationAt = &t
	}

	configured := stamped > 0
	coverage := 0
	if total > 0 {
		coverage = int((stamped * 100) / total)
	}
	// Status precedence: recorded violations always win; then "not_configured"
	// (nothing is even stamped); then "not_scanning" — rows are stamped but the
	// background scanner is off, so nothing has actually verified them and we
	// must not claim "verified" (F8); otherwise "verified".
	status := "verified"
	switch {
	case violations > 0:
		status = "violations_detected"
	case !configured:
		status = "not_configured"
	case !h.auditScanningEnabled:
		status = "not_scanning"
	}

	writeJSON(w, dto.AuditIntegrityResponse{
		Period:           period,
		Configured:       configured,
		Scanning:         h.auditScanningEnabled,
		Status:           status,
		TotalEvents:      total,
		StampedEvents:    stamped,
		ChainedEvents:    chained,
		CoveragePercent:  coverage,
		Violations:       violations,
		LastViolationAt:  lastViolationAt,
		RecentViolations: recent,
	})
}

// ==========================================
// Alert Rules API
// ==========================================

// GET /api/admin/alerts/rules
func (h *MonitoringHandler) ListAlertRules(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	rules, err := h.alertRuleRepo.FindAll(ctx)
	if err != nil {
		logger.Errorf("Failed to list alert rules: %v", err)
		writeError(w, "failed to list alert rules", http.StatusInternalServerError)
		return
	}

	response := make([]dto.AlertRuleResponse, len(rules))
	for i, rule := range rules {
		response[i] = dto.FromAlertRule(&rule)
	}

	writeJSON(w, dto.AlertRulesListResponse{
		Rules: response,
		Total: int64(len(rules)),
	})
}

// POST /api/admin/alerts/rules
func (h *MonitoringHandler) CreateAlertRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userID, ok := middleware.GetUserIDFromContext(ctx)
	if !ok {
		writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req dto.AlertRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Name == "" || req.EventType == "" {
		writeError(w, "name and event_type are required", http.StatusBadRequest)
		return
	}

	enabled := true
	if req.Enabled != nil {
		enabled = *req.Enabled
	}

	rule := &model.AlertRule{
		Name:        req.Name,
		Description: req.Description,
		EventType:   req.EventType,
		Condition:   req.Condition,
		Severity:    model.AlertSeverity(req.Severity),
		Enabled:     enabled,
		Actions:     req.Actions,
		Recipients:  req.Recipients,
		WebhookURL:  req.WebhookURL,
		CreatedBy:   &userID,
		CreatedAt:   time.Now(),
		UpdatedAt:   time.Now(),
	}

	if err := h.alertRuleRepo.Create(ctx, rule); err != nil {
		writeError(w, "failed to create alert rule", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	writeJSON(w, dto.FromAlertRule(rule))
}

// PUT /api/admin/alerts/rules/:id
func (h *MonitoringHandler) UpdateAlertRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, "invalid rule ID", http.StatusBadRequest)
		return
	}

	rule, err := h.alertRuleRepo.FindByID(ctx, uint(id))
	if err != nil {
		writeError(w, "alert rule not found", http.StatusNotFound)
		return
	}

	var req dto.AlertRuleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Name != "" {
		rule.Name = req.Name
	}
	if req.Description != "" {
		rule.Description = req.Description
	}
	if req.EventType != "" {
		rule.EventType = req.EventType
	}
	if req.Condition != nil {
		rule.Condition = req.Condition
	}
	if req.Severity != "" {
		rule.Severity = model.AlertSeverity(req.Severity)
	}
	if req.Enabled != nil {
		rule.Enabled = *req.Enabled
	}
	if req.Actions != nil {
		rule.Actions = req.Actions
	}
	if req.Recipients != nil {
		rule.Recipients = req.Recipients
	}
	if req.WebhookURL != "" {
		rule.WebhookURL = req.WebhookURL
	}
	rule.UpdatedAt = time.Now()

	if err := h.alertRuleRepo.Update(ctx, rule); err != nil {
		writeError(w, "failed to update alert rule", http.StatusInternalServerError)
		return
	}

	writeJSON(w, dto.FromAlertRule(rule))
}

// DELETE /api/admin/alerts/rules/:id
func (h *MonitoringHandler) DeleteAlertRule(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, "invalid rule ID", http.StatusBadRequest)
		return
	}

	if err := h.alertRuleRepo.Delete(ctx, uint(id)); err != nil {
		writeError(w, "failed to delete alert rule", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// ==========================================
// Triggered Alerts API
// ==========================================

// GET /api/admin/alerts/history
func (h *MonitoringHandler) GetAlertHistory(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	var alerts []model.TriggeredAlert
	var total int64

	// Filter by acknowledged status if specified
	acknowledged := r.URL.Query().Get("acknowledged")
	if acknowledged == "false" {
		alerts, total, _ = h.triggeredAlertRepo.FindUnacknowledged(ctx, page, pageSize)
	} else {
		alerts, total, _ = h.triggeredAlertRepo.FindAll(ctx, page, pageSize)
	}

	// Get unacknowledged count
	unackCount, _ := h.triggeredAlertRepo.CountUnacknowledged(ctx)

	response := make([]dto.TriggeredAlertResponse, len(alerts))
	for i, alert := range alerts {
		response[i] = dto.FromTriggeredAlert(&alert)
	}

	writeJSON(w, dto.AlertsHistoryResponse{
		Alerts:         response,
		Total:          total,
		Unacknowledged: unackCount,
		Page:           page,
		PageSize:       pageSize,
	})
}

// POST /api/admin/alerts/:id/acknowledge
func (h *MonitoringHandler) AcknowledgeAlert(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userID, ok := middleware.GetUserIDFromContext(ctx)
	if !ok {
		writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, "invalid alert ID", http.StatusBadRequest)
		return
	}

	var req dto.AcknowledgeAlertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		// Allow empty body
		req = dto.AcknowledgeAlertRequest{}
	}

	if err := h.triggeredAlertRepo.Acknowledge(ctx, uint(id), userID, req.Note); err != nil {
		writeError(w, "failed to acknowledge alert", http.StatusInternalServerError)
		return
	}

	writeJSON(w, map[string]string{
		"message": "alert acknowledged",
	})
}

// ==========================================
// Blocked IPs API
// ==========================================

// GET /api/admin/security/blocked-ips
func (h *MonitoringHandler) ListBlockedIPs(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	ips, err := h.blockedIPRepo.FindActive(ctx)
	if err != nil {
		writeError(w, "failed to list blocked IPs", http.StatusInternalServerError)
		return
	}

	response := make([]dto.BlockedIPResponse, len(ips))
	for i, ip := range ips {
		response[i] = dto.FromBlockedIP(&ip)
	}

	writeJSON(w, dto.BlockedIPsListResponse{
		BlockedIPs: response,
		Total:      int64(len(ips)),
	})
}

// POST /api/admin/security/blocked-ips
func (h *MonitoringHandler) BlockIP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	userID, ok := middleware.GetUserIDFromContext(ctx)
	if !ok {
		writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req dto.BlockIPRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	if req.IPAddress == "" {
		writeError(w, "ip_address is required", http.StatusBadRequest)
		return
	}

	// Check if already blocked
	exists, _ := h.blockedIPRepo.IsBlocked(ctx, req.IPAddress)
	if exists {
		writeError(w, "IP is already blocked", http.StatusConflict)
		return
	}

	blockedIP := &model.BlockedIP{
		IPAddress: req.IPAddress,
		Reason:    req.Reason,
		BlockedBy: &userID,
		BlockedAt: time.Now(),
		Permanent: req.Permanent,
	}

	if !req.Permanent && req.DurationHours > 0 {
		expiresAt := time.Now().Add(time.Duration(req.DurationHours) * time.Hour)
		blockedIP.ExpiresAt = &expiresAt
	}

	if err := h.blockedIPRepo.Create(ctx, blockedIP); err != nil {
		writeError(w, "failed to block IP", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	writeJSON(w, dto.FromBlockedIP(blockedIP))
}

// DELETE /api/admin/security/blocked-ips/:id
func (h *MonitoringHandler) UnblockIP(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, "invalid blocked IP ID", http.StatusBadRequest)
		return
	}

	if err := h.blockedIPRepo.Delete(ctx, uint(id)); err != nil {
		writeError(w, "failed to unblock IP", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// GET /api/admin/security/ip-reputation/:ip
func (h *MonitoringHandler) GetIPReputation(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	ipAddress := chi.URLParam(r, "ip")
	if ipAddress == "" {
		writeError(w, "IP address is required", http.StatusBadRequest)
		return
	}

	// Check if blocked
	isBlocked, _ := h.blockedIPRepo.IsBlocked(ctx, ipAddress)

	// Get event counts
	now := time.Now()
	twentyFourHoursAgo := now.Add(-24 * time.Hour)
	sevenDaysAgo := now.AddDate(0, 0, -7)

	var events24h, events7d, failedLogins24h, uniqueUsers int64
	h.db.WithContext(ctx).Model(&model.SecurityAuditLog{}).
		Where("ip_address = ? AND created_at >= ?", ipAddress, twentyFourHoursAgo).
		Count(&events24h)

	h.db.WithContext(ctx).Model(&model.SecurityAuditLog{}).
		Where("ip_address = ? AND created_at >= ?", ipAddress, sevenDaysAgo).
		Count(&events7d)

	h.db.WithContext(ctx).Model(&model.SecurityAuditLog{}).
		Where("ip_address = ? AND created_at >= ? AND event_type = ?", ipAddress, twentyFourHoursAgo, "login_failed").
		Count(&failedLogins24h)

	h.db.WithContext(ctx).Model(&model.SecurityAuditLog{}).
		Where("ip_address = ? AND user_id IS NOT NULL", ipAddress).
		Distinct("user_id").
		Count(&uniqueUsers)

	// Calculate risk score (simple heuristic)
	riskScore := 0
	if failedLogins24h > 10 {
		riskScore += 50
	} else if failedLogins24h > 5 {
		riskScore += 25
	} else if failedLogins24h > 0 {
		riskScore += 10
	}
	if uniqueUsers > 5 {
		riskScore += 25
	}
	if isBlocked {
		riskScore = 100
	}
	if riskScore > 100 {
		riskScore = 100
	}

	// Get first and last seen
	var firstSeen, lastSeen *time.Time
	var firstLog, lastLog model.SecurityAuditLog
	if err := h.db.WithContext(ctx).Model(&model.SecurityAuditLog{}).
		Where("ip_address = ?", ipAddress).
		Order("created_at ASC").
		First(&firstLog).Error; err == nil {
		firstSeen = &firstLog.CreatedAt
	}
	if err := h.db.WithContext(ctx).Model(&model.SecurityAuditLog{}).
		Where("ip_address = ?", ipAddress).
		Order("created_at DESC").
		First(&lastLog).Error; err == nil {
		lastSeen = &lastLog.CreatedAt
	}

	// Get recent events
	var recentEvents []model.SecurityAuditLog
	h.db.WithContext(ctx).
		Preload("User").
		Where("ip_address = ?", ipAddress).
		Order("created_at DESC").
		Limit(10).
		Find(&recentEvents)

	recentEventDTOs := make([]dto.SecurityEventResponse, len(recentEvents))
	for i, event := range recentEvents {
		recentEventDTOs[i] = dto.FromSecurityAuditLog(&event)
	}

	writeJSON(w, dto.IPReputationResponse{
		IPAddress:           ipAddress,
		IsBlocked:           isBlocked,
		RiskScore:           riskScore,
		Events24h:           events24h,
		Events7d:            events7d,
		FailedLogins24h:     failedLogins24h,
		UniqueUsersTargeted: uniqueUsers,
		FirstSeen:           firstSeen,
		LastSeen:            lastSeen,
		RecentEvents:        recentEventDTOs,
	})
}

// ==========================================
// Token Analytics API
// ==========================================

// GET /api/admin/tokens/stats
func (h *MonitoringHandler) GetTokenStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse period
	period := r.URL.Query().Get("period")
	if period == "" {
		period = "24h"
	}

	var since time.Time
	switch period {
	case "15m":
		since = time.Now().Add(-15 * time.Minute)
	case "1h":
		since = time.Now().Add(-1 * time.Hour)
	case "24h":
		since = time.Now().Add(-24 * time.Hour)
	case "7d":
		since = time.Now().AddDate(0, 0, -7)
	case "30d":
		since = time.Now().AddDate(0, 0, -30)
	default:
		since = time.Now().Add(-24 * time.Hour)
	}

	// Count token events
	var issued, refreshed, revoked, expiredAttempts, invalidAttempts int64

	// Count all token issuance events
	h.db.WithContext(ctx).Model(&model.SecurityAuditLog{}).
		Where("created_at >= ? AND event_type = ?", since, "token_issued").
		Count(&issued)

	// Count refresh operations
	h.db.WithContext(ctx).Model(&model.SecurityAuditLog{}).
		Where("created_at >= ? AND event_type = ?", since, "token_refreshed").
		Count(&refreshed)

	// Total tokens = issued + refreshed (each operation generates new tokens)
	accessTokens := issued + refreshed
	refreshTokens := issued + refreshed
	// ID tokens only issued with openid scope - estimate same as access for now
	idTokens := issued + refreshed

	h.db.WithContext(ctx).Model(&model.SecurityAuditLog{}).
		Where("created_at >= ? AND event_type = ?", since, "token_revoked").
		Count(&revoked)

	h.db.WithContext(ctx).Model(&model.SecurityAuditLog{}).
		Where("created_at >= ? AND event_type = ?", since, "expired_token_used").
		Count(&expiredAttempts)

	h.db.WithContext(ctx).Model(&model.SecurityAuditLog{}).
		Where("created_at >= ? AND event_type = ?", since, "invalid_token_used").
		Count(&invalidAttempts)

	// Get by app
	type appStats struct {
		AppID uint
		Name  string
	}
	var apps []appStats
	h.db.WithContext(ctx).Table("apps").Select("id as app_id, name").Scan(&apps)

	byApp := make([]dto.TokenAppStats, 0)
	for _, app := range apps {
		var appIssued, appRefreshed, appRevoked int64
		h.db.WithContext(ctx).Model(&model.SecurityAuditLog{}).
			Where("created_at >= ? AND event_type = ? AND app_id = ?", since, "token_issued", app.AppID).
			Count(&appIssued)
		h.db.WithContext(ctx).Model(&model.SecurityAuditLog{}).
			Where("created_at >= ? AND event_type = ? AND app_id = ?", since, "token_refreshed", app.AppID).
			Count(&appRefreshed)
		h.db.WithContext(ctx).Model(&model.SecurityAuditLog{}).
			Where("created_at >= ? AND event_type = ? AND app_id = ?", since, "token_revoked", app.AppID).
			Count(&appRevoked)

		if appIssued > 0 || appRefreshed > 0 || appRevoked > 0 {
			byApp = append(byApp, dto.TokenAppStats{
				AppID:     app.AppID,
				AppName:   app.Name,
				Issued:    appIssued,
				Refreshed: appRefreshed,
				Revoked:   appRevoked,
			})
		}
	}

	writeJSON(w, dto.TokenStatsResponse{
		Period: period,
		Issued: dto.TokenCounts{
			AccessTokens:  accessTokens,
			RefreshTokens: refreshTokens,
			IDTokens:      idTokens,
		},
		Refreshed:            refreshed,
		Revoked:              revoked,
		ExpiredUsageAttempts: expiredAttempts,
		InvalidUsageAttempts: invalidAttempts,
		ByApp:                byApp,
	})
}

// ==========================================
// SSE Events Stream API
// ==========================================

// GET /api/admin/events/stream
func (h *MonitoringHandler) StreamEvents(w http.ResponseWriter, r *http.Request) {
	// Set headers for SSE.
	//
	// CORS is intentionally NOT set here. The admin router's corsHandler
	// middleware (H-06) already emits the correct, origin-scoped
	// Access-Control-Allow-Origin based on the configured ALLOWED_ORIGINS.
	// Hard-coding "*" on this handler previously overrode that policy on the
	// most sensitive endpoint — the live security-telemetry stream — and a
	// wildcard is invalid for the credentialed cross-origin fetch the SPA uses
	// (Authorization header). Let the configured policy stand.
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")

	// Get flusher for streaming
	flusher, ok := w.(http.Flusher)
	if !ok {
		http.Error(w, "Streaming unsupported", http.StatusInternalServerError)
		return
	}

	// Parse filters from query params
	severityFilter := r.URL.Query().Get("severity")
	eventTypeFilter := r.URL.Query().Get("event_type")

	// Create a context that cancels when client disconnects
	ctx := r.Context()

	// Track last event ID for polling. A live feed must start at the current
	// tip, not at 0: with a large backlog, replaying id>0 in 50-row pages every
	// 2s never reaches recent events within the connection's lifetime, so the
	// stream would show only ancient events and never anything live (F3). When
	// the client resumes with last_event_id we honour it; otherwise we seed from
	// MAX(id) so only genuinely new events are streamed.
	var lastEventID uint
	if lastID := r.URL.Query().Get("last_event_id"); lastID != "" {
		if id, err := strconv.ParseUint(lastID, 10, 64); err == nil {
			lastEventID = uint(id)
		}
	} else if h.db != nil {
		var maxID uint
		if err := h.db.WithContext(ctx).Model(&model.SecurityAuditLog{}).
			Select("COALESCE(MAX(id), 0)").Scan(&maxID).Error; err == nil {
			lastEventID = maxID
		}
	}

	// Send initial heartbeat
	_, _ = w.Write([]byte("event: heartbeat\ndata: {\"status\":\"connected\"}\n\n"))
	flusher.Flush()

	// Poll for new events every 2 seconds
	ticker := time.NewTicker(2 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			// Query for new events
			query := h.db.WithContext(ctx).Model(&model.SecurityAuditLog{}).
				Where("id > ?", lastEventID)

			// Apply filters
			if severityFilter != "" {
				severities := strings.Split(severityFilter, ",")
				query = query.Where("severity IN ?", severities)
			}
			if eventTypeFilter != "" {
				types := strings.Split(eventTypeFilter, ",")
				query = query.Where("event_type IN ?", types)
			}

			var events []model.SecurityAuditLog
			if err := query.
				Preload("User").
				Preload("App").
				Order("id ASC").
				Limit(50).
				Find(&events).Error; err != nil {
				continue
			}

			// Send events
			for _, event := range events {
				eventDTO := dto.FromSecurityAuditLog(&event)
				data, _ := json.Marshal(eventDTO)
				_, _ = w.Write([]byte("event: security_event\n"))
				_, _ = w.Write([]byte("data: "))
				_, _ = w.Write(data)
				_, _ = w.Write([]byte("\n\n"))
				lastEventID = event.ID
			}

			// Send heartbeat if no events
			if len(events) == 0 {
				heartbeat := map[string]interface{}{
					"timestamp": time.Now().Format(time.RFC3339),
					"type":      "heartbeat",
				}
				data, _ := json.Marshal(heartbeat)
				_, _ = w.Write([]byte("event: heartbeat\n"))
				_, _ = w.Write([]byte("data: "))
				_, _ = w.Write(data)
				_, _ = w.Write([]byte("\n\n"))
			}

			flusher.Flush()
		}
	}
}

// ==========================================
// Sessions Management API
// ==========================================

// GET /api/admin/sessions
func (h *MonitoringHandler) ListSessions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	offset := (page - 1) * pageSize

	// Build query for active sessions based on recent token usage
	// We infer sessions from security audit logs of type "token_issued" or "login_success"
	// within the last 24 hours that haven't been followed by a logout
	now := time.Now()
	sessionWindow := now.Add(-24 * time.Hour)

	query := h.db.WithContext(ctx).Table("security_audit_logs").
		Select(`
			DISTINCT ON (user_id, app_id, ip_address)
			id,
			user_id,
			app_id,
			ip_address,
			user_agent,
			created_at,
			created_at as last_activity
		`).
		Where("event_type IN ?", []string{"login_success", "token_issued", "token_refreshed"}).
		Where("created_at >= ?", sessionWindow).
		Where("user_id IS NOT NULL")

	// Apply filters
	if userID := r.URL.Query().Get("user_id"); userID != "" {
		if id, err := strconv.ParseUint(userID, 10, 64); err == nil {
			query = query.Where("user_id = ?", id)
		}
	}
	if appID := r.URL.Query().Get("app_id"); appID != "" {
		if id, err := strconv.ParseUint(appID, 10, 64); err == nil {
			query = query.Where("app_id = ?", id)
		}
	}

	// Count total
	var total int64
	h.db.WithContext(ctx).Table("security_audit_logs").
		Where("event_type IN ?", []string{"login_success", "token_issued", "token_refreshed"}).
		Where("created_at >= ?", sessionWindow).
		Where("user_id IS NOT NULL").
		Distinct("user_id", "app_id", "ip_address").
		Count(&total)

	// Get sessions
	type sessionRow struct {
		ID           uint
		UserID       *uint
		AppID        *uint
		IPAddress    string
		UserAgent    string
		CreatedAt    time.Time
		LastActivity time.Time
	}
	var rows []sessionRow
	query.Order("created_at DESC").
		Offset(offset).
		Limit(pageSize).
		Scan(&rows)

	// Build response with user/app details
	sessions := make([]dto.SessionResponse, 0, len(rows))
	for _, row := range rows {
		session := dto.SessionResponse{
			ID:           strconv.FormatUint(uint64(row.ID), 10),
			IPAddress:    row.IPAddress,
			UserAgent:    row.UserAgent,
			CreatedAt:    row.CreatedAt,
			LastActivity: row.LastActivity,
			ExpiresAt:    row.CreatedAt.Add(24 * time.Hour), // Assume 24h session
		}
		if row.UserID != nil {
			session.UserID = *row.UserID
			var user model.User
			if err := h.db.WithContext(ctx).First(&user, *row.UserID).Error; err == nil {
				session.UserEmail = user.Email
			}
		}
		if row.AppID != nil {
			session.AppID = *row.AppID
			var app model.App
			if err := h.db.WithContext(ctx).First(&app, *row.AppID).Error; err == nil {
				session.AppName = app.Name
			}
		}
		sessions = append(sessions, session)
	}

	writeJSON(w, dto.SessionsListResponse{
		Sessions: sessions,
		Total:    total,
		Page:     page,
		PageSize: pageSize,
	})
}

// GET /api/admin/users/:id/sessions
func (h *MonitoringHandler) GetUserSessions(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()
	userID, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, "invalid user ID", http.StatusBadRequest)
		return
	}

	now := time.Now()
	sessionWindow := now.Add(-24 * time.Hour)

	type sessionRow struct {
		ID           uint
		AppID        *uint
		IPAddress    string
		UserAgent    string
		CreatedAt    time.Time
		LastActivity time.Time
	}
	var rows []sessionRow
	h.db.WithContext(ctx).Table("security_audit_logs").
		Select("id, app_id, ip_address, user_agent, created_at, created_at as last_activity").
		Where("user_id = ?", userID).
		Where("event_type IN ?", []string{"login_success", "token_issued", "token_refreshed"}).
		Where("created_at >= ?", sessionWindow).
		Order("created_at DESC").
		Scan(&rows)

	// Get user info
	var user model.User
	if err := h.db.WithContext(ctx).First(&user, userID).Error; err != nil {
		writeError(w, "user not found", http.StatusNotFound)
		return
	}

	sessions := make([]dto.SessionResponse, 0, len(rows))
	for _, row := range rows {
		session := dto.SessionResponse{
			ID:           strconv.FormatUint(uint64(row.ID), 10),
			UserID:       uint(userID),
			UserEmail:    user.Email,
			IPAddress:    row.IPAddress,
			UserAgent:    row.UserAgent,
			CreatedAt:    row.CreatedAt,
			LastActivity: row.LastActivity,
			ExpiresAt:    row.CreatedAt.Add(24 * time.Hour),
		}
		if row.AppID != nil {
			session.AppID = *row.AppID
			var app model.App
			if err := h.db.WithContext(ctx).First(&app, *row.AppID).Error; err == nil {
				session.AppName = app.Name
			}
		}
		sessions = append(sessions, session)
	}

	writeJSON(w, dto.SessionsListResponse{
		Sessions: sessions,
		Total:    int64(len(sessions)),
		Page:     1,
		PageSize: len(sessions),
	})
}

// ==========================================
// Geographic Analytics API
// ==========================================

// GET /api/admin/security/geo
func (h *MonitoringHandler) GetGeoAnalytics(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Parse period
	period := r.URL.Query().Get("period")
	if period == "" {
		period = "24h"
	}

	var since time.Time
	switch period {
	case "15m":
		since = time.Now().Add(-15 * time.Minute)
	case "1h":
		since = time.Now().Add(-1 * time.Hour)
	case "24h":
		since = time.Now().Add(-24 * time.Hour)
	case "7d":
		since = time.Now().AddDate(0, 0, -7)
	case "30d":
		since = time.Now().AddDate(0, 0, -30)
	default:
		since = time.Now().Add(-24 * time.Hour)
	}

	// Get top IPs with login activity
	type ipStats struct {
		IPAddress   string
		LoginCount  int64
		FailedCount int64
		UniqueUsers int64
	}
	var ipData []ipStats
	h.db.WithContext(ctx).Model(&model.SecurityAuditLog{}).
		Select(`
			ip_address,
			COUNT(*) as login_count,
			SUM(CASE WHEN success = false THEN 1 ELSE 0 END) as failed_count,
			COUNT(DISTINCT user_id) as unique_users
		`).
		Where("created_at >= ?", since).
		Where("event_type IN ?", []string{"login_success", "login_failed"}).
		Group("ip_address").
		Order("login_count DESC").
		Limit(50).
		Scan(&ipData)

	// Collect unique IPs for batch lookup
	ips := make([]string, len(ipData))
	for i, ip := range ipData {
		ips[i] = ip.IPAddress
	}

	// Perform GeoIP lookup
	geoResults := h.geoIPService.LookupBatch(ips)

	// Aggregate by country
	countryStats := make(map[string]*dto.GeoCountryStats)
	for _, ip := range ipData {
		geo := geoResults[ip.IPAddress]
		countryCode := "XX"
		countryName := "Unknown"
		if geo != nil && geo.IsValid {
			countryCode = geo.CountryCode
			countryName = geo.CountryName
			if countryCode == "" {
				countryCode = "XX"
				countryName = "Unknown"
			}
		}

		if _, exists := countryStats[countryCode]; !exists {
			countryStats[countryCode] = &dto.GeoCountryStats{
				CountryCode: countryCode,
				CountryName: countryName,
			}
		}
		countryStats[countryCode].LoginCount += ip.LoginCount
		countryStats[countryCode].FailedCount += ip.FailedCount
		countryStats[countryCode].UniqueUsers += ip.UniqueUsers
	}

	// Convert to slice and sort by login count
	byCountry := make([]dto.GeoCountryStats, 0, len(countryStats))
	for _, stats := range countryStats {
		byCountry = append(byCountry, *stats)
	}

	// Build city stats with geo data
	byCity := make([]dto.GeoCityStats, 0, len(ipData))
	for _, ip := range ipData {
		geo := geoResults[ip.IPAddress]
		city := ip.IPAddress
		countryCode := "XX"
		var lat, lng float64

		if geo != nil && geo.IsValid {
			if geo.City != "" && geo.City != "Unknown" {
				city = geo.City
			}
			countryCode = geo.CountryCode
			lat = geo.Latitude
			lng = geo.Longitude
		}

		byCity = append(byCity, dto.GeoCityStats{
			City:        city,
			CountryCode: countryCode,
			Latitude:    lat,
			Longitude:   lng,
			LoginCount:  ip.LoginCount,
			FailedCount: ip.FailedCount,
		})
	}

	// Detect anomalies: users logging in from multiple countries
	type anomalyRow struct {
		UserID    uint
		Email     string
		IPCount   int64
		FirstIP   string
		LastIP    string
		CreatedAt time.Time
	}
	var anomalyData []anomalyRow
	h.db.WithContext(ctx).Table("security_audit_logs sal").
		Select(`
			sal.user_id,
			u.email,
			COUNT(DISTINCT sal.ip_address) as ip_count,
			MIN(sal.ip_address) as first_ip,
			MAX(sal.ip_address) as last_ip,
			MAX(sal.created_at) as created_at
		`).
		Joins("JOIN users u ON u.id = sal.user_id").
		Where("sal.created_at >= ?", since).
		Where("sal.event_type = ?", "login_success").
		Where("sal.user_id IS NOT NULL").
		Group("sal.user_id, u.email").
		Having("COUNT(DISTINCT sal.ip_address) > 2").
		Order("ip_count DESC").
		Limit(10).
		Scan(&anomalyData)

	anomalies := make([]dto.GeoAnomaly, 0, len(anomalyData))
	for _, a := range anomalyData {
		// Look up geo for first and last IP
		firstGeo := h.geoIPService.Lookup(a.FirstIP)
		lastGeo := h.geoIPService.Lookup(a.LastIP)

		usualCountry := a.FirstIP
		loginCountry := a.LastIP
		if firstGeo != nil && firstGeo.CountryName != "" {
			usualCountry = firstGeo.CountryName
		}
		if lastGeo != nil && lastGeo.CountryName != "" {
			loginCountry = lastGeo.CountryName
		}

		description := "Login from multiple IPs (" + strconv.FormatInt(a.IPCount, 10) + " different IPs)"
		if usualCountry != loginCountry && usualCountry != a.FirstIP && loginCountry != a.LastIP {
			description = "Suspicious: Login from " + loginCountry + " (usually from " + usualCountry + ")"
		}

		anomalies = append(anomalies, dto.GeoAnomaly{
			UserID:       a.UserID,
			UserEmail:    a.Email,
			Description:  description,
			UsualCountry: usualCountry,
			LoginCountry: loginCountry,
			CreatedAt:    a.CreatedAt,
		})
	}

	// Add GeoIP status to response
	geoConfigured := h.geoIPService.IsConfigured()

	writeJSON(w, dto.GeoAnalyticsResponse{
		Period:        period,
		GeoConfigured: geoConfigured,
		ByCountry:     byCountry,
		ByCity:        byCity,
		Anomalies:     anomalies,
	})
}

// ==========================================
// Report Generation API
// ==========================================

// Reports are persisted in the security_reports table (see model.SecurityReport)
// so they survive restarts and are retrievable from any server instance. The
// previous implementation kept them in per-process in-memory maps.

// reportDataToMap round-trips the structured report payload into the generic map
// stored on model.SecurityReport (avoids a model→dto import cycle).
func reportDataToMap(data *dto.SecurityReportData) (map[string]interface{}, error) {
	raw, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	var m map[string]interface{}
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return m, nil
}

// mapToReportData reconstructs the structured payload from the stored map.
func mapToReportData(m map[string]interface{}) (*dto.SecurityReportData, error) {
	raw, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	var data dto.SecurityReportData
	if err := json.Unmarshal(raw, &data); err != nil {
		return nil, err
	}
	return &data, nil
}

func reportResponseFromModel(rec *model.SecurityReport) dto.ReportResponse {
	return dto.ReportResponse{
		ReportID:    rec.ReportID,
		Status:      rec.Status,
		Type:        rec.Type,
		Format:      rec.Format,
		DownloadURL: "/api/admin/reports/" + rec.ReportID + "/download",
		CreatedAt:   rec.CreatedAt,
		CompletedAt: rec.CompletedAt,
		ExpiresAt:   rec.ExpiresAt,
	}
}

// POST /api/admin/reports/security
func (h *MonitoringHandler) GenerateSecurityReport(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var req dto.ReportRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Type == "" {
		req.Type = "security_summary"
	}
	if req.Format == "" {
		req.Format = "json"
	}

	// Validate format
	if req.Format != "json" && req.Format != "csv" {
		writeError(w, "format must be 'json' or 'csv'", http.StatusBadRequest)
		return
	}

	// Best-effort cleanup of expired reports so the table does not grow unbounded.
	h.db.WithContext(ctx).
		Where("expires_at IS NOT NULL AND expires_at < ?", time.Now()).
		Delete(&model.SecurityReport{})

	// Generate report ID and data synchronously.
	reportID := "rpt_" + strconv.FormatInt(time.Now().UnixNano(), 36)
	now := time.Now()
	expiresAt := now.Add(24 * time.Hour)

	data := h.generateReportData(ctx, req.Period)
	dataMap, err := reportDataToMap(data)
	if err != nil {
		writeError(w, "failed to serialize report", http.StatusInternalServerError)
		return
	}

	rec := &model.SecurityReport{
		ReportID:    reportID,
		Status:      "completed",
		Type:        req.Type,
		Format:      req.Format,
		Data:        dataMap,
		CompletedAt: &now,
		ExpiresAt:   &expiresAt,
	}
	if err := h.db.WithContext(ctx).Create(rec).Error; err != nil {
		writeError(w, "failed to persist report", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
	writeJSON(w, reportResponseFromModel(rec))
}

// GET /api/admin/reports/:id
func (h *MonitoringHandler) GetReportStatus(w http.ResponseWriter, r *http.Request) {
	reportID := chi.URLParam(r, "id")

	var rec model.SecurityReport
	if err := h.db.WithContext(r.Context()).
		Where("report_id = ?", reportID).First(&rec).Error; err != nil {
		writeError(w, "report not found", http.StatusNotFound)
		return
	}

	writeJSON(w, reportResponseFromModel(&rec))
}

// GET /api/admin/reports/:id/download
func (h *MonitoringHandler) DownloadReport(w http.ResponseWriter, r *http.Request) {
	reportID := chi.URLParam(r, "id")

	var rec model.SecurityReport
	if err := h.db.WithContext(r.Context()).
		Where("report_id = ?", reportID).First(&rec).Error; err != nil {
		writeError(w, "report not found", http.StatusNotFound)
		return
	}

	// Check expiry
	if rec.IsExpired() {
		writeError(w, "report has expired", http.StatusGone)
		return
	}

	data, err := mapToReportData(rec.Data)
	if err != nil {
		writeError(w, "failed to read report data", http.StatusInternalServerError)
		return
	}

	switch rec.Format {
	case "csv":
		w.Header().Set("Content-Type", "text/csv")
		w.Header().Set("Content-Disposition", "attachment; filename=security_report_"+reportID+".csv")
		h.writeReportCSV(w, data)
	default:
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=security_report_"+reportID+".json")
		writeJSON(w, data)
	}
}

func (h *MonitoringHandler) generateReportData(ctx context.Context, period dto.ReportPeriod) *dto.SecurityReportData {
	from := period.From
	to := period.To
	if from.IsZero() {
		from = time.Now().AddDate(0, 0, -30)
	}
	if to.IsZero() {
		to = time.Now()
	}

	data := &dto.SecurityReportData{
		GeneratedAt: time.Now(),
		Period: dto.ReportPeriod{
			From: from,
			To:   to,
		},
	}

	// Overview statistics
	h.db.WithContext(ctx).Model(&model.SecurityAuditLog{}).
		Where("created_at BETWEEN ? AND ?", from, to).
		Count(&data.Overview.TotalEvents)

	h.db.WithContext(ctx).Model(&model.SecurityAuditLog{}).
		Where("created_at BETWEEN ? AND ? AND severity = ?", from, to, "critical").
		Count(&data.Overview.CriticalEvents)

	h.db.WithContext(ctx).Model(&model.SecurityAuditLog{}).
		Where("created_at BETWEEN ? AND ? AND event_type = ? AND success = ?", from, to, "login_success", true).
		Count(&data.Overview.SuccessfulLogins)

	h.db.WithContext(ctx).Model(&model.SecurityAuditLog{}).
		Where("created_at BETWEEN ? AND ? AND event_type = ?", from, to, "login_failed").
		Count(&data.Overview.FailedLogins)

	h.db.WithContext(ctx).Model(&model.SecurityAuditLog{}).
		Where("created_at BETWEEN ? AND ? AND user_id IS NOT NULL", from, to).
		Distinct("user_id").
		Count(&data.Overview.UniqueUsers)

	h.db.WithContext(ctx).Model(&model.BlockedIP{}).
		Where("blocked_at BETWEEN ? AND ?", from, to).
		Count(&data.Overview.BlockedIPs)

	h.db.WithContext(ctx).Model(&model.TriggeredAlert{}).
		Where("triggered_at BETWEEN ? AND ?", from, to).
		Count(&data.Overview.AlertsTriggered)

	// Threat statistics
	type threatCount struct {
		EventType string
		Count     int64
	}
	var threatCounts []threatCount
	h.db.WithContext(ctx).Model(&model.SecurityAuditLog{}).
		Select("event_type, count(*) as count").
		Where("created_at BETWEEN ? AND ? AND success = ?", from, to, false).
		Group("event_type").
		Order("count DESC").
		Limit(5).
		Scan(&threatCounts)

	for _, tc := range threatCounts {
		var uniqueIPs, affectedUsers int64
		h.db.WithContext(ctx).Model(&model.SecurityAuditLog{}).
			Where("created_at BETWEEN ? AND ? AND event_type = ?", from, to, tc.EventType).
			Distinct("ip_address").
			Count(&uniqueIPs)
		h.db.WithContext(ctx).Model(&model.SecurityAuditLog{}).
			Where("created_at BETWEEN ? AND ? AND event_type = ? AND user_id IS NOT NULL", from, to, tc.EventType).
			Distinct("user_id").
			Count(&affectedUsers)

		data.Threats.TopAttackTypes = append(data.Threats.TopAttackTypes, dto.ThreatTypeStats{
			Type:          tc.EventType,
			Count:         tc.Count,
			UniqueIPs:     uniqueIPs,
			AffectedUsers: affectedUsers,
		})
	}

	// Brute force attempts
	h.db.WithContext(ctx).Model(&model.SecurityAuditLog{}).
		Where("created_at BETWEEN ? AND ? AND event_type = ?", from, to, "brute_force_detected").
		Count(&data.Threats.BruteForceAttempts)

	// User statistics
	h.db.WithContext(ctx).Model(&model.User{}).Count(&data.Users.TotalUsers)

	h.db.WithContext(ctx).Model(&model.SecurityAuditLog{}).
		Where("created_at BETWEEN ? AND ? AND user_id IS NOT NULL", from, to).
		Distinct("user_id").
		Count(&data.Users.ActiveUsers)

	h.db.WithContext(ctx).Model(&model.User{}).
		Where("created_at BETWEEN ? AND ?", from, to).
		Count(&data.Users.NewUsers)

	// App statistics
	h.db.WithContext(ctx).Model(&model.App{}).Count(&data.Apps.TotalApps)

	h.db.WithContext(ctx).Model(&model.SecurityAuditLog{}).
		Where("created_at BETWEEN ? AND ? AND app_id IS NOT NULL", from, to).
		Distinct("app_id").
		Count(&data.Apps.ActiveApps)

	return data
}

func (h *MonitoringHandler) writeReportCSV(w http.ResponseWriter, data *dto.SecurityReportData) {
	// Write CSV header and data
	lines := []string{
		"Security Report",
		"Generated At," + data.GeneratedAt.Format(time.RFC3339),
		"Period," + data.Period.From.Format("2006-01-02") + " to " + data.Period.To.Format("2006-01-02"),
		"",
		"Overview",
		"Total Events," + strconv.FormatInt(data.Overview.TotalEvents, 10),
		"Critical Events," + strconv.FormatInt(data.Overview.CriticalEvents, 10),
		"Successful Logins," + strconv.FormatInt(data.Overview.SuccessfulLogins, 10),
		"Failed Logins," + strconv.FormatInt(data.Overview.FailedLogins, 10),
		"Unique Users," + strconv.FormatInt(data.Overview.UniqueUsers, 10),
		"Blocked IPs," + strconv.FormatInt(data.Overview.BlockedIPs, 10),
		"Alerts Triggered," + strconv.FormatInt(data.Overview.AlertsTriggered, 10),
		"",
		"Users",
		"Total Users," + strconv.FormatInt(data.Users.TotalUsers, 10),
		"Active Users," + strconv.FormatInt(data.Users.ActiveUsers, 10),
		"New Users," + strconv.FormatInt(data.Users.NewUsers, 10),
		"",
		"Applications",
		"Total Apps," + strconv.FormatInt(data.Apps.TotalApps, 10),
		"Active Apps," + strconv.FormatInt(data.Apps.ActiveApps, 10),
	}

	for _, line := range lines {
		_, _ = w.Write([]byte(line + "\n"))
	}
}
