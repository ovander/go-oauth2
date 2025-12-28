package handler

import (
	"encoding/json"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/ovandermoten/go-oauth2/internal/dto"
	"github.com/ovandermoten/go-oauth2/internal/middleware"
	"github.com/ovandermoten/go-oauth2/internal/model"
	"github.com/ovandermoten/go-oauth2/internal/repository"
	"gorm.io/gorm"
)

// MonitoringHandler handles security monitoring endpoints
type MonitoringHandler struct {
	db                  *gorm.DB
	alertRuleRepo       repository.AlertRuleRepository
	triggeredAlertRepo  repository.TriggeredAlertRepository
	blockedIPRepo       repository.BlockedIPRepository
	securityAuditRepo   repository.SecurityAuditLogRepository
}

// NewMonitoringHandler creates a new monitoring handler
func NewMonitoringHandler(
	db *gorm.DB,
	alertRuleRepo repository.AlertRuleRepository,
	triggeredAlertRepo repository.TriggeredAlertRepository,
	blockedIPRepo repository.BlockedIPRepository,
	securityAuditRepo repository.SecurityAuditLogRepository,
) *MonitoringHandler {
	return &MonitoringHandler{
		db:                 db,
		alertRuleRepo:      alertRuleRepo,
		triggeredAlertRepo: triggeredAlertRepo,
		blockedIPRepo:      blockedIPRepo,
		securityAuditRepo:  securityAuditRepo,
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

	if success := r.URL.Query().Get("success"); success != "" {
		if success == "true" {
			query = query.Where("success = ?", true)
		} else if success == "false" {
			query = query.Where("success = ?", false)
		}
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

	json.NewEncoder(w).Encode(dto.SecurityEventsListResponse{
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

	json.NewEncoder(w).Encode(dto.ThreatMetricsResponse{
		TimeRange:      timeRange,
		Summary:        summary,
		TopThreats:     topThreats,
		SuspiciousIPs:  suspiciousIPs,
		LockedAccounts: lockedAccounts,
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
		writeError(w, "failed to list alert rules", http.StatusInternalServerError)
		return
	}

	response := make([]dto.AlertRuleResponse, len(rules))
	for i, rule := range rules {
		response[i] = dto.FromAlertRule(&rule)
	}

	json.NewEncoder(w).Encode(dto.AlertRulesListResponse{
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
	json.NewEncoder(w).Encode(dto.FromAlertRule(rule))
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

	json.NewEncoder(w).Encode(dto.FromAlertRule(rule))
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

	json.NewEncoder(w).Encode(dto.AlertsHistoryResponse{
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

	json.NewEncoder(w).Encode(map[string]string{
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

	json.NewEncoder(w).Encode(dto.BlockedIPsListResponse{
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
	json.NewEncoder(w).Encode(dto.FromBlockedIP(blockedIP))
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

	json.NewEncoder(w).Encode(dto.IPReputationResponse{
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

	h.db.WithContext(ctx).Model(&model.SecurityAuditLog{}).
		Where("created_at >= ? AND event_type = ?", since, "token_issued").
		Count(&issued)

	h.db.WithContext(ctx).Model(&model.SecurityAuditLog{}).
		Where("created_at >= ? AND event_type = ?", since, "token_refreshed").
		Count(&refreshed)

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

	json.NewEncoder(w).Encode(dto.TokenStatsResponse{
		Period: period,
		Issued: dto.TokenCounts{
			AccessTokens:  issued,
			RefreshTokens: issued,
			IDTokens:      issued,
		},
		Refreshed:            refreshed,
		Revoked:              revoked,
		ExpiredUsageAttempts: expiredAttempts,
		InvalidUsageAttempts: invalidAttempts,
		ByApp:                byApp,
	})
}
