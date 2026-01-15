package handler

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"github.com/ovandermoten/go-oauth2/internal/dto"
	"github.com/ovandermoten/go-oauth2/internal/repository"
	"gorm.io/gorm"
)

// DashboardHandler handles admin dashboard endpoints
type DashboardHandler struct {
	db              *gorm.DB
	userRepo        repository.UserRepository
	appRepo         repository.AppRepository
	userAppRoleRepo repository.UserAppRoleRepository
	startTime       time.Time
}

// NewDashboardHandler creates a new dashboard handler
func NewDashboardHandler(
	db *gorm.DB,
	userRepo repository.UserRepository,
	appRepo repository.AppRepository,
	userAppRoleRepo repository.UserAppRoleRepository,
) *DashboardHandler {
	return &DashboardHandler{
		db:              db,
		userRepo:        userRepo,
		appRepo:         appRepo,
		userAppRoleRepo: userAppRoleRepo,
		startTime:       time.Now(),
	}
}

// GET /api/admin/dashboard/stats
func (h *DashboardHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	var stats dto.DashboardStatsResponse

	// Total users
	h.db.WithContext(ctx).Table("users").Where("deleted_at IS NULL").Count(&stats.TotalUsers)

	// Active users (logged in within last 30 days)
	thirtyDaysAgo := time.Now().AddDate(0, 0, -30)
	h.db.WithContext(ctx).Table("users").
		Where("deleted_at IS NULL AND last_login > ?", thirtyDaysAgo).
		Count(&stats.ActiveUsers)

	// Total apps
	h.db.WithContext(ctx).Table("apps").Count(&stats.TotalApps)

	// Active apps
	h.db.WithContext(ctx).Table("apps").Where("active = ?", true).Count(&stats.ActiveApps)

	// Today's logins (from security_audit_logs)
	todayStart := time.Now().Truncate(24 * time.Hour)
	h.db.WithContext(ctx).Table("security_audit_logs").
		Where("event_type = ? AND success = ? AND created_at >= ?", "login_success", true, todayStart).
		Count(&stats.TodayLogins)

	// Today's signups
	h.db.WithContext(ctx).Table("users").
		Where("deleted_at IS NULL AND inserted_at >= ?", todayStart).
		Count(&stats.TodaySignups)

	// Failed logins in last 24 hours
	twentyFourHoursAgo := time.Now().Add(-24 * time.Hour)
	h.db.WithContext(ctx).Table("security_audit_logs").
		Where("event_type = ? AND created_at >= ?", "login_failed", twentyFourHoursAgo).
		Count(&stats.FailedLogins24h)

	// Locked accounts
	h.db.WithContext(ctx).Table("users").
		Where("deleted_at IS NULL AND locked_until > ?", time.Now()).
		Count(&stats.LockedAccounts)

	json.NewEncoder(w).Encode(stats)
}

// GET /api/admin/dashboard/activity
func (h *DashboardHandler) GetActivity(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	limit := 10
	if l := r.URL.Query().Get("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil && parsed > 0 && parsed <= 100 {
			limit = parsed
		}
	}

	var activities []dto.DashboardActivityItem

	// Get recent security audit logs
	type auditLogRow struct {
		ID        uint
		EventType string
		UserID    *uint
		AppID     *uint
		IPAddress string
		Success   bool
		Metadata  map[string]interface{}
		CreatedAt time.Time
		UserEmail string
		AppName   string
	}

	var rows []auditLogRow
	h.db.WithContext(ctx).
		Table("security_audit_logs").
		Select("security_audit_logs.id, security_audit_logs.event_type, security_audit_logs.user_id, security_audit_logs.app_id, security_audit_logs.ip_address, security_audit_logs.success, security_audit_logs.metadata, security_audit_logs.created_at, users.email as user_email, apps.name as app_name").
		Joins("LEFT JOIN users ON users.id = security_audit_logs.user_id").
		Joins("LEFT JOIN apps ON apps.id = security_audit_logs.app_id").
		Order("security_audit_logs.created_at DESC").
		Limit(limit).
		Scan(&rows)

	for _, row := range rows {
		activities = append(activities, dto.DashboardActivityItem{
			ID:          row.ID,
			Type:        row.EventType,
			Description: formatEventDescription(row.EventType, row.Success),
			UserID:      row.UserID,
			UserEmail:   row.UserEmail,
			AppID:       row.AppID,
			AppName:     row.AppName,
			IPAddress:   row.IPAddress,
			Success:     row.Success,
			Metadata:    row.Metadata,
			CreatedAt:   row.CreatedAt,
		})
	}

	if activities == nil {
		activities = []dto.DashboardActivityItem{}
	}

	var total int64
	h.db.WithContext(ctx).Table("security_audit_logs").Count(&total)

	json.NewEncoder(w).Encode(dto.DashboardActivityResponse{
		Activities: activities,
		Total:      total,
	})
}

// GET /api/admin/dashboard/health
func (h *DashboardHandler) GetHealth(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	// Check database health
	dbStatus := dto.HealthCheckResult{Status: "healthy"}
	start := time.Now()
	sqlDB, err := h.db.DB()
	if err != nil {
		dbStatus.Status = "unhealthy"
		dbStatus.Error = err.Error()
	} else {
		if err := sqlDB.PingContext(ctx); err != nil {
			dbStatus.Status = "unhealthy"
			dbStatus.Error = err.Error()
		} else {
			dbStatus.Latency = time.Since(start).String()
		}
	}

	// Calculate uptime
	uptime := time.Since(h.startTime)
	uptimeStr := formatDuration(uptime)

	overallStatus := "healthy"
	if dbStatus.Status != "healthy" {
		overallStatus = "unhealthy"
	}

	json.NewEncoder(w).Encode(dto.DashboardHealthResponse{
		Status:   overallStatus,
		Database: dbStatus,
		Uptime:   uptimeStr,
		Version:  "1.0.0",
		Details: map[string]interface{}{
			"go_version": "1.21+",
			"started_at": h.startTime.Format(time.RFC3339),
		},
	})
}

// GET /api/admin/dashboard/login-trends
func (h *DashboardHandler) GetLoginTrends(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	days := 7
	if d := r.URL.Query().Get("days"); d != "" {
		if parsed, err := strconv.Atoi(d); err == nil && parsed > 0 && parsed <= 90 {
			days = parsed
		}
	}

	var trends []dto.LoginTrendItem

	// Get login trends for the past N days
	for i := days - 1; i >= 0; i-- {
		date := time.Now().AddDate(0, 0, -i).Truncate(24 * time.Hour)
		nextDate := date.Add(24 * time.Hour)
		dateStr := date.Format("2006-01-02")

		var successCount, failureCount, uniqueUsers int64

		// Success count
		h.db.WithContext(ctx).Table("security_audit_logs").
			Where("event_type = ? AND success = ? AND created_at >= ? AND created_at < ?",
				"login_success", true, date, nextDate).
			Count(&successCount)

		// Failure count
		h.db.WithContext(ctx).Table("security_audit_logs").
			Where("event_type = ? AND created_at >= ? AND created_at < ?",
				"login_failed", date, nextDate).
			Count(&failureCount)

		// Unique users who logged in
		h.db.WithContext(ctx).Table("security_audit_logs").
			Where("event_type = ? AND success = ? AND created_at >= ? AND created_at < ?",
				"login_success", true, date, nextDate).
			Distinct("user_id").
			Count(&uniqueUsers)

		trends = append(trends, dto.LoginTrendItem{
			Date:         dateStr,
			SuccessCount: successCount,
			FailureCount: failureCount,
			UniqueUsers:  uniqueUsers,
		})
	}

	json.NewEncoder(w).Encode(dto.DashboardLoginTrendsResponse{
		Trends: trends,
		Period: strconv.Itoa(days) + " days",
	})
}

// GET /api/admin/dashboard/app-usage
func (h *DashboardHandler) GetAppUsage(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	type appUsageRow struct {
		ID       uint
		Name     string
		ClientID string
	}

	var apps []appUsageRow
	h.db.WithContext(ctx).Table("apps").Select("id, name, client_id").Scan(&apps)

	var usageItems []dto.AppUsageItem

	for _, app := range apps {
		var totalUsers, activeUsers, totalLogins int64

		// Total users with access to this app
		h.db.WithContext(ctx).Table("user_app_roles").
			Where("app_id = ?", app.ID).
			Count(&totalUsers)

		// Active users (logged in within 30 days)
		thirtyDaysAgo := time.Now().AddDate(0, 0, -30)
		h.db.WithContext(ctx).Table("security_audit_logs").
			Where("app_id = ? AND event_type = ? AND success = ? AND created_at >= ?",
				app.ID, "login_success", true, thirtyDaysAgo).
			Distinct("user_id").
			Count(&activeUsers)

		// Total logins
		h.db.WithContext(ctx).Table("security_audit_logs").
			Where("app_id = ? AND event_type = ? AND success = ?",
				app.ID, "login_success", true).
			Count(&totalLogins)

		// Last activity
		var lastActivity *time.Time
		var lastLog struct {
			CreatedAt time.Time
		}
		result := h.db.WithContext(ctx).Table("security_audit_logs").
			Where("app_id = ?", app.ID).
			Order("created_at DESC").
			Limit(1).
			Scan(&lastLog)
		if result.RowsAffected > 0 {
			lastActivity = &lastLog.CreatedAt
		}

		usageItems = append(usageItems, dto.AppUsageItem{
			AppID:        app.ID,
			AppName:      app.Name,
			ClientID:     app.ClientID,
			TotalUsers:   totalUsers,
			ActiveUsers:  activeUsers,
			TotalLogins:  totalLogins,
			LastActivity: lastActivity,
		})
	}

	if usageItems == nil {
		usageItems = []dto.AppUsageItem{}
	}

	json.NewEncoder(w).Encode(dto.DashboardAppUsageResponse{
		Apps:  usageItems,
		Total: int64(len(apps)),
	})
}

// Helper functions

func formatEventDescription(eventType string, success bool) string {
	descriptions := map[string]string{
		"login_success":    "User logged in successfully",
		"login_failed":     "Login attempt failed",
		"logout":           "User logged out",
		"account_locked":   "Account was locked",
		"password_reset":   "Password was reset",
		"email_verified":   "Email was verified",
		"token_revoked":    "Tokens were revoked",
		"signup":           "New user signed up",
	}

	if desc, ok := descriptions[eventType]; ok {
		return desc
	}
	return eventType
}

func formatDuration(d time.Duration) string {
	days := int(d.Hours() / 24)
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60

	if days > 0 {
		return strconv.Itoa(days) + "d " + strconv.Itoa(hours) + "h " + strconv.Itoa(minutes) + "m"
	}
	if hours > 0 {
		return strconv.Itoa(hours) + "h " + strconv.Itoa(minutes) + "m"
	}
	return strconv.Itoa(minutes) + "m"
}
