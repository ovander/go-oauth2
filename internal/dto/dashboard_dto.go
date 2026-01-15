package dto

import "time"

// DashboardStatsResponse contains overview statistics for the admin dashboard
type DashboardStatsResponse struct {
	TotalUsers       int64 `json:"total_users"`
	ActiveUsers      int64 `json:"active_users"`
	TotalApps        int64 `json:"total_apps"`
	ActiveApps       int64 `json:"active_apps"`
	TodayLogins      int64 `json:"today_logins"`
	TodaySignups     int64 `json:"today_signups"`
	FailedLogins24h  int64 `json:"failed_logins_24h"`
	LockedAccounts   int64 `json:"locked_accounts"`
}

// DashboardActivityItem represents a single activity entry
type DashboardActivityItem struct {
	ID          uint                   `json:"id"`
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	UserID      *uint                  `json:"user_id,omitempty"`
	UserEmail   string                 `json:"user_email,omitempty"`
	AppID       *uint                  `json:"app_id,omitempty"`
	AppName     string                 `json:"app_name,omitempty"`
	IPAddress   string                 `json:"ip_address,omitempty"`
	Success     bool                   `json:"success"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
}

// DashboardActivityResponse contains recent activity for the dashboard
type DashboardActivityResponse struct {
	Activities []DashboardActivityItem `json:"activities"`
	Total      int64                   `json:"total"`
}

// DashboardHealthResponse contains system health information
type DashboardHealthResponse struct {
	Status    string                 `json:"status"`
	Database  HealthCheckResult      `json:"database"`
	Uptime    string                 `json:"uptime"`
	Version   string                 `json:"version"`
	Details   map[string]interface{} `json:"details,omitempty"`
}

// HealthCheckResult represents a single health check
type HealthCheckResult struct {
	Status  string `json:"status"`
	Latency string `json:"latency,omitempty"`
	Error   string `json:"error,omitempty"`
}

// LoginTrendItem represents login data for a specific day
type LoginTrendItem struct {
	Date          string `json:"date"`
	SuccessCount  int64  `json:"success_count"`
	FailureCount  int64  `json:"failure_count"`
	UniqueUsers   int64  `json:"unique_users"`
}

// DashboardLoginTrendsResponse contains login trend data
type DashboardLoginTrendsResponse struct {
	Trends []LoginTrendItem `json:"trends"`
	Period string           `json:"period"`
}

// AppUsageItem represents usage statistics for a single app
type AppUsageItem struct {
	AppID        uint   `json:"app_id"`
	AppName      string `json:"app_name"`
	ClientID     string `json:"client_id"`
	TotalUsers   int64  `json:"total_users"`
	ActiveUsers  int64  `json:"active_users"`
	TotalLogins  int64  `json:"total_logins"`
	LastActivity *time.Time `json:"last_activity,omitempty"`
}

// DashboardAppUsageResponse contains app usage statistics
type DashboardAppUsageResponse struct {
	Apps  []AppUsageItem `json:"apps"`
	Total int64          `json:"total"`
}
