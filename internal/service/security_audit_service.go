package service

import (
	"context"
	"net/http"
	"time"

	"github.com/socrate-auth/go-oauth/internal/model"
	"github.com/socrate-auth/go-oauth/internal/repository"
)

// SecurityAuditService provides security audit logging functionality
type SecurityAuditService interface {
	// Log creates a security audit log entry
	Log(ctx context.Context, event SecurityEvent) error

	// LogFromRequest creates a log entry extracting IP and User-Agent from request
	LogFromRequest(ctx context.Context, r *http.Request, event SecurityEvent) error

	// Query methods
	GetByUser(ctx context.Context, userID uint, page, pageSize int) ([]model.SecurityAuditLog, int64, error)
	GetByApp(ctx context.Context, appID uint, page, pageSize int) ([]model.SecurityAuditLog, int64, error)
	GetByEventType(ctx context.Context, eventType model.SecurityEventType, page, pageSize int) ([]model.SecurityAuditLog, int64, error)
	GetBySeverity(ctx context.Context, severity model.SecuritySeverity, page, pageSize int) ([]model.SecurityAuditLog, int64, error)
	GetByDateRange(ctx context.Context, start, end time.Time, page, pageSize int) ([]model.SecurityAuditLog, int64, error)
	GetByIPAddress(ctx context.Context, ipAddress string, page, pageSize int) ([]model.SecurityAuditLog, int64, error)

	// Analysis methods
	GetFailedLoginsByUser(ctx context.Context, userID uint, since time.Time) ([]model.SecurityAuditLog, error)
	GetFailedLoginsByIP(ctx context.Context, ipAddress string, since time.Time) ([]model.SecurityAuditLog, error)
	CountCriticalEventsSince(ctx context.Context, since time.Time) (int64, error)

	// Maintenance
	CleanupOldLogs(ctx context.Context, retentionDays int) (int64, error)
}

// SecurityEvent represents a security event to be logged
type SecurityEvent struct {
	UserID    *uint
	AppID     *uint
	EventType model.SecurityEventType
	IPAddress string
	UserAgent string
	Success   bool
	Details   map[string]interface{}
}

type securityAuditService struct {
	repo repository.SecurityAuditLogRepository
}

// NewSecurityAuditService creates a new security audit service
func NewSecurityAuditService(repo repository.SecurityAuditLogRepository) SecurityAuditService {
	return &securityAuditService{repo: repo}
}

func (s *securityAuditService) Log(ctx context.Context, event SecurityEvent) error {
	severity := model.GetSeverityForEvent(event.EventType, event.Success)

	log := &model.SecurityAuditLog{
		UserID:    event.UserID,
		AppID:     event.AppID,
		EventType: event.EventType,
		Severity:  severity,
		IPAddress: event.IPAddress,
		UserAgent: event.UserAgent,
		Success:   event.Success,
		Details:   event.Details,
		CreatedAt: time.Now(),
	}

	return s.repo.Create(ctx, log)
}

func (s *securityAuditService) LogFromRequest(ctx context.Context, r *http.Request, event SecurityEvent) error {
	// Extract IP address from request
	if event.IPAddress == "" {
		event.IPAddress = extractIPAddress(r)
	}

	// Extract User-Agent if not provided
	if event.UserAgent == "" {
		event.UserAgent = r.UserAgent()
		// Truncate if too long
		if len(event.UserAgent) > 500 {
			event.UserAgent = event.UserAgent[:500]
		}
	}

	return s.Log(ctx, event)
}

// extractIPAddress gets the client IP from the request, considering proxies
func extractIPAddress(r *http.Request) string {
	// Check X-Forwarded-For first (may be set by reverse proxy)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		// X-Forwarded-For can contain multiple IPs, take the first one
		for i := 0; i < len(xff); i++ {
			if xff[i] == ',' {
				return xff[:i]
			}
		}
		return xff
	}

	// Check X-Real-IP (nginx)
	if xri := r.Header.Get("X-Real-IP"); xri != "" {
		return xri
	}

	// Fall back to RemoteAddr
	// RemoteAddr is in the form "IP:port", so strip the port
	addr := r.RemoteAddr
	for i := len(addr) - 1; i >= 0; i-- {
		if addr[i] == ':' {
			return addr[:i]
		}
		if addr[i] == ']' {
			// IPv6 address with brackets
			return addr
		}
	}
	return addr
}

func (s *securityAuditService) GetByUser(ctx context.Context, userID uint, page, pageSize int) ([]model.SecurityAuditLog, int64, error) {
	page, pageSize = normalizePagination(page, pageSize)
	return s.repo.FindByUser(ctx, userID, page, pageSize)
}

func (s *securityAuditService) GetByApp(ctx context.Context, appID uint, page, pageSize int) ([]model.SecurityAuditLog, int64, error) {
	page, pageSize = normalizePagination(page, pageSize)
	return s.repo.FindByApp(ctx, appID, page, pageSize)
}

func (s *securityAuditService) GetByEventType(ctx context.Context, eventType model.SecurityEventType, page, pageSize int) ([]model.SecurityAuditLog, int64, error) {
	page, pageSize = normalizePagination(page, pageSize)
	return s.repo.FindByEventType(ctx, eventType, page, pageSize)
}

func (s *securityAuditService) GetBySeverity(ctx context.Context, severity model.SecuritySeverity, page, pageSize int) ([]model.SecurityAuditLog, int64, error) {
	page, pageSize = normalizePagination(page, pageSize)
	return s.repo.FindBySeverity(ctx, severity, page, pageSize)
}

func (s *securityAuditService) GetByDateRange(ctx context.Context, start, end time.Time, page, pageSize int) ([]model.SecurityAuditLog, int64, error) {
	page, pageSize = normalizePagination(page, pageSize)
	return s.repo.FindByDateRange(ctx, start, end, page, pageSize)
}

func (s *securityAuditService) GetByIPAddress(ctx context.Context, ipAddress string, page, pageSize int) ([]model.SecurityAuditLog, int64, error) {
	page, pageSize = normalizePagination(page, pageSize)
	return s.repo.FindByIPAddress(ctx, ipAddress, page, pageSize)
}

func (s *securityAuditService) GetFailedLoginsByUser(ctx context.Context, userID uint, since time.Time) ([]model.SecurityAuditLog, error) {
	return s.repo.FindFailedLoginsByUser(ctx, userID, since)
}

func (s *securityAuditService) GetFailedLoginsByIP(ctx context.Context, ipAddress string, since time.Time) ([]model.SecurityAuditLog, error) {
	return s.repo.FindFailedLoginsByIP(ctx, ipAddress, since)
}

func (s *securityAuditService) CountCriticalEventsSince(ctx context.Context, since time.Time) (int64, error) {
	return s.repo.CountBySeveritySince(ctx, model.SecuritySeverityCritical, since)
}

func (s *securityAuditService) CleanupOldLogs(ctx context.Context, retentionDays int) (int64, error) {
	if retentionDays < 1 {
		retentionDays = 90 // Default 90 day retention
	}
	before := time.Now().AddDate(0, 0, -retentionDays)
	return s.repo.DeleteOlderThan(ctx, before)
}

// normalizePagination ensures page and pageSize are within valid ranges
func normalizePagination(page, pageSize int) (int, int) {
	if page < 1 {
		page = 1
	}
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}
	return page, pageSize
}
