package service

import (
	"context"
	"net"
	"net/http"
	"time"
	"unicode/utf8"

	"github.com/ovander/go-oauth2/internal/contextkeys"
	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/repository"
	"github.com/ovander/go-oauth2/pkg/logger"
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
	// CorrelationID optionally overrides the correlation ID. When empty, Log
	// derives it from the request context (RFC-007/RFC-008).
	CorrelationID string
}

type securityAuditService struct {
	repo repository.SecurityAuditLogRepository
}

// NewSecurityAuditService creates a new security audit service
func NewSecurityAuditService(repo repository.SecurityAuditLogRepository) SecurityAuditService {
	logger.WithFields(logger.Fields{
		"service": "security_audit",
	}).Debug("✅ Security audit service initialized")

	return &securityAuditService{repo: repo}
}

func (s *securityAuditService) Log(ctx context.Context, event SecurityEvent) error {
	severity := model.GetSeverityForEvent(event.EventType, event.Success)

	// RFC-007/RFC-008: stamp the correlation ID so each audit row identifies the
	// request that produced it. An explicit event.CorrelationID wins; otherwise
	// derive it from the request context.
	correlationID := event.CorrelationID
	if correlationID == "" {
		correlationID = correlationIDFromContext(ctx)
	}

	log := &model.SecurityAuditLog{
		UserID:        event.UserID,
		AppID:         event.AppID,
		EventType:     event.EventType,
		Severity:      severity,
		IPAddress:     event.IPAddress,
		UserAgent:     event.UserAgent,
		CorrelationID: correlationID,
		Success:       event.Success,
		Details:       event.Details,
		CreatedAt:     time.Now(),
	}

	return s.repo.Create(ctx, log)
}

// correlationIDFromContext extracts the request correlation ID set by
// middleware.CorrelationID (contextkeys.RequestIDKey), or "" if absent.
func correlationIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if id, ok := ctx.Value(contextkeys.RequestIDKey).(string); ok {
		return id
	}
	return ""
}

// contextString returns the string stored in ctx under key, or "".
func contextString(ctx context.Context, key interface{}) string {
	if ctx == nil {
		return ""
	}
	s, _ := ctx.Value(key).(string)
	return s
}

// maxUserAgentLen matches the user_agent column (varchar(500)).
const maxUserAgentLen = 500

// truncateUTF8 cuts s to at most max bytes without splitting a character:
// PostgreSQL rejects invalid UTF-8, and a rejected audit insert is lost silently.
func truncateUTF8(s string, max int) string {
	if len(s) <= max {
		return s
	}
	for max > 0 && !utf8.RuneStart(s[max]) {
		max--
	}
	return s[:max]
}

// newSecurityAuditLog builds a SecurityAuditLog with the severity derived for
// the event and the correlation ID stamped from ctx (RFC-007/RFC-008). It is
// the shared construction path for the direct (hot-path) audit writers
// (authService/oauthService.logSecurityEvent) so correlation coverage is
// consistent across all request-scoped audit rows.
//
// An empty ipAddress or userAgent is taken from ctx, where middleware.ClientIP
// put the trusted-proxy-aware client IP and the User-Agent: those writers only
// receive the context, and wrote rows without either before.
func newSecurityAuditLog(ctx context.Context, eventType model.SecurityEventType, userID, appID *uint, ipAddress, userAgent string, success bool, details map[string]interface{}) *model.SecurityAuditLog {
	if ipAddress == "" {
		ipAddress = contextString(ctx, contextkeys.IPAddressKey)
	}
	if userAgent == "" {
		userAgent = contextString(ctx, contextkeys.UserAgentKey)
	}
	userAgent = truncateUTF8(userAgent, maxUserAgentLen)
	return &model.SecurityAuditLog{
		UserID:        userID,
		AppID:         appID,
		EventType:     eventType,
		Severity:      model.GetSeverityForEvent(eventType, success),
		IPAddress:     ipAddress,
		UserAgent:     userAgent,
		CorrelationID: correlationIDFromContext(ctx),
		Success:       success,
		Details:       details,
		CreatedAt:     time.Now(),
	}
}

func (s *securityAuditService) LogFromRequest(ctx context.Context, r *http.Request, event SecurityEvent) error {
	// The client IP resolved once per request by middleware.ClientIP, which honours
	// forwarding headers only from TRUSTED_PROXIES. Never read them here: any peer
	// can send X-Forwarded-For.
	if event.IPAddress == "" {
		event.IPAddress = clientIPFromRequest(ctx, r)
	}

	if event.UserAgent == "" {
		// Cut on a character boundary: PostgreSQL rejects invalid UTF-8, and a
		// rejected audit insert is lost.
		event.UserAgent = truncateUTF8(r.UserAgent(), maxUserAgentLen)
	}

	return s.Log(ctx, event)
}

// clientIPFromRequest returns the client IP that middleware.ClientIP resolved and
// stored under contextkeys.IPAddressKey (trusted-proxy aware). Without it — the
// middleware is not installed, e.g. in a unit test — it falls back to the bare
// peer address and never to a forwarding header, so an untrusted peer cannot
// choose the address that is audited.
func clientIPFromRequest(ctx context.Context, r *http.Request) string {
	if ip := contextString(ctx, contextkeys.IPAddressKey); ip != "" {
		return ip
	}
	if ip := contextString(r.Context(), contextkeys.IPAddressKey); ip != "" {
		return ip
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
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
