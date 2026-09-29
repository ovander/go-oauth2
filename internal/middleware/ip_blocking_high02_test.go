// Package middleware — tests for the HIGH-02 fail-closed IP blocking fix.
//
// HIGH-02 fix: when the database is unreachable and no stale cache entry
// exists, IsBlocked returns (false, err) instead of (false, nil).
// IPBlockMiddleware then responds with 503 Service Unavailable rather than
// silently allowing the request through (fail-open).
package middleware

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/repository"
)

// ---------------------------------------------------------------------------
// Minimal BlockedIPRepository stub
// ---------------------------------------------------------------------------

type stubBlockedIPRepo struct {
	// isBlockedResult / isBlockedErr drive calls to IsBlocked.
	isBlockedResult bool
	isBlockedErr    error

	// findActiveResult / findActiveErr drive calls to FindActive (used by
	// refreshCache during initial load).
	findActiveResult []model.BlockedIP
	findActiveErr    error
}

func (r *stubBlockedIPRepo) IsBlocked(_ context.Context, _ string) (bool, error) {
	return r.isBlockedResult, r.isBlockedErr
}
func (r *stubBlockedIPRepo) FindActive(_ context.Context) ([]model.BlockedIP, error) {
	return r.findActiveResult, r.findActiveErr
}
func (r *stubBlockedIPRepo) Create(_ context.Context, _ *model.BlockedIP) error { return nil }
func (r *stubBlockedIPRepo) Delete(_ context.Context, _ uint) error             { return nil }
func (r *stubBlockedIPRepo) FindByID(_ context.Context, _ uint) (*model.BlockedIP, error) {
	return nil, errors.New("not found")
}
func (r *stubBlockedIPRepo) FindByIP(_ context.Context, _ string) (*model.BlockedIP, error) {
	return nil, errors.New("not found")
}
func (r *stubBlockedIPRepo) FindAll(_ context.Context) ([]model.BlockedIP, error) {
	return nil, nil
}
func (r *stubBlockedIPRepo) CleanupExpired(_ context.Context) (int64, error) { return 0, nil }

// Compile-time interface compliance check.
var _ repository.BlockedIPRepository = (*stubBlockedIPRepo)(nil)

// ---------------------------------------------------------------------------
// Helper: build a minimal IPBlockChecker without starting its background
// goroutine.  We bypass the goroutine so tests are deterministic.
// ---------------------------------------------------------------------------

func newBareChecker(repo repository.BlockedIPRepository) *IPBlockChecker {
	return &IPBlockChecker{
		repo:        repo,
		cache:       make(map[string]cacheEntry),
		cacheTTL:    30 * time.Second,
		stopCh:      make(chan struct{}),
		refreshChan: make(chan struct{}, 1),
	}
}

// setCacheEntry injects a cache entry directly (simulates a previous DB load).
func setCacheEntry(c *IPBlockChecker, ip string, entry cacheEntry) {
	c.mu.Lock()
	c.cache[ip] = entry
	c.mu.Unlock()
}

// ---------------------------------------------------------------------------
// IsBlocked unit tests
// ---------------------------------------------------------------------------

// TestHIGH02_IsBlocked_DBError_NoCache_ReturnsError verifies that when the
// database returns an error and there is no cache entry for the IP, IsBlocked
// returns (false, err) — the signal for the middleware to fail closed.
func TestHIGH02_IsBlocked_DBError_NoCache_ReturnsError(t *testing.T) {
	repo := &stubBlockedIPRepo{
		isBlockedErr: errors.New("db connection refused"),
	}
	checker := newBareChecker(repo)
	defer close(checker.stopCh)

	blocked, err := checker.IsBlocked(context.Background(), "10.0.0.1")
	if err == nil {
		t.Fatal("expected an error when DB fails and no cache exists, got nil")
	}
	if blocked {
		t.Error("blocked should be false on DB error with no cache")
	}
}

// TestHIGH02_IsBlocked_DBError_StaleBlockedCache_ReturnsTrueNoError verifies
// that when the DB is unavailable but a stale "blocked" entry exists,
// IsBlocked returns (true, nil) — stale data is preferred over no data.
func TestHIGH02_IsBlocked_DBError_StaleBlockedCache_ReturnsTrueNoError(t *testing.T) {
	repo := &stubBlockedIPRepo{
		isBlockedErr: errors.New("db timeout"),
	}
	checker := newBareChecker(repo)
	defer close(checker.stopCh)

	// Inject an expired-but-present "blocked" cache entry.
	setCacheEntry(checker, "192.168.1.100", cacheEntry{
		blocked:   true,
		expiresAt: time.Now().Add(-5 * time.Minute), // already expired
	})

	blocked, err := checker.IsBlocked(context.Background(), "192.168.1.100")
	if err != nil {
		t.Fatalf("expected no error when stale cache exists, got: %v", err)
	}
	if !blocked {
		t.Error("expected blocked=true from stale cache entry")
	}
}

// TestHIGH02_IsBlocked_DBError_StaleAllowedCache_ReturnsFalseNoError verifies
// that a stale "not-blocked" cache entry is also honoured when the DB is down.
func TestHIGH02_IsBlocked_DBError_StaleAllowedCache_ReturnsFalseNoError(t *testing.T) {
	repo := &stubBlockedIPRepo{
		isBlockedErr: errors.New("db timeout"),
	}
	checker := newBareChecker(repo)
	defer close(checker.stopCh)

	setCacheEntry(checker, "10.1.2.3", cacheEntry{
		blocked:   false,
		expiresAt: time.Now().Add(-1 * time.Minute), // expired
	})

	blocked, err := checker.IsBlocked(context.Background(), "10.1.2.3")
	if err != nil {
		t.Fatalf("expected no error when stale cache exists, got: %v", err)
	}
	if blocked {
		t.Error("expected blocked=false from stale not-blocked cache entry")
	}
}

// TestHIGH02_IsBlocked_FreshCache_DoesNotHitDB verifies that a fresh
// (unexpired) cache hit is returned without hitting the database at all.
// The DB stub always returns an error, so any DB call would surface as an error.
func TestHIGH02_IsBlocked_FreshCache_DoesNotHitDB(t *testing.T) {
	repo := &stubBlockedIPRepo{
		isBlockedErr: errors.New("should not be called"),
	}
	checker := newBareChecker(repo)
	defer close(checker.stopCh)

	setCacheEntry(checker, "172.16.0.1", cacheEntry{
		blocked:   true,
		expiresAt: time.Now().Add(30 * time.Second), // still fresh
	})

	blocked, err := checker.IsBlocked(context.Background(), "172.16.0.1")
	if err != nil {
		t.Fatalf("fresh cache hit should not contact DB, got error: %v", err)
	}
	if !blocked {
		t.Error("expected blocked=true from fresh cache entry")
	}
}

// ---------------------------------------------------------------------------
// IPBlockMiddleware integration tests
// ---------------------------------------------------------------------------

var passHandler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
})

// TestHIGH02_Middleware_DBError_NoCache_Returns503 is the core HIGH-02 test:
// a DB error with no stale cache MUST result in 503, not 200 (fail-open).
func TestHIGH02_Middleware_DBError_NoCache_Returns503(t *testing.T) {
	repo := &stubBlockedIPRepo{
		isBlockedErr: errors.New("db down"),
	}
	checker := newBareChecker(repo)
	defer close(checker.stopCh)

	mw := IPBlockMiddleware(checker, nil)
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "10.0.0.1:9999"
	rec := httptest.NewRecorder()

	mw(passHandler).ServeHTTP(rec, req)

	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("expected 503 Service Unavailable on fail-closed, got %d", rec.Code)
	}
}

// TestHIGH02_Middleware_BlockedIP_Returns403 verifies that a blocked IP gets
// 403 Forbidden (basic functionality sanity check).
func TestHIGH02_Middleware_BlockedIP_Returns403(t *testing.T) {
	repo := &stubBlockedIPRepo{isBlockedResult: true}
	checker := newBareChecker(repo)
	defer close(checker.stopCh)

	mw := IPBlockMiddleware(checker, nil)
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	rec := httptest.NewRecorder()

	mw(passHandler).ServeHTTP(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for blocked IP, got %d", rec.Code)
	}
}

// TestHIGH02_Middleware_AllowedIP_Returns200 verifies that a non-blocked IP
// passes through to the downstream handler.
func TestHIGH02_Middleware_AllowedIP_Returns200(t *testing.T) {
	repo := &stubBlockedIPRepo{isBlockedResult: false}
	checker := newBareChecker(repo)
	defer close(checker.stopCh)

	mw := IPBlockMiddleware(checker, nil)
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "8.8.8.8:80"
	rec := httptest.NewRecorder()

	mw(passHandler).ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200 OK for non-blocked IP, got %d", rec.Code)
	}
}
