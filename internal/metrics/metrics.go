// Package metrics exposes Socrate's Prometheus instrumentation (plan B1 /
// EPIC-4). Everything registers on the default registry; the scrape endpoint
// is served on the ADMIN router only (loopback), never on a public host.
//
// Cardinality rule: labels are bounded enumerations (route pattern, method,
// status class, grant, outcome, event type). No label ever carries a user,
// client, IP or token — those belong in the audit log, not in a time series.
package metrics

import (
	"context"
	"database/sql"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	chimiddleware "github.com/go-chi/chi/v5/middleware"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promauto"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/ovandermoten/go-oauth2/internal/model"
	"github.com/ovandermoten/go-oauth2/internal/repository"
)

const ns = "socrate"

var (
	httpRequests = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns, Subsystem: "http", Name: "requests_total",
		Help: "HTTP requests by router, route pattern, method and status class.",
	}, []string{"router", "route", "method", "status"})
	httpDuration = promauto.NewHistogramVec(prometheus.HistogramOpts{
		Namespace: ns, Subsystem: "http", Name: "request_duration_seconds",
		Help:    "HTTP request latency by router, route pattern and method.",
		Buckets: []float64{.005, .01, .025, .05, .1, .15, .25, .5, 1, 2.5, 5},
	}, []string{"router", "route", "method"})

	tokensIssued = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns, Name: "tokens_issued_total",
		Help: "Token endpoint grants by grant type and outcome (success or the OAuth error class).",
	}, []string{"grant", "outcome"})
	securityEvents = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns, Name: "security_events_total",
		Help: "Security audit events by type and success flag (login, refresh reuse, DPoP, PKCE, scope policy, IP blocks…).",
	}, []string{"event_type", "success"})
	rateLimitHits = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns, Name: "rate_limit_hits_total",
		Help: "Requests refused with 429 by route pattern.",
	}, []string{"route"})
	ipBlocks = promauto.NewCounter(prometheus.CounterOpts{
		Namespace: ns, Name: "ip_blocks_total",
		Help: "Requests refused because the client IP is blocked.",
	})
	policyDecisions = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns, Subsystem: "policy", Name: "decisions_total",
		Help: "Policy decisions (A4) by source, POLICY_MODE and outcome (allow, deny, error).",
	}, []string{"source", "mode", "outcome"})
	policyDivergences = promauto.NewCounterVec(prometheus.CounterOpts{
		Namespace: ns, Subsystem: "policy", Name: "divergences_total",
		Help: "Requests where the policy decision and the code gates disagreed, by kind. Must be zero before a code gate is retired.",
	}, []string{"source", "kind"})
	buildInfo = promauto.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: ns, Name: "build_info",
		Help: "Build metadata (always 1).",
	}, []string{"version", "commit"})

	keyCreatedMu sync.RWMutex
	keyCreatedFn func() time.Time
	_            = promauto.NewGaugeFunc(prometheus.GaugeOpts{
		Namespace: ns, Name: "signing_key_age_seconds",
		Help: "Age of the current RSA signing key; alert when it exceeds the rotation interval.",
	}, func() float64 {
		keyCreatedMu.RLock()
		fn := keyCreatedFn
		keyCreatedMu.RUnlock()
		if fn == nil {
			return 0
		}
		t := fn()
		if t.IsZero() {
			return 0
		}
		return time.Since(t).Seconds()
	})
)

// Handler serves the Prometheus exposition format.
func Handler() http.Handler { return promhttp.Handler() }

// SetBuildInfo publishes the build metadata gauge.
func SetBuildInfo(version, commit string) { buildInfo.WithLabelValues(version, commit).Set(1) }

// SetSigningKeyCreatedAt wires the signing-key age gauge to the key manager.
func SetSigningKeyCreatedAt(fn func() time.Time) {
	keyCreatedMu.Lock()
	keyCreatedFn = fn
	keyCreatedMu.Unlock()
}

// RegisterDBStats publishes the sql.DB pool gauges from the given stats
// function. Safe to call once per process.
func RegisterDBStats(stats func() sql.DBStats) {
	g := func(name, help string, f func(sql.DBStats) float64) {
		promauto.NewGaugeFunc(prometheus.GaugeOpts{Namespace: ns, Subsystem: "db", Name: name, Help: help},
			func() float64 { return f(stats()) })
	}
	g("pool_open_connections", "Open connections in the pool.", func(s sql.DBStats) float64 { return float64(s.OpenConnections) })
	g("pool_in_use", "Connections currently in use.", func(s sql.DBStats) float64 { return float64(s.InUse) })
	g("pool_idle", "Idle connections.", func(s sql.DBStats) float64 { return float64(s.Idle) })
	g("pool_wait_count_total", "Total number of connections waited for.", func(s sql.DBStats) float64 { return float64(s.WaitCount) })
	g("pool_wait_seconds_total", "Total time blocked waiting for a connection.", func(s sql.DBStats) float64 { return s.WaitDuration.Seconds() })
}

// HTTP is the RED middleware: one counter and one histogram per router, keyed
// by the chi route PATTERN (never the raw path, which would carry ids and
// tokens). Wrap it early — after Recoverer, before rate limiting — so refused
// requests are counted too.
func HTTP(router string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			ww := chimiddleware.NewWrapResponseWriter(w, r.ProtoMajor)
			next.ServeHTTP(ww, r)
			route := RoutePattern(r)
			status := ww.Status()
			if status == 0 {
				status = http.StatusOK
			}
			httpRequests.WithLabelValues(router, route, r.Method, strconv.Itoa(status/100)+"xx").Inc()
			httpDuration.WithLabelValues(router, route, r.Method).Observe(time.Since(start).Seconds())
		})
	}
}

// RoutePattern returns the chi route pattern that matched the request
// ("/api/admin/users/{id}"), or "unmatched" before/without routing.
func RoutePattern(r *http.Request) string {
	if rc := chi.RouteContext(r.Context()); rc != nil {
		if p := rc.RoutePattern(); p != "" {
			return p
		}
	}
	return "unmatched"
}

// TokenIssued records one token-endpoint grant attempt.
func TokenIssued(grant, outcome string) {
	if grant == "" {
		grant = "unknown"
	}
	tokensIssued.WithLabelValues(grant, outcome).Inc()
}

// RateLimited records a 429 for the request's route pattern.
func RateLimited(r *http.Request) { rateLimitHits.WithLabelValues(RoutePattern(r)).Inc() }

// IPBlocked records a request refused by the IP block list.
func IPBlocked() { ipBlocks.Inc() }

// PolicyDecision records one policy decision.
func PolicyDecision(source, mode, outcome string) {
	policyDecisions.WithLabelValues(source, mode, outcome).Inc()
}

// PolicyDivergence records one disagreement between the policy and the code
// gates it shadows.
func PolicyDivergence(source, kind string) { policyDivergences.WithLabelValues(source, kind).Inc() }

// auditRepo decorates the security audit repository so every persisted event
// is also counted — one hook covers logins, refresh reuse, DPoP and PKCE
// failures, scope denials, blocks and every future event type.
type auditRepo struct {
	repository.SecurityAuditLogRepository
}

func (a auditRepo) Create(ctx context.Context, l *model.SecurityAuditLog) error {
	err := a.SecurityAuditLogRepository.Create(ctx, l)
	if err == nil && l != nil {
		securityEvents.WithLabelValues(string(l.EventType), strconv.FormatBool(l.Success)).Inc()
	}
	return err
}

// InstrumentAuditRepo wraps repo so successful Create calls increment
// socrate_security_events_total.
func InstrumentAuditRepo(repo repository.SecurityAuditLogRepository) repository.SecurityAuditLogRepository {
	return auditRepo{repo}
}
