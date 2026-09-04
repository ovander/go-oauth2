package handler

import (
	"context"
	"net/http"
	"time"

	"github.com/ovandermoten/go-oauth2/internal/version"
	"gorm.io/gorm"
)

// readinessTimeout bounds each dependency check, so a hung database makes the
// probe fail fast rather than hanging the load balancer's health check with it.
const readinessTimeout = 2 * time.Second

// KeyMaterialProbe reports whether signing key material is usable. The key
// manager satisfies it; nil skips the check.
type KeyMaterialProbe interface {
	GetKeyID() string
}

// StateProbe reports whether the shared-state backend is reachable (B4/B5).
// Nil means no shared backend is configured, and the check is skipped rather
// than reported as failing.
type StateProbe interface {
	Sweep(ctx context.Context) (int64, error)
}

type HealthHandler struct {
	db    *gorm.DB
	keys  KeyMaterialProbe
	state StateProbe
}

func NewHealthHandler(db *gorm.DB) *HealthHandler {
	return &HealthHandler{db: db}
}

// SetProbes wires the optional readiness dependencies (B5). Called once at
// bootstrap; either may be nil, in which case that check is omitted.
func (h *HealthHandler) SetProbes(keys KeyMaterialProbe, state StateProbe) {
	h.keys = keys
	h.state = state
}

// GET /health
func (h *HealthHandler) Health(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	writeJSON(w, map[string]string{
		"status": "ok",
	})
}

// GET /health/liveness
//
// Liveness answers "is this process running", deliberately without touching a
// dependency: a liveness probe that fails on a database blip gets the container
// killed and restarted, which cures nothing and removes capacity exactly when
// the database is already struggling. Dependency checks belong in readiness.
func (h *HealthHandler) Liveness(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	writeJSON(w, map[string]string{
		"status": "ok",
	})
}

// GET /version
func (h *HealthHandler) Version(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	writeJSON(w, map[string]string{
		"version":    version.Version,
		"commit":     version.Commit,
		"branch":     version.Branch,
		"build_time": version.BuildTime,
	})
}

// GET /health/readiness
//
// Readiness answers "should this instance receive traffic". It checks every
// dependency the instance needs to actually serve a token — the database, the
// signing key, and the shared-state backend when one is configured — and
// reports each one by name, so a load balancer taking an instance out of
// rotation also says why (B5).
//
// Every check runs even when an earlier one has already failed: an operator
// debugging a rollout wants the whole picture, not the first problem.
func (h *HealthHandler) Readiness(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), readinessTimeout)
	defer cancel()

	checks := map[string]string{}
	ready := true

	// Database.
	switch sqlDB, err := h.db.DB(); {
	case err != nil:
		checks["database"] = "unavailable: " + err.Error()
		ready = false
	default:
		if err := sqlDB.PingContext(ctx); err != nil {
			checks["database"] = "unreachable: " + err.Error()
			ready = false
		} else {
			checks["database"] = "ok"
		}
	}

	// Signing key material. Without a key ID the instance cannot mint a token,
	// so it must not be sent traffic even though the process is alive and the
	// database answers.
	if h.keys != nil {
		if kid := h.keys.GetKeyID(); kid == "" {
			checks["signing_key"] = "no key material"
			ready = false
		} else {
			checks["signing_key"] = "ok"
		}
	}

	// Shared-state backend. Reached with a real query rather than a ping,
	// because the failure that matters is "the table is not there" (a missed
	// migration) as much as "the server is down".
	if h.state != nil {
		if _, err := h.state.Sweep(ctx); err != nil {
			checks["shared_state"] = "unreachable: " + err.Error()
			ready = false
		} else {
			checks["shared_state"] = "ok"
		}
	}

	w.Header().Set("Content-Type", "application/json")
	body := map[string]any{"status": "ok", "checks": checks}
	if !ready {
		body["status"] = "error"
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	writeJSON(w, body)
}
