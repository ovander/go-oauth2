package handler

import (
	"net/http"

	"gorm.io/gorm"
)

type HealthHandler struct {
	db *gorm.DB
}

func NewHealthHandler(db *gorm.DB) *HealthHandler {
	return &HealthHandler{db: db}
}

// GET /health
func (h *HealthHandler) Health(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	writeJSON(w, map[string]string{
		"status": "ok",
	})
}

// GET /health/liveness
func (h *HealthHandler) Liveness(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	writeJSON(w, map[string]string{
		"status": "ok",
	})
}

// GET /health/readiness
func (h *HealthHandler) Readiness(w http.ResponseWriter, r *http.Request) {
	// Check database connection
	sqlDB, err := h.db.DB()
	if err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		writeJSON(w, map[string]string{
			"status":   "error",
			"database": "failed to get DB connection",
		})
		return
	}

	if err := sqlDB.Ping(); err != nil {
		w.WriteHeader(http.StatusServiceUnavailable)
		writeJSON(w, map[string]string{
			"status":   "error",
			"database": "failed to ping database",
		})
		return
	}

	w.Header().Set("Content-Type", "application/json")
	writeJSON(w, map[string]string{
		"status":   "ok",
		"database": "connected",
	})
}
