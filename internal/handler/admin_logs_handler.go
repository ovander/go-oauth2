package handler

import (
	"encoding/csv"
	"fmt"
	"net/http"
	"strconv"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/ovander/go-oauth2/internal/dto"
	"github.com/ovander/go-oauth2/internal/model"
	"gorm.io/gorm"
)

// AdminLogsHandler serves the admin audit-log endpoints.
//
// Routes (all under /api/admin, protected by AuthMiddleware):
//
//	GET /api/admin/logs          – paginated list with optional filters
//	GET /api/admin/logs/export   – CSV download of matching rows
//	GET /api/admin/logs/{id}     – single entry
//
// The handler queries the admin_logs table directly (same pattern as
// MonitoringHandler) to support flexible, multi-field filtering without
// forcing a large change to the existing AdminLogRepository interface.
type AdminLogsHandler struct {
	db *gorm.DB
}

// NewAdminLogsHandler creates the handler.
func NewAdminLogsHandler(db *gorm.DB) *AdminLogsHandler {
	return &AdminLogsHandler{db: db}
}

// ==========================================
// GET /api/admin/logs
// ==========================================

// ListLogs returns a paginated, filterable list of admin audit-log entries.
//
// Supported query parameters:
//
//	admin_id     – filter by the acting admin's user ID
//	action       – filter by action string (e.g. "update_role", "unlock_user")
//	target_type  – "user" | "application" | "settings"
//	start_date   – RFC3339 lower bound (inclusive) on created_at
//	end_date     – RFC3339 upper bound (inclusive) on created_at
//	page         – 1-based page number (default: 1)
//	page_size    – rows per page, 1–100 (default: 25)
func (h *AdminLogsHandler) ListLogs(w http.ResponseWriter, r *http.Request) {
	page, pageSize := parsePage(r, 25)
	query := h.buildQuery(r)

	var total int64
	if err := query.Count(&total).Error; err != nil {
		writeError(w, "failed to count logs", http.StatusInternalServerError)
		return
	}

	var logs []model.AdminLog
	offset := (page - 1) * pageSize
	err := h.db.WithContext(r.Context()).
		Model(&model.AdminLog{}).
		Scopes(h.applyFilters(r)).
		Preload("Admin").
		Preload("App").
		Preload("TargetUser").
		Order("inserted_at DESC").
		Offset(offset).
		Limit(pageSize).
		Find(&logs).Error
	if err != nil {
		writeError(w, "failed to query logs", http.StatusInternalServerError)
		return
	}

	response := make([]dto.AdminAuditLogResponse, len(logs))
	for i, l := range logs {
		response[i] = dto.FromAdminLog(&l)
	}

	writeJSON(w, dto.AdminAuditListResponse{
		Logs:       response,
		TotalCount: total,
		Page:       page,
		PageSize:   pageSize,
	})
}

// ==========================================
// GET /api/admin/logs/{id}
// ==========================================

// GetLog returns a single audit-log entry by ID.
func (h *AdminLogsHandler) GetLog(w http.ResponseWriter, r *http.Request) {
	id, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, "invalid log ID", http.StatusBadRequest)
		return
	}

	var log model.AdminLog
	err = h.db.WithContext(r.Context()).
		Preload("Admin").
		Preload("App").
		Preload("TargetUser").
		First(&log, id).Error
	if err != nil {
		writeError(w, "log entry not found", http.StatusNotFound)
		return
	}

	writeJSON(w, dto.FromAdminLog(&log))
}

// ==========================================
// GET /api/admin/logs/export
// ==========================================

// ExportLogs streams the matching rows as a CSV attachment.
// Accepts the same filter params as ListLogs; ignores page/page_size
// (always exports all matching rows, up to 10 000).
func (h *AdminLogsHandler) ExportLogs(w http.ResponseWriter, r *http.Request) {
	var logs []model.AdminLog
	err := h.db.WithContext(r.Context()).
		Model(&model.AdminLog{}).
		Scopes(h.applyFilters(r)).
		Preload("Admin").
		Preload("App").
		Preload("TargetUser").
		Order("inserted_at DESC").
		Limit(10000).
		Find(&logs).Error
	if err != nil {
		writeError(w, "failed to query logs", http.StatusInternalServerError)
		return
	}

	filename := fmt.Sprintf("admin_audit_logs_%s.csv", time.Now().Format("2006-01-02"))
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename="+filename)

	cw := csv.NewWriter(w)
	//nolint:errcheck // G104: streaming CSV write errors are not recoverable once headers are sent
	_ = cw.Write([]string{
		"id", "admin_id", "admin_email", "action",
		"target_type", "target_id", "target_name",
		"ip_address", "created_at",
	})

	for _, l := range logs {
		row := dto.FromAdminLog(&l)
		targetID := ""
		if row.TargetID != nil {
			targetID = strconv.FormatUint(uint64(*row.TargetID), 10)
		}
		//nolint:errcheck // G104: see above
		// P4-2: every free-text column is user-influenced (emails, app names,
		// user agents) and must not be able to start a spreadsheet formula.
		_ = cw.Write([]string{
			strconv.FormatUint(uint64(row.ID), 10),
			strconv.FormatUint(uint64(row.AdminID), 10),
			csvSafe(row.AdminEmail),
			csvSafe(row.Action),
			csvSafe(row.TargetType),
			targetID,
			csvSafe(row.TargetName),
			csvSafe(row.IPAddress),
			row.CreatedAt.Format(time.RFC3339),
		})
	}

	cw.Flush()
}

// ==========================================
// Helpers
// ==========================================

// parsePage extracts validated page / page_size query params.
func parsePage(r *http.Request, defaultSize int) (page, pageSize int) {
	page, _ = strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	pageSize, _ = strconv.Atoi(r.URL.Query().Get("page_size"))
	if pageSize < 1 || pageSize > 100 {
		pageSize = defaultSize
	}
	return page, pageSize
}

// buildQuery is a convenience wrapper that returns a counted query using the
// same filter set as applyFilters, so we do not need to repeat the filter
// logic for the COUNT and the data fetch.
func (h *AdminLogsHandler) buildQuery(r *http.Request) *gorm.DB {
	return h.db.WithContext(r.Context()).
		Model(&model.AdminLog{}).
		Scopes(h.applyFilters(r))
}

// applyFilters returns a gorm Scope (func(*gorm.DB)*gorm.DB) that applies all
// supported query-param filters to the given query.
func (h *AdminLogsHandler) applyFilters(r *http.Request) func(*gorm.DB) *gorm.DB {
	return func(db *gorm.DB) *gorm.DB {
		// admin_id
		if v := r.URL.Query().Get("admin_id"); v != "" {
			if id, err := strconv.ParseUint(v, 10, 64); err == nil {
				db = db.Where("admin_id = ?", id)
			}
		}

		// action
		if v := r.URL.Query().Get("action"); v != "" {
			db = db.Where("action = ?", v)
		}

		// target_type → translate to column constraints
		switch r.URL.Query().Get("target_type") {
		case "user":
			db = db.Where("target_user_id IS NOT NULL")
		case "application":
			db = db.Where("app_id IS NOT NULL AND target_user_id IS NULL")
		case "settings":
			db = db.Where("app_id IS NULL AND target_user_id IS NULL")
		}

		// start_date / end_date (RFC3339)
		if v := r.URL.Query().Get("start_date"); v != "" {
			if t, err := time.Parse(time.RFC3339, v); err == nil {
				db = db.Where("inserted_at >= ?", t)
			}
		}
		if v := r.URL.Query().Get("end_date"); v != "" {
			if t, err := time.Parse(time.RFC3339, v); err == nil {
				db = db.Where("inserted_at <= ?", t)
			}
		}

		return db
	}
}
