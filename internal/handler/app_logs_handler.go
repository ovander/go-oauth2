package handler

import (
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/ovander/go-oauth2/internal/dto"
	"github.com/ovander/go-oauth2/internal/service"
)

type AppLogsHandler struct {
	appActivityLogService service.AppActivityLogService
}

func NewAppLogsHandler(appActivityLogService service.AppActivityLogService) *AppLogsHandler {
	return &AppLogsHandler{
		appActivityLogService: appActivityLogService,
	}
}

// GET /api/apps/:app_id/logs
func (h *AppLogsHandler) GetLogs(w http.ResponseWriter, r *http.Request) {
	appID, err := strconv.ParseUint(chi.URLParam(r, "app_id"), 10, 64)
	if err != nil {
		writeError(w, "invalid app ID", http.StatusBadRequest)
		return
	}

	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	pageSize, _ := strconv.Atoi(r.URL.Query().Get("page_size"))
	if pageSize < 1 || pageSize > 100 {
		pageSize = 20
	}

	logs, totalCount, err := h.appActivityLogService.GetByApp(r.Context(), uint(appID), page, pageSize)
	if err != nil {
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := make([]dto.AppActivityLogResponse, len(logs))
	for i, log := range logs {
		response[i] = dto.AppActivityLogResponse{
			ID:            log.ID,
			AppID:         log.AppID,
			UserID:        log.UserID,
			EventType:     string(log.EventType),
			EventCategory: string(log.EventCategory),
			Metadata:      log.Metadata,
			IPAddress:     log.IPAddress,
			UserAgent:     log.UserAgent,
			Success:       log.Success,
			CreatedAt:     log.CreatedAt,
		}
	}

	writeJSON(w, dto.AppActivityLogListResponse{
		Logs:       response,
		TotalCount: totalCount,
		Page:       page,
		PageSize:   pageSize,
	})
}
