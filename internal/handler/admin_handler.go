package handler

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/ovandermoten/go-oauth2/internal/dto"
	"github.com/ovandermoten/go-oauth2/internal/middleware"
	"github.com/ovandermoten/go-oauth2/internal/model"
	"github.com/ovandermoten/go-oauth2/internal/service"
)

type AdminHandler struct {
	appService         service.AppService
	userService        service.UserService
	adminLogService    service.AdminLogService
	appActivityService service.AppActivityLogService
}

func NewAdminHandler(
	appService service.AppService,
	userService service.UserService,
	adminLogService service.AdminLogService,
	appActivityService service.AppActivityLogService,
) *AdminHandler {
	return &AdminHandler{
		appService:         appService,
		userService:        userService,
		adminLogService:    adminLogService,
		appActivityService: appActivityService,
	}
}

// GET /api/admin/apps
func (h *AdminHandler) ListApps(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserIDFromContext(r.Context())
	if !ok {
		writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	apps, err := h.appService.GetByOwnerID(r.Context(), userID)
	if err != nil {
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := make([]dto.AppResponse, len(apps))
	for i, app := range apps {
		response[i] = dto.AppResponse{
			ID:           app.ID,
			Name:         app.Name,
			ClientID:     app.ClientID,
			Active:       app.Active,
			URL:          app.URL,
			RedirectURIs: app.RedirectURIs,
			OwnerID:      app.OwnerID,
			CreatedAt:    app.CreatedAt,
		}
	}

	json.NewEncoder(w).Encode(dto.AppListResponse{
		Apps:       response,
		TotalCount: int64(len(apps)),
	})
}

// GET /api/admin/apps/:id
func (h *AdminHandler) GetApp(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserIDFromContext(r.Context())
	if !ok {
		writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	appID, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, "invalid app ID", http.StatusBadRequest)
		return
	}

	app, err := h.appService.GetByID(r.Context(), uint(appID))
	if err != nil {
		writeError(w, "app not found", http.StatusNotFound)
		return
	}

	// Check ownership or global admin
	user, _ := r.Context().Value("current_user").(*model.User)
	if app.OwnerID != nil && *app.OwnerID != userID {
		if user == nil || !user.IsGlobalAdmin() {
			writeError(w, "forbidden", http.StatusForbidden)
			return
		}
	}

	json.NewEncoder(w).Encode(dto.AppResponse{
		ID:           app.ID,
		Name:         app.Name,
		ClientID:     app.ClientID,
		Active:       app.Active,
		URL:          app.URL,
		RedirectURIs: app.RedirectURIs,
		OwnerID:      app.OwnerID,
		CreatedAt:    app.CreatedAt,
	})
}

// POST /api/admin/apps
func (h *AdminHandler) CreateApp(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserIDFromContext(r.Context())
	if !ok {
		writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req dto.CreateAppRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Name == "" {
		writeError(w, "name is required", http.StatusBadRequest)
		return
	}

	app, clientSecret, err := h.appService.Create(r.Context(), req, userID)
	if err != nil {
		writeError(w, err.Error(), http.StatusBadRequest)
		return
	}

	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(dto.AppWithSecretResponse{
		AppResponse: dto.AppResponse{
			ID:           app.ID,
			Name:         app.Name,
			ClientID:     app.ClientID,
			Active:       app.Active,
			URL:          app.URL,
			RedirectURIs: app.RedirectURIs,
			OwnerID:      app.OwnerID,
			CreatedAt:    app.CreatedAt,
		},
		ClientSecret: clientSecret,
	})
}

// PUT /api/admin/apps/:id
func (h *AdminHandler) UpdateApp(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserIDFromContext(r.Context())
	if !ok {
		writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	appID, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, "invalid app ID", http.StatusBadRequest)
		return
	}

	// Check ownership
	app, err := h.appService.GetByID(r.Context(), uint(appID))
	if err != nil {
		writeError(w, "app not found", http.StatusNotFound)
		return
	}

	user, _ := r.Context().Value("current_user").(*model.User)
	if app.OwnerID != nil && *app.OwnerID != userID {
		if user == nil || !user.IsGlobalAdmin() {
			writeError(w, "forbidden", http.StatusForbidden)
			return
		}
	}

	var req dto.UpdateAppRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	updatedApp, err := h.appService.Update(r.Context(), uint(appID), req)
	if err != nil {
		writeError(w, err.Error(), http.StatusBadRequest)
		return
	}

	json.NewEncoder(w).Encode(dto.AppResponse{
		ID:           updatedApp.ID,
		Name:         updatedApp.Name,
		ClientID:     updatedApp.ClientID,
		Active:       updatedApp.Active,
		URL:          updatedApp.URL,
		RedirectURIs: updatedApp.RedirectURIs,
		OwnerID:      updatedApp.OwnerID,
		CreatedAt:    updatedApp.CreatedAt,
	})
}

// DELETE /api/admin/apps/:id
func (h *AdminHandler) DeleteApp(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserIDFromContext(r.Context())
	if !ok {
		writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	appID, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, "invalid app ID", http.StatusBadRequest)
		return
	}

	// Check ownership
	app, err := h.appService.GetByID(r.Context(), uint(appID))
	if err != nil {
		writeError(w, "app not found", http.StatusNotFound)
		return
	}

	user, _ := r.Context().Value("current_user").(*model.User)
	if app.OwnerID != nil && *app.OwnerID != userID {
		if user == nil || !user.IsGlobalAdmin() {
			writeError(w, "forbidden", http.StatusForbidden)
			return
		}
	}

	if err := h.appService.Delete(r.Context(), uint(appID)); err != nil {
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

// POST /api/admin/apps/:id/rotate-secret
func (h *AdminHandler) RotateSecret(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserIDFromContext(r.Context())
	if !ok {
		writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	appID, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, "invalid app ID", http.StatusBadRequest)
		return
	}

	// Check ownership
	app, err := h.appService.GetByID(r.Context(), uint(appID))
	if err != nil {
		writeError(w, "app not found", http.StatusNotFound)
		return
	}

	user, _ := r.Context().Value("current_user").(*model.User)
	if app.OwnerID != nil && *app.OwnerID != userID {
		if user == nil || !user.IsGlobalAdmin() {
			writeError(w, "forbidden", http.StatusForbidden)
			return
		}
	}

	updatedApp, newSecret, err := h.appService.RotateSecret(r.Context(), uint(appID))
	if err != nil {
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Log the secret rotation
	if h.appActivityService != nil {
		h.appActivityService.LogEvent(r.Context(), uint(appID), &userID, model.EventTypeSecretRotated, model.EventCategoryAdmin, map[string]interface{}{
			"rotated_by": userID,
		}, middleware.GetClientIP(r), r.UserAgent(), true)
	}

	json.NewEncoder(w).Encode(dto.AppWithSecretResponse{
		AppResponse: dto.AppResponse{
			ID:           updatedApp.ID,
			Name:         updatedApp.Name,
			ClientID:     updatedApp.ClientID,
			Active:       updatedApp.Active,
			URL:          updatedApp.URL,
			RedirectURIs: updatedApp.RedirectURIs,
			OwnerID:      updatedApp.OwnerID,
			CreatedAt:    updatedApp.CreatedAt,
		},
		ClientSecret: newSecret,
	})
}

// GET /api/admin/stats
func (h *AdminHandler) GetStats(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserIDFromContext(r.Context())
	if !ok {
		writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Get apps owned by user
	apps, err := h.appService.GetByOwnerID(r.Context(), userID)
	if err != nil {
		apps = []model.App{}
	}

	// Get user count
	users, totalUsers, _ := h.userService.List(r.Context(), 1, 1)
	_ = users

	json.NewEncoder(w).Encode(map[string]interface{}{
		"total_users": totalUsers,
		"total_apps":  len(apps),
	})
}

// GET /api/admin/users
func (h *AdminHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	_, ok := middleware.GetUserIDFromContext(r.Context())
	if !ok {
		writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Check if user is global admin
	user, _ := r.Context().Value("current_user").(*model.User)
	if user == nil || !user.IsGlobalAdmin() {
		writeError(w, "forbidden: global admin required", http.StatusForbidden)
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

	users, totalCount, err := h.userService.List(r.Context(), page, pageSize)
	if err != nil {
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := make([]dto.UserResponse, len(users))
	for i, u := range users {
		response[i] = dto.UserResponse{
			ID:         u.ID,
			Email:      u.Email,
			Name:       u.Name,
			Role:       string(u.Role),
			IsVerified: u.IsVerified,
			CreatedAt:  u.CreatedAt,
		}
	}

	json.NewEncoder(w).Encode(dto.UserListResponse{
		Users:      response,
		TotalCount: totalCount,
		Page:       page,
		PageSize:   pageSize,
	})
}

// GET /api/admin/users/:id
func (h *AdminHandler) GetUser(w http.ResponseWriter, r *http.Request) {
	_, ok := middleware.GetUserIDFromContext(r.Context())
	if !ok {
		writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Check if user is global admin
	currentUser, _ := r.Context().Value("current_user").(*model.User)
	if currentUser == nil || !currentUser.IsGlobalAdmin() {
		writeError(w, "forbidden: global admin required", http.StatusForbidden)
		return
	}

	userID, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, "invalid user ID", http.StatusBadRequest)
		return
	}

	user, err := h.userService.GetByID(r.Context(), uint(userID))
	if err != nil {
		writeError(w, "user not found", http.StatusNotFound)
		return
	}

	json.NewEncoder(w).Encode(dto.UserResponse{
		ID:         user.ID,
		Email:      user.Email,
		Name:       user.Name,
		Role:       string(user.Role),
		IsVerified: user.IsVerified,
		CreatedAt:  user.CreatedAt,
	})
}

// POST /api/admin/users/:id/revoke-tokens
func (h *AdminHandler) RevokeUserTokens(w http.ResponseWriter, r *http.Request) {
	adminID, ok := middleware.GetUserIDFromContext(r.Context())
	if !ok {
		writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Check if user is global admin
	currentUser, _ := r.Context().Value("current_user").(*model.User)
	if currentUser == nil || !currentUser.IsGlobalAdmin() {
		writeError(w, "forbidden: global admin required", http.StatusForbidden)
		return
	}

	userID, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, "invalid user ID", http.StatusBadRequest)
		return
	}

	// Verify user exists
	user, err := h.userService.GetByID(r.Context(), uint(userID))
	if err != nil {
		writeError(w, "user not found", http.StatusNotFound)
		return
	}

	// Revoke tokens
	if err := h.userService.RevokeTokens(r.Context(), uint(userID)); err != nil {
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Log the action
	if h.adminLogService != nil {
		h.adminLogService.LogAction(r.Context(), adminID, nil, &user.ID, model.AdminActionRevokeTokens, map[string]interface{}{
			"target_email": user.Email,
		})
	}

	json.NewEncoder(w).Encode(map[string]string{
		"message": "tokens revoked successfully",
	})
}

// POST /api/admin/users/:id/unlock
func (h *AdminHandler) UnlockUser(w http.ResponseWriter, r *http.Request) {
	adminID, ok := middleware.GetUserIDFromContext(r.Context())
	if !ok {
		writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Check if user is global admin
	currentUser, _ := r.Context().Value("current_user").(*model.User)
	if currentUser == nil || !currentUser.IsGlobalAdmin() {
		writeError(w, "forbidden: global admin required", http.StatusForbidden)
		return
	}

	userID, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, "invalid user ID", http.StatusBadRequest)
		return
	}

	// Verify user exists
	user, err := h.userService.GetByID(r.Context(), uint(userID))
	if err != nil {
		writeError(w, "user not found", http.StatusNotFound)
		return
	}

	// Unlock user
	if err := h.userService.Unlock(r.Context(), uint(userID)); err != nil {
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Log the action
	if h.adminLogService != nil {
		h.adminLogService.LogAction(r.Context(), adminID, nil, &user.ID, model.AdminActionUnlockUser, map[string]interface{}{
			"target_email": user.Email,
		})
	}

	json.NewEncoder(w).Encode(map[string]string{
		"message": "user unlocked successfully",
	})
}

// GET /api/admin/activity
func (h *AdminHandler) GetActivity(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserIDFromContext(r.Context())
	if !ok {
		writeError(w, "unauthorized", http.StatusUnauthorized)
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

	logs, totalCount, err := h.adminLogService.GetByAdmin(r.Context(), userID, page, pageSize)
	if err != nil {
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := make([]dto.AdminLogResponse, len(logs))
	for i, log := range logs {
		response[i] = dto.AdminLogResponse{
			ID:           log.ID,
			AdminID:      log.AdminID,
			AppID:        log.AppID,
			TargetUserID: log.TargetUserID,
			Action:       string(log.Action),
			Details:      log.Details,
			CreatedAt:    log.CreatedAt,
		}
	}

	json.NewEncoder(w).Encode(dto.AdminLogListResponse{
		Logs:       response,
		TotalCount: totalCount,
		Page:       page,
		PageSize:   pageSize,
	})
}
