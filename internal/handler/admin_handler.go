package handler

import (
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/ovander/go-oauth2/internal/contextkeys"
	"github.com/ovander/go-oauth2/internal/dto"
	"github.com/ovander/go-oauth2/internal/middleware"
	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/service"
	"github.com/ovander/go-oauth2/pkg/logger"
)

type AdminHandler struct {
	appService           service.AppService
	userService          service.UserService
	userAppRoleService   service.UserAppRoleService
	adminLogService      service.AdminLogService
	appActivityService   service.AppActivityLogService
	emailService         service.EmailService
	securityAuditService service.SecurityAuditService
}

func NewAdminHandler(
	appService service.AppService,
	userService service.UserService,
	userAppRoleService service.UserAppRoleService,
	adminLogService service.AdminLogService,
	appActivityService service.AppActivityLogService,
	emailService service.EmailService,
	securityAuditService service.SecurityAuditService,
) *AdminHandler {
	return &AdminHandler{
		appService:           appService,
		userService:          userService,
		userAppRoleService:   userAppRoleService,
		adminLogService:      adminLogService,
		appActivityService:   appActivityService,
		emailService:         emailService,
		securityAuditService: securityAuditService,
	}
}

// logClientLifecycle records an OAuth client lifecycle change (#203) as an
// alertable security audit event. It is fire-and-forget and nil-safe: a missing
// audit service or a write failure never affects the admin response. IP, User-
// Agent, and correlation ID are filled from the request by the audit service.
func (h *AdminHandler) logClientLifecycle(r *http.Request, eventType model.SecurityEventType, actorID *uint, app *model.App, details map[string]interface{}) {
	if h.securityAuditService == nil {
		return
	}
	var appID *uint
	if app != nil {
		id := app.ID
		appID = &id
	}
	_ = h.securityAuditService.LogFromRequest(r.Context(), r, service.SecurityEvent{
		UserID:    actorID,
		AppID:     appID,
		EventType: eventType,
		Success:   true,
		Details:   details,
	})
}

// appChangeSet compares a client before and after an update and returns the
// security-relevant fields that changed. For the fields an attacker would
// target (redirect URIs, active flag, delegation grants, audiences) it also
// records old→new values so the SOC can reason about the change.
func appChangeSet(before, after *model.App) (changed []string, detail map[string]interface{}) {
	detail = map[string]interface{}{}
	mark := func(field string) { changed = append(changed, field) }
	markVal := func(field string, old, updated interface{}) {
		changed = append(changed, field)
		detail[field] = map[string]interface{}{"old": old, "new": updated}
	}
	if before.Name != after.Name {
		mark("name")
	}
	if !stringPtrEqual(before.URL, after.URL) {
		mark("url")
	}
	if !stringSliceEqual(before.RedirectURIs, after.RedirectURIs) {
		markVal("redirect_uris", []string(before.RedirectURIs), []string(after.RedirectURIs))
	}
	if before.Active != after.Active {
		markVal("active", before.Active, after.Active)
	}
	if before.RequireDPoP != after.RequireDPoP {
		markVal("require_dpop", before.RequireDPoP, after.RequireDPoP)
	}
	if before.AllowTokenExchange != after.AllowTokenExchange {
		markVal("allow_token_exchange", before.AllowTokenExchange, after.AllowTokenExchange)
	}
	if before.AllowImpersonation != after.AllowImpersonation {
		markVal("allow_impersonation", before.AllowImpersonation, after.AllowImpersonation)
	}
	if !stringSliceEqual(before.Audiences, after.Audiences) {
		markVal("audiences", []string(before.Audiences), []string(after.Audiences))
	}
	// The magic-link page receives single-use login tokens, so a change is as
	// sensitive as a redirect URI change.
	if !stringPtrEqual(before.MagicLinkURL, after.MagicLinkURL) {
		markVal("magic_link_url", derefString(before.MagicLinkURL), derefString(after.MagicLinkURL))
	}
	// A longer token lifetime widens the window a stolen token stays usable.
	if derefInt(before.AccessTokenTTLSeconds) != derefInt(after.AccessTokenTTLSeconds) {
		markVal("access_token_ttl_seconds", derefInt(before.AccessTokenTTLSeconds), derefInt(after.AccessTokenTTLSeconds))
	}
	return changed, detail
}

func stringPtrEqual(a, b *string) bool {
	if a == nil || b == nil {
		return a == b
	}
	return *a == *b
}

func stringSliceEqual(a, b model.StringArray) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// GET /api/admin/apps
// Superadmin can see ALL apps in the system
func (h *AdminHandler) ListApps(w http.ResponseWriter, r *http.Request) {
	_, ok := middleware.GetUserIDFromContext(r.Context())
	if !ok {
		writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Superadmin sees all apps
	apps, err := h.appService.List(r.Context())
	if err != nil {
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := make([]dto.AppResponse, len(apps))
	for i, app := range apps {
		response[i] = appToResponse(app)
	}

	writeJSON(w, dto.AppListResponse{
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
	user, _ := r.Context().Value(contextkeys.CurrentUserKey).(*model.User)
	if app.OwnerID != nil && *app.OwnerID != userID {
		if user == nil || !user.IsGlobalAdmin() {
			writeError(w, "forbidden", http.StatusForbidden)
			return
		}
	}

	writeJSON(w, appToResponse(*app))
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

	// Send credentials email to admin (only for confidential clients that
	// actually have a secret — public clients have no secret to send).
	if clientSecret != "" && h.emailService != nil {
		admin, adminErr := h.userService.GetByID(r.Context(), userID)
		if adminErr == nil && admin != nil {
			if err := h.emailService.SendAppCredentialsEmail(admin.Email, admin.Name, app.Name, app.ClientID, clientSecret); err != nil {
				logger.Logger.WithFields(logger.Fields{
					"email": admin.Email,
					"app":   app.Name,
					"error": err.Error(),
				}).Warn("📧 Failed to send app credentials email")
			}
		}
	} else if clientSecret == "" {
		logger.Logger.WithFields(logger.Fields{
			"app": app.Name,
		}).Info("📧 Public client — no credentials email sent")
	}

	// #203: a new client is new attack surface — surface it to the SOC as an
	// alertable security event, not just to the app owner.
	h.logClientLifecycle(r, model.SecurityEventClientCreated, &userID, app, map[string]interface{}{
		"client_id":     app.ClientID,
		"name":          app.Name,
		"confidential":  clientSecret != "",
		"redirect_uris": []string(app.RedirectURIs),
	})

	w.WriteHeader(http.StatusCreated)
	//nolint:gosec // G117 intentional: one-time plaintext delivery of the newly-generated client_secret to the registering party
	writeJSON(w, dto.AppWithSecretResponse{
		AppResponse:  appToResponse(*app),
		ClientSecret: clientSecret, // empty string for public clients
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

	user, _ := r.Context().Value(contextkeys.CurrentUserKey).(*model.User)
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

	// Snapshot the pre-update state so we can record exactly what changed.
	before := *app

	updatedApp, err := h.appService.Update(r.Context(), uint(appID), req)
	if err != nil {
		writeError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// #203: record which security-relevant fields changed (redirect URIs, active
	// flag, delegation grants are classic abuse targets) as an alertable event.
	changed, changeDetail := appChangeSet(&before, updatedApp)
	if len(changed) > 0 {
		changeDetail["client_id"] = updatedApp.ClientID
		changeDetail["name"] = updatedApp.Name
		changeDetail["changed"] = changed
		h.logClientLifecycle(r, model.SecurityEventClientUpdated, &userID, updatedApp, changeDetail)
	}

	writeJSON(w, appToResponse(*updatedApp))
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

	user, _ := r.Context().Value(contextkeys.CurrentUserKey).(*model.User)
	if app.OwnerID != nil && *app.OwnerID != userID {
		if user == nil || !user.IsGlobalAdmin() {
			writeError(w, "forbidden", http.StatusForbidden)
			return
		}
	}

	if err := h.appService.Delete(r.Context(), uint(appID)); err != nil {
		logger.Logger.WithFields(logger.Fields{
			"app_id": appID,
			"error":  err.Error(),
		}).Error("❌ DeleteApp: failed to delete app")
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// #203: client deletion is destructive (cascades tokens/roles) — emit a
	// warning-severity alertable event so the SOC sees it.
	h.logClientLifecycle(r, model.SecurityEventClientDeleted, &userID, app, map[string]interface{}{
		"client_id": app.ClientID,
		"name":      app.Name,
	})

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

	user, _ := r.Context().Value(contextkeys.CurrentUserKey).(*model.User)
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

	// Log the secret rotation to the app-activity (admin) trail …
	if h.appActivityService != nil {
		_ = h.appActivityService.LogEvent(r.Context(), uint(appID), &userID, model.EventTypeSecretRotated, model.EventCategoryAdmin, map[string]interface{}{
			"rotated_by": userID,
		}, middleware.GetClientIP(r), r.UserAgent(), true)
	}

	// … and promote it to an alertable security event (#203): a rotated client
	// secret invalidates the old credential and is worth SOC visibility.
	h.logClientLifecycle(r, model.SecurityEventClientSecretRotated, &userID, updatedApp, map[string]interface{}{
		"client_id":  updatedApp.ClientID,
		"name":       updatedApp.Name,
		"rotated_by": userID,
	})

	// Send new credentials email to admin
	if h.emailService != nil {
		admin, adminErr := h.userService.GetByID(r.Context(), userID)
		if adminErr == nil && admin != nil {
			if err := h.emailService.SendAppCredentialsEmail(admin.Email, admin.Name, updatedApp.Name, updatedApp.ClientID, newSecret); err != nil {
				logger.Logger.WithFields(logger.Fields{
					"email": admin.Email,
					"app":   updatedApp.Name,
					"error": err.Error(),
				}).Warn("📧 Failed to send rotated credentials email")
			}
		}
	} else {
		logger.Logger.WithFields(logger.Fields{
			"app": updatedApp.Name,
		}).Debug("📧 Email service not configured, skipping rotated credentials email")
	}

	//nolint:gosec // G117 intentional: one-time delivery of the rotated client_secret to the admin caller
	writeJSON(w, dto.AppWithSecretResponse{
		AppResponse:  appToResponse(*updatedApp),
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

	writeJSON(w, map[string]interface{}{
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
	user, _ := r.Context().Value(contextkeys.CurrentUserKey).(*model.User)
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

	writeJSON(w, dto.UserListResponse{
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
	currentUser, _ := r.Context().Value(contextkeys.CurrentUserKey).(*model.User)
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

	writeJSON(w, dto.UserResponse{
		ID:         user.ID,
		Email:      user.Email,
		Name:       user.Name,
		Role:       string(user.Role),
		IsVerified: user.IsVerified,
		Attributes: user.Attributes,
		CreatedAt:  user.CreatedAt,
	})
}

// GET /api/admin/users/:id/apps
// Returns all apps this user belongs to with their roles
func (h *AdminHandler) GetUserApps(w http.ResponseWriter, r *http.Request) {
	_, ok := middleware.GetUserIDFromContext(r.Context())
	if !ok {
		writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	// Check if user is global admin
	currentUser, _ := r.Context().Value(contextkeys.CurrentUserKey).(*model.User)
	if currentUser == nil || !currentUser.IsGlobalAdmin() {
		writeError(w, "forbidden: global admin required", http.StatusForbidden)
		return
	}

	userID, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, "invalid user ID", http.StatusBadRequest)
		return
	}

	// Get user info
	user, err := h.userService.GetByID(r.Context(), uint(userID))
	if err != nil {
		writeError(w, "user not found", http.StatusNotFound)
		return
	}

	// Get user's app memberships
	roles, err := h.userAppRoleService.GetUserRoles(r.Context(), uint(userID))
	if err != nil {
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	memberships := make([]dto.UserAppMembershipResponse, 0, len(roles))
	for _, role := range roles {
		if role.App != nil {
			memberships = append(memberships, dto.UserAppMembershipResponse{
				AppID:     role.AppID,
				AppName:   role.App.Name,
				ClientID:  role.App.ClientID,
				Role:      string(role.Role),
				CreatedAt: role.CreatedAt,
			})
		}
	}

	writeJSON(w, dto.UserAppMembershipsResponse{
		UserID:      user.ID,
		Email:       user.Email,
		Name:        user.Name,
		Memberships: memberships,
		TotalCount:  len(memberships),
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
	currentUser, _ := r.Context().Value(contextkeys.CurrentUserKey).(*model.User)
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
		_ = h.adminLogService.LogAction(r.Context(), adminID, nil, &user.ID, model.AdminActionRevokeTokens, map[string]interface{}{
			"target_email": user.Email,
		})
	}

	writeJSON(w, map[string]string{
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
	currentUser, _ := r.Context().Value(contextkeys.CurrentUserKey).(*model.User)
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
		_ = h.adminLogService.LogAction(r.Context(), adminID, nil, &user.ID, model.AdminActionUnlockUser, map[string]interface{}{
			"target_email": user.Email,
		})
	}

	writeJSON(w, map[string]string{
		"message": "user unlocked successfully",
	})
}

// PUT /api/admin/users/:id/attributes
//
// A2: replaces a user's free-form attribute set. Attributes are inert on their
// own — they only reach a token when a client declares a claim mapping naming
// `user.attributes.<key>` — but because they can end up in tokens, this is
// global-admin only and always audited. The body replaces the whole set, so an
// empty object clears it.
func (h *AdminHandler) UpdateUserAttributes(w http.ResponseWriter, r *http.Request) {
	adminID, ok := middleware.GetUserIDFromContext(r.Context())
	if !ok {
		writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	currentUser, _ := r.Context().Value(contextkeys.CurrentUserKey).(*model.User)
	if currentUser == nil || !currentUser.IsGlobalAdmin() {
		writeError(w, "forbidden: global admin required", http.StatusForbidden)
		return
	}

	userID, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, "invalid user ID", http.StatusBadRequest)
		return
	}

	var body struct {
		Attributes model.JSONMap `json:"attributes"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeError(w, "invalid request body", http.StatusBadRequest)
		return
	}
	if body.Attributes == nil {
		body.Attributes = model.JSONMap{}
	}

	user, err := h.userService.Update(r.Context(), uint(userID), dto.UpdateUserRequest{Attributes: &body.Attributes})
	if err != nil {
		switch {
		case errors.Is(err, service.ErrUserNotFound):
			writeError(w, "user not found", http.StatusNotFound)
		case errors.Is(err, service.ErrInvalidUserAttributes):
			writeError(w, err.Error(), http.StatusBadRequest)
		default:
			writeError(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	if h.adminLogService != nil {
		// The names are audited, not the values: an attribute may hold
		// business-sensitive data and the audit log is widely readable.
		names := make([]string, 0, len(user.Attributes))
		for name := range user.Attributes {
			names = append(names, name)
		}
		sort.Strings(names)
		_ = h.adminLogService.LogAction(r.Context(), adminID, nil, &user.ID, model.AdminActionUpdateUserAttributes, map[string]interface{}{
			"target_email": user.Email,
			"attributes":   names,
		})
	}

	writeJSON(w, dto.UserResponse{
		ID:         user.ID,
		Email:      user.Email,
		Name:       user.Name,
		Role:       string(user.Role),
		IsVerified: user.IsVerified,
		Attributes: user.Attributes,
		CreatedAt:  user.CreatedAt,
	})
}

// DELETE /api/admin/users/:id
func (h *AdminHandler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	adminID, ok := middleware.GetUserIDFromContext(r.Context())
	if !ok {
		writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	currentUser, _ := r.Context().Value(contextkeys.CurrentUserKey).(*model.User)
	if currentUser == nil || !currentUser.IsGlobalAdmin() {
		writeError(w, "forbidden: global admin required", http.StatusForbidden)
		return
	}

	userID, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, "invalid user ID", http.StatusBadRequest)
		return
	}

	if uint(userID) == adminID {
		writeError(w, "cannot delete your own account", http.StatusBadRequest)
		return
	}

	user, err := h.userService.GetByID(r.Context(), uint(userID))
	if err != nil {
		writeError(w, "user not found", http.StatusNotFound)
		return
	}

	// Superadmins must be removed via the superadmin management endpoint
	// (/api/admin/superadmins/:id) which enforces the last-superadmin guard.
	if user.Role == model.UserRoleSuperadmin {
		writeError(w, "cannot delete a superadmin via this endpoint; use DELETE /api/admin/superadmins/:id", http.StatusForbidden)
		return
	}

	if err := h.userService.Delete(r.Context(), uint(userID)); err != nil {
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	if h.adminLogService != nil {
		_ = h.adminLogService.LogAction(r.Context(), adminID, nil, &user.ID, model.AdminActionDeleteUser, map[string]interface{}{
			"target_email": user.Email,
			"role":         string(user.Role),
		})
	}

	w.WriteHeader(http.StatusNoContent)
}

// POST /api/admin/users/:id/block
func (h *AdminHandler) BlockUser(w http.ResponseWriter, r *http.Request) {
	adminID, ok := middleware.GetUserIDFromContext(r.Context())
	if !ok {
		writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	currentUser, _ := r.Context().Value(contextkeys.CurrentUserKey).(*model.User)
	if currentUser == nil || !currentUser.IsGlobalAdmin() {
		writeError(w, "forbidden: global admin required", http.StatusForbidden)
		return
	}

	userID, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, "invalid user ID", http.StatusBadRequest)
		return
	}

	if uint(userID) == adminID {
		writeError(w, "cannot block your own account", http.StatusBadRequest)
		return
	}

	user, err := h.userService.GetByID(r.Context(), uint(userID))
	if err != nil {
		writeError(w, "user not found", http.StatusNotFound)
		return
	}

	if err := h.userService.Block(r.Context(), uint(userID)); err != nil {
		writeError(w, err.Error(), http.StatusBadRequest)
		return
	}

	if h.adminLogService != nil {
		_ = h.adminLogService.LogAction(r.Context(), adminID, nil, &user.ID, model.AdminActionBlockUser, map[string]interface{}{
			"target_email": user.Email,
		})
	}

	writeJSON(w, map[string]string{
		"message": "user blocked successfully",
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

	writeJSON(w, dto.AdminLogListResponse{
		Logs:       response,
		TotalCount: totalCount,
		Page:       page,
		PageSize:   pageSize,
	})
}

// ==========================================
// Superadmin Management
// ==========================================

// GET /api/admin/superadmins
func (h *AdminHandler) ListSuperadmins(w http.ResponseWriter, r *http.Request) {
	_, ok := middleware.GetUserIDFromContext(r.Context())
	if !ok {
		writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	superadmins, err := h.userService.ListSuperadmins(r.Context())
	if err != nil {
		writeError(w, err.Error(), http.StatusInternalServerError)
		return
	}

	response := make([]dto.SuperadminResponse, len(superadmins))
	for i, u := range superadmins {
		response[i] = dto.SuperadminResponse{
			ID:           u.ID,
			Email:        u.Email,
			Name:         u.Name,
			IsVerified:   u.IsVerified,
			LastLogin:    u.LastLogin,
			FailedLogins: u.FailedLoginAttempts,
			LockedUntil:  u.LockedUntil,
			CreatedAt:    u.CreatedAt,
			UpdatedAt:    u.UpdatedAt,
		}
	}

	writeJSON(w, dto.SuperadminListResponse{
		Superadmins: response,
		TotalCount:  int64(len(superadmins)),
	})
}

// GET /api/admin/superadmins/:id
func (h *AdminHandler) GetSuperadmin(w http.ResponseWriter, r *http.Request) {
	_, ok := middleware.GetUserIDFromContext(r.Context())
	if !ok {
		writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	userID, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, "invalid superadmin ID", http.StatusBadRequest)
		return
	}

	user, err := h.userService.GetByID(r.Context(), uint(userID))
	if err != nil {
		writeError(w, "superadmin not found", http.StatusNotFound)
		return
	}

	// Verify the user is a superadmin
	if user.Role != model.UserRoleSuperadmin {
		writeError(w, "user is not a superadmin", http.StatusNotFound)
		return
	}

	writeJSON(w, dto.SuperadminResponse{
		ID:           user.ID,
		Email:        user.Email,
		Name:         user.Name,
		IsVerified:   user.IsVerified,
		LastLogin:    user.LastLogin,
		FailedLogins: user.FailedLoginAttempts,
		LockedUntil:  user.LockedUntil,
		CreatedAt:    user.CreatedAt,
		UpdatedAt:    user.UpdatedAt,
	})
}

// POST /api/admin/superadmins
func (h *AdminHandler) CreateSuperadmin(w http.ResponseWriter, r *http.Request) {
	adminID, ok := middleware.GetUserIDFromContext(r.Context())
	if !ok {
		writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req dto.CreateSuperadminRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Email == "" || req.Name == "" || req.Password == "" {
		writeError(w, "email, name, and password are required", http.StatusBadRequest)
		return
	}

	user, err := h.userService.CreateSuperadmin(r.Context(), req)
	if err != nil {
		if err == service.ErrEmailAlreadyExists {
			writeError(w, err.Error(), http.StatusConflict)
			return
		}
		writeError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Log the action
	if h.adminLogService != nil {
		_ = h.adminLogService.LogAction(r.Context(), adminID, nil, &user.ID, model.AdminActionCreateSuperadmin, map[string]interface{}{
			"email": req.Email,
		})
	}

	w.WriteHeader(http.StatusCreated)
	writeJSON(w, dto.SuperadminResponse{
		ID:           user.ID,
		Email:        user.Email,
		Name:         user.Name,
		IsVerified:   user.IsVerified,
		LastLogin:    user.LastLogin,
		FailedLogins: user.FailedLoginAttempts,
		LockedUntil:  user.LockedUntil,
		CreatedAt:    user.CreatedAt,
		UpdatedAt:    user.UpdatedAt,
	})
}

// PUT /api/admin/superadmins/:id
func (h *AdminHandler) UpdateSuperadmin(w http.ResponseWriter, r *http.Request) {
	adminID, ok := middleware.GetUserIDFromContext(r.Context())
	if !ok {
		writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	userID, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, "invalid superadmin ID", http.StatusBadRequest)
		return
	}

	var req dto.UpdateSuperadminRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	user, err := h.userService.UpdateSuperadmin(r.Context(), uint(userID), req)
	if err != nil {
		if err == service.ErrUserNotFound {
			writeError(w, "superadmin not found", http.StatusNotFound)
			return
		}
		if err == service.ErrNotAdmin {
			writeError(w, "user is not a superadmin", http.StatusBadRequest)
			return
		}
		if err == service.ErrEmailAlreadyExists {
			writeError(w, err.Error(), http.StatusConflict)
			return
		}
		writeError(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Log the action
	if h.adminLogService != nil {
		_ = h.adminLogService.LogAction(r.Context(), adminID, nil, &user.ID, model.AdminActionUpdateSuperadmin, map[string]interface{}{
			"email": user.Email,
		})
	}

	writeJSON(w, dto.SuperadminResponse{
		ID:           user.ID,
		Email:        user.Email,
		Name:         user.Name,
		IsVerified:   user.IsVerified,
		LastLogin:    user.LastLogin,
		FailedLogins: user.FailedLoginAttempts,
		LockedUntil:  user.LockedUntil,
		CreatedAt:    user.CreatedAt,
		UpdatedAt:    user.UpdatedAt,
	})
}

// DELETE /api/admin/superadmins/:id
func (h *AdminHandler) DeleteSuperadmin(w http.ResponseWriter, r *http.Request) {
	adminID, ok := middleware.GetUserIDFromContext(r.Context())
	if !ok {
		writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	userID, err := strconv.ParseUint(chi.URLParam(r, "id"), 10, 64)
	if err != nil {
		writeError(w, "invalid superadmin ID", http.StatusBadRequest)
		return
	}

	// Get user info for logging before deletion
	user, _ := h.userService.GetByID(r.Context(), uint(userID))

	err = h.userService.DeleteSuperadmin(r.Context(), uint(userID), adminID)
	if err != nil {
		switch err {
		case service.ErrUserNotFound:
			writeError(w, "superadmin not found", http.StatusNotFound)
		case service.ErrNotAdmin:
			writeError(w, "user is not a superadmin", http.StatusBadRequest)
		case service.ErrCannotDeleteSelf:
			writeError(w, err.Error(), http.StatusForbidden)
		case service.ErrCannotDeleteLastSuperadmin:
			writeError(w, err.Error(), http.StatusForbidden)
		default:
			writeError(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	// Log the action
	if h.adminLogService != nil && user != nil {
		targetID := uint(userID)
		_ = h.adminLogService.LogAction(r.Context(), adminID, nil, &targetID, model.AdminActionDeleteSuperadmin, map[string]interface{}{
			"email": user.Email,
		})
	}

	w.WriteHeader(http.StatusNoContent)
}

// appToResponse converts a model.App to a dto.AppResponse, including all
// fields added since the initial release (is_public, require_pkce, …).
// Centralising this conversion prevents fields being silently omitted when
// new columns are added to the model.
func appToResponse(app model.App) dto.AppResponse {
	return dto.AppResponse{
		ID:                 app.ID,
		Name:               app.Name,
		ClientID:           app.ClientID,
		Active:             app.Active,
		IsPublic:           app.IsPublic,
		RequirePKCE:        app.RequirePKCE,
		RequireDPoP:        app.RequireDPoP,
		AllowTokenExchange: app.AllowTokenExchange,
		AllowImpersonation: app.AllowImpersonation,
		Audiences:          app.Audiences,
		AllowedScopes:      app.AllowedScopes,
		ClaimMappings:      app.ClaimMappings,
		URL:                app.URL,
		RedirectURIs:       app.RedirectURIs,
		MagicLinkURL:       app.MagicLinkURL,
		OwnerID:            app.OwnerID,
		CreatedAt:          app.CreatedAt,

		AccessTokenTTLSeconds: app.AccessTokenTTLSeconds,
	}
}

// derefInt returns *p, or 0 for nil.
func derefInt(p *int) int {
	if p == nil {
		return 0
	}
	return *p
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
