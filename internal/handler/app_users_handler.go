package handler

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	"github.com/ovander/go-oauth2/internal/dto"
	"github.com/ovander/go-oauth2/internal/middleware"
	"github.com/ovander/go-oauth2/internal/model"
	"github.com/ovander/go-oauth2/internal/service"
	"github.com/ovander/go-oauth2/internal/shared/auth"
	"github.com/ovander/go-oauth2/pkg/logger"
)

type AppUsersHandler struct {
	userService        service.UserService
	userAppRoleService service.UserAppRoleService
	appService         service.AppService
	adminLogService    service.AdminLogService
	emailService       service.EmailService
	tokenService       *auth.TokenService
	baseURL            string
}

func NewAppUsersHandler(
	userService service.UserService,
	userAppRoleService service.UserAppRoleService,
	appService service.AppService,
	adminLogService service.AdminLogService,
	emailService service.EmailService,
	tokenService *auth.TokenService,
	baseURL string,
) *AppUsersHandler {
	return &AppUsersHandler{
		userService:        userService,
		userAppRoleService: userAppRoleService,
		appService:         appService,
		adminLogService:    adminLogService,
		emailService:       emailService,
		tokenService:       tokenService,
		baseURL:            baseURL,
	}
}

// GET /api/apps/:app_id/users
func (h *AppUsersHandler) ListUsers(w http.ResponseWriter, r *http.Request) {
	appID, err := getAppIDFromURL(r)
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
	search := r.URL.Query().Get("search")

	roles, totalCount, err := h.userAppRoleService.GetAppUsers(r.Context(), appID, page, pageSize, search)
	if err != nil {
		// P2-2: static messages only; repository/driver detail is logged, not
		// forwarded to the (app-admin) caller.
		logger.Warnf("app users: list for app %d: %v", appID, err)
		writeError(w, "could not list app users", http.StatusInternalServerError)
		return
	}

	users := make([]dto.AppUserResponse, len(roles))
	for i, role := range roles {
		if role.User != nil {
			users[i] = dto.AppUserResponse{
				ID:         role.User.ID,
				Email:      role.User.Email,
				Name:       role.User.Name,
				Role:       string(role.Role),
				IsVerified: role.User.IsVerified,
				InviteSent: role.InviteSent,
				LastLogin:  role.User.LastLogin,
				CreatedAt:  role.CreatedAt,
			}
		}
	}

	writeJSON(w, dto.AppUserListResponse{
		Users:      users,
		TotalCount: totalCount,
		Page:       page,
		PageSize:   pageSize,
	})
}

// GET /api/apps/:app_id/users/:user_id
func (h *AppUsersHandler) GetUser(w http.ResponseWriter, r *http.Request) {
	appID, err := getAppIDFromURL(r)
	if err != nil {
		writeError(w, "invalid app ID", http.StatusBadRequest)
		return
	}

	userID, err := getUserIDFromURL(r)
	if err != nil {
		writeError(w, "invalid user ID", http.StatusBadRequest)
		return
	}

	user, err := h.userService.GetByID(r.Context(), userID)
	if err != nil {
		writeError(w, "user not found", http.StatusNotFound)
		return
	}

	role, err := h.userAppRoleService.GetUserRoleForApp(r.Context(), userID, appID)
	if err != nil {
		writeError(w, "user not in app", http.StatusNotFound)
		return
	}

	writeJSON(w, dto.AppUserResponse{
		ID:         user.ID,
		Email:      user.Email,
		Name:       user.Name,
		Role:       string(role.Role),
		IsVerified: user.IsVerified,
		InviteSent: role.InviteSent,
		LastLogin:  user.LastLogin,
		CreatedAt:  role.CreatedAt,
	})
}

// POST /api/apps/:app_id/users
func (h *AppUsersHandler) CreateUser(w http.ResponseWriter, r *http.Request) {
	appID, err := getAppIDFromURL(r)
	if err != nil {
		writeError(w, "invalid app ID", http.StatusBadRequest)
		return
	}

	// Resolve caller identity: human admin (user JWT) or service account (client_credentials).
	// Service accounts have no user ID — adminID=0 is the sentinel used in audit logs.
	adminID, ok := middleware.GetUserIDFromContext(r.Context())
	if !ok {
		if _, isServiceAccount := middleware.GetServiceAccountAppFromContext(r.Context()); !isServiceAccount {
			writeError(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		adminID = 0 // service account — logged as system actor
	}

	var req dto.AddAppUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Email == "" || req.Role == "" {
		writeError(w, "email and role are required", http.StatusBadRequest)
		return
	}

	// Validate role
	if !model.IsValidAppRole(req.Role) {
		writeError(w, "invalid role: must be one of admin, manager, editor, viewer, user", http.StatusBadRequest)
		return
	}

	// Check if user exists
	user, err := h.userService.GetByEmail(r.Context(), req.Email)
	isNewUser := err != nil
	if !isNewUser && user.Role == model.UserRoleSuperadmin {
		// Superadmins have global access to all apps by definition — they must
		// never appear in per-app user lists or be granted explicit app roles.
		writeError(w, "superadmins cannot be assigned to a specific app", http.StatusForbidden)
		return
	}
	if isNewUser {
		// Create new user
		name := req.Name
		if name == "" {
			name = req.Email
		}
		user, err = h.userService.Create(r.Context(), dto.CreateUserRequest{
			Email:    req.Email,
			Name:     name,
			Password: generateTempPassword(),
		})
		if err != nil {
			logger.Warnf("app users: create user for app %d: %v", appID, err)
			writeError(w, "could not create user", http.StatusBadRequest)
			return
		}
	}

	// Assign role
	role, err := h.userAppRoleService.AssignRole(r.Context(), user.ID, appID, model.AppRole(req.Role))
	if err != nil {
		if errors.Is(err, service.ErrRoleAlreadyExists) {
			writeError(w, "user already has a role in this app", http.StatusConflict)
			return
		}
		logger.Warnf("app users: assign role for user %d app %d: %v", user.ID, appID, err)
		writeError(w, "could not assign role", http.StatusInternalServerError)
		return
	}

	// Generate invite token
	inviteToken, err := h.tokenService.GenerateInviteToken(user.Email, appID, req.Role, adminID)
	if err != nil {
		logger.Warnf("app users: generate invite token for user %d app %d: %v", user.ID, appID, err)
		writeError(w, "could not generate invite token", http.StatusInternalServerError)
		return
	}

	// Get app name for email
	var appName string
	if app, err := h.appService.GetByID(r.Context(), appID); err == nil {
		appName = app.Name
	} else {
		appName = "the application"
	}

	// Send invitation email
	emailSent := false
	var emailError string
	if h.emailService != nil {
		inviteURL := h.tokenService.GetIssuer() + "/auth/invite?token=" + inviteToken
		if err := h.emailService.SendInviteEmail(user.Email, appName, inviteURL); err != nil {
			// Log error but don't fail the request — the invite token is still valid and can be resent
			logger.Logger.WithFields(logger.Fields{
				"email": user.Email,
				"app":   appName,
				"error": err.Error(),
			}).Warn("📧 Failed to send invite email, but invite token is valid")
			// P2-2: the SMTP/driver error text stays in the log.
			emailError = "failed to send invite email"
		} else {
			emailSent = true
		}
	} else {
		logger.Logger.WithFields(logger.Fields{
			"email": user.Email,
			"app":   appName,
		}).Debug("📧 Email service not configured, skipping invite email")
		emailError = "email service not configured"
	}

	// Mark invite as sent only when the email was actually delivered
	if emailSent {
		_ = h.userAppRoleService.SetInviteSent(r.Context(), user.ID, appID)
	}

	// Log admin action
	if h.adminLogService != nil {
		_ = h.adminLogService.LogAction(r.Context(), adminID, &appID, &user.ID, model.AdminActionAddUser, map[string]interface{}{
			"email":       req.Email,
			"role":        req.Role,
			"is_new_user": isNewUser,
			"email_sent":  emailSent,
		})
	}

	resp := map[string]interface{}{
		"user_id":      user.ID,
		"invite_token": inviteToken,
		"role":         role.Role,
		"email_sent":   emailSent,
	}
	if emailError != "" {
		resp["email_error"] = emailError
	}
	w.WriteHeader(http.StatusCreated)
	writeJSON(w, resp)
}

// PUT /api/apps/:app_id/users/:user_id
func (h *AppUsersHandler) UpdateUserRole(w http.ResponseWriter, r *http.Request) {
	appID, err := getAppIDFromURL(r)
	if err != nil {
		writeError(w, "invalid app ID", http.StatusBadRequest)
		return
	}

	userID, err := getUserIDFromURL(r)
	if err != nil {
		writeError(w, "invalid user ID", http.StatusBadRequest)
		return
	}

	adminID, _ := middleware.GetUserIDFromContext(r.Context())

	// Get old role for logging
	oldRole, _ := h.userAppRoleService.GetUserRoleForApp(r.Context(), userID, appID)

	var req dto.UpdateAppUserRoleRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Role == "" {
		writeError(w, "role is required", http.StatusBadRequest)
		return
	}

	// Validate role
	if !model.IsValidAppRole(req.Role) {
		writeError(w, "invalid role: must be one of admin, manager, editor, viewer, user", http.StatusBadRequest)
		return
	}

	role, err := h.userAppRoleService.UpdateRole(r.Context(), userID, appID, model.AppRole(req.Role))
	if err != nil {
		if errors.Is(err, service.ErrRoleNotFound) {
			writeError(w, "user not in app", http.StatusNotFound)
			return
		}
		logger.Warnf("app users: update role for user %d app %d: %v", userID, appID, err)
		writeError(w, "could not update role", http.StatusInternalServerError)
		return
	}

	// Log admin action
	if h.adminLogService != nil {
		oldRoleStr := ""
		if oldRole != nil {
			oldRoleStr = string(oldRole.Role)
		}
		_ = h.adminLogService.LogAction(r.Context(), adminID, &appID, &userID, model.AdminActionUpdateRole, map[string]interface{}{
			"old_role": oldRoleStr,
			"new_role": req.Role,
		})
	}

	writeJSON(w, map[string]interface{}{
		"role": role.Role,
	})
}

// DELETE /api/apps/:app_id/users/:user_id
func (h *AppUsersHandler) RemoveUser(w http.ResponseWriter, r *http.Request) {
	appID, err := getAppIDFromURL(r)
	if err != nil {
		writeError(w, "invalid app ID", http.StatusBadRequest)
		return
	}

	userID, err := getUserIDFromURL(r)
	if err != nil {
		writeError(w, "invalid user ID", http.StatusBadRequest)
		return
	}

	// Check not removing self
	currentUserID, _ := middleware.GetUserIDFromContext(r.Context())
	if currentUserID == userID {
		writeError(w, "cannot remove yourself", http.StatusBadRequest)
		return
	}

	// Get user info for logging
	user, _ := h.userService.GetByID(r.Context(), userID)

	if err := h.userAppRoleService.RemoveRole(r.Context(), userID, appID); err != nil {
		if errors.Is(err, service.ErrRoleNotFound) {
			writeError(w, "user not in app", http.StatusNotFound)
			return
		}
		logger.Warnf("app users: remove role for user %d app %d: %v", userID, appID, err)
		writeError(w, "could not remove user from app", http.StatusInternalServerError)
		return
	}

	// Log admin action
	if h.adminLogService != nil {
		details := map[string]interface{}{}
		if user != nil {
			details["email"] = user.Email
		}
		_ = h.adminLogService.LogAction(r.Context(), currentUserID, &appID, &userID, model.AdminActionRemoveUser, details)
	}

	w.WriteHeader(http.StatusNoContent)
}

// POST /api/apps/:app_id/users/:user_id/resend-verification
func (h *AppUsersHandler) ResendVerification(w http.ResponseWriter, r *http.Request) {
	appID, err := getAppIDFromURL(r)
	if err != nil {
		writeError(w, "invalid app ID", http.StatusBadRequest)
		return
	}

	userID, err := getUserIDFromURL(r)
	if err != nil {
		writeError(w, "invalid user ID", http.StatusBadRequest)
		return
	}

	adminID, _ := middleware.GetUserIDFromContext(r.Context())

	user, err := h.userService.GetByID(r.Context(), userID)
	if err != nil {
		writeError(w, "user not found", http.StatusNotFound)
		return
	}

	// P3-7: an app-admin may only trigger mail for members of their own app.
	// Without this check any user ID on the platform could be targeted.
	if !h.requireAppMember(w, r, userID, appID) {
		return
	}

	// Get app details for context
	app, err := h.appService.GetByID(r.Context(), appID)
	if err != nil {
		writeError(w, "app not found", http.StatusNotFound)
		return
	}

	// Generate new verification token with app context
	appCtx := &auth.AppContext{
		AppID:   app.ID,
		AppName: app.Name,
	}
	if len(app.RedirectURIs) > 0 {
		appCtx.RedirectURI = app.RedirectURIs[0]
	}

	token, err := h.tokenService.GenerateEmailVerificationToken(user.Email, user.ID, appCtx)
	if err != nil {
		logger.Warnf("app users: verification token for user %d app %d: %v", userID, appID, err)
		writeError(w, "could not generate verification token", http.StatusInternalServerError)
		return
	}

	// Log admin action
	if h.adminLogService != nil {
		_ = h.adminLogService.LogAction(r.Context(), adminID, &appID, &userID, model.AdminActionResendVerification, map[string]interface{}{
			"email": user.Email,
		})
	}

	// Send verification email with app name
	if h.emailService != nil {
		verifyURL := h.baseURL + "/auth/verify-email?token=" + token
		if err := h.emailService.SendVerificationEmail(user.Email, user.Name, app.Name, verifyURL); err != nil {
			logger.Warnf("app users: send verification email for user %d app %d: %v", userID, appID, err)
			writeError(w, "failed to send verification email", http.StatusInternalServerError)
			return
		}
	}

	writeJSON(w, dto.MessageResponse{Message: "Verification email sent"})
}

// POST /api/apps/:app_id/users/:user_id/reset-password
func (h *AppUsersHandler) ForcePasswordReset(w http.ResponseWriter, r *http.Request) {
	appID, err := getAppIDFromURL(r)
	if err != nil {
		writeError(w, "invalid app ID", http.StatusBadRequest)
		return
	}

	userID, err := getUserIDFromURL(r)
	if err != nil {
		writeError(w, "invalid user ID", http.StatusBadRequest)
		return
	}

	adminID, _ := middleware.GetUserIDFromContext(r.Context())

	user, err := h.userService.GetByID(r.Context(), userID)
	if err != nil {
		writeError(w, "user not found", http.StatusNotFound)
		return
	}

	// P3-7: same membership gate as ResendVerification.
	if !h.requireAppMember(w, r, userID, appID) {
		return
	}

	// Get app details for context
	app, err := h.appService.GetByID(r.Context(), appID)
	if err != nil {
		writeError(w, "app not found", http.StatusNotFound)
		return
	}

	// Generate password reset token with app context
	appCtx := &auth.AppContext{
		AppID:   app.ID,
		AppName: app.Name,
	}
	if len(app.RedirectURIs) > 0 {
		appCtx.RedirectURI = app.RedirectURIs[0]
	}

	token, err := h.tokenService.GeneratePasswordResetToken(user.Email, user.ID, appCtx)
	if err != nil {
		logger.Warnf("app users: password reset token for user %d app %d: %v", userID, appID, err)
		writeError(w, "could not generate password reset token", http.StatusInternalServerError)
		return
	}

	// Log admin action
	if h.adminLogService != nil {
		_ = h.adminLogService.LogAction(r.Context(), adminID, &appID, &userID, model.AdminActionResetPassword, map[string]interface{}{
			"email": user.Email,
		})
	}

	// Send password reset email with app name
	if h.emailService != nil {
		resetURL := h.baseURL + "/auth/reset-password?token=" + token
		if err := h.emailService.SendPasswordResetEmail(user.Email, user.Name, app.Name, resetURL); err != nil {
			logger.Warnf("app users: send password reset email for user %d app %d: %v", userID, appID, err)
			writeError(w, "failed to send password reset email", http.StatusInternalServerError)
			return
		}
	}

	writeJSON(w, dto.MessageResponse{Message: "Password reset email sent"})
}

// requireAppMember writes 404 and returns false unless userID holds a role in
// appID. Used by the mail-triggering admin actions (P3-7) so an app-admin can
// only act on members of the app they administer; the 404 matches GetUser so
// the check does not disclose whether a foreign user ID exists.
func (h *AppUsersHandler) requireAppMember(w http.ResponseWriter, r *http.Request, userID, appID uint) bool {
	if _, err := h.userAppRoleService.GetUserRoleForApp(r.Context(), userID, appID); err != nil {
		if !errors.Is(err, service.ErrRoleNotFound) {
			logger.Warnf("app users: membership check for user %d app %d: %v", userID, appID, err)
		}
		writeError(w, "user not in app", http.StatusNotFound)
		return false
	}
	return true
}

func getAppIDFromURL(r *http.Request) (uint, error) {
	appIDStr := chi.URLParam(r, "app_id")
	appID, err := strconv.ParseUint(appIDStr, 10, 64)
	return uint(appID), err
}

func getUserIDFromURL(r *http.Request) (uint, error) {
	userIDStr := chi.URLParam(r, "user_id")
	userID, err := strconv.ParseUint(userIDStr, 10, 64)
	return uint(userID), err
}

func generateTempPassword() string {
	// Generate a secure random temporary password
	bytes := make([]byte, 24)
	if _, err := rand.Read(bytes); err != nil {
		return "TempPass123!@#" // Fallback
	}
	return base64.RawURLEncoding.EncodeToString(bytes) + "!Aa1"
}
