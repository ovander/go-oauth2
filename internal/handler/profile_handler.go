package handler

import (
	"encoding/json"
	"net/http"

	"github.com/ovandermoten/go-oauth2/internal/dto"
	"github.com/ovandermoten/go-oauth2/internal/middleware"
	"github.com/ovandermoten/go-oauth2/internal/service"
)

type ProfileHandler struct {
	userService service.UserService
}

func NewProfileHandler(userService service.UserService) *ProfileHandler {
	return &ProfileHandler{
		userService: userService,
	}
}

// PUT/PATCH /api/profile
func (h *ProfileHandler) UpdateProfile(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserIDFromContext(r.Context())
	if !ok {
		writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	var req dto.UpdateProfileRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, "invalid JSON", http.StatusBadRequest)
		return
	}

	user, err := h.userService.UpdateProfile(r.Context(), userID, req)
	if err != nil {
		writeError(w, err.Error(), http.StatusBadRequest)
		return
	}

	json.NewEncoder(w).Encode(dto.UserResponse{
		ID:         user.ID,
		Email:      user.Email,
		Name:       user.Name,
		Role:       string(user.Role),
		IsVerified: user.IsVerified,
		Title:      user.Title,
		Division:   user.Division,
		Company:    user.Company,
		Country:    user.Country,
		Phone:      user.Phone,
		JobTitle:   user.JobTitle,
		Department: user.Department,
		Language:   user.Language,
		Timezone:   user.Timezone,
		LastLogin:  user.LastLogin,
		CreatedAt:  user.CreatedAt,
	})
}

// GET /api/profile
func (h *ProfileHandler) GetProfile(w http.ResponseWriter, r *http.Request) {
	userID, ok := middleware.GetUserIDFromContext(r.Context())
	if !ok {
		writeError(w, "unauthorized", http.StatusUnauthorized)
		return
	}

	user, err := h.userService.GetByID(r.Context(), userID)
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
		Title:      user.Title,
		Division:   user.Division,
		Company:    user.Company,
		Country:    user.Country,
		Phone:      user.Phone,
		JobTitle:   user.JobTitle,
		Department: user.Department,
		Language:   user.Language,
		Timezone:   user.Timezone,
		LastLogin:  user.LastLogin,
		CreatedAt:  user.CreatedAt,
	})
}
