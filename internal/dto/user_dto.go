package dto

import (
	"time"

	"github.com/ovander/go-oauth2/internal/model"
)

// Request DTOs

type CreateUserRequest struct {
	Email    string `json:"email"`
	Name     string `json:"name"`
	Password string `json:"password"`
	Role     string `json:"role,omitempty"`
}

type UpdateUserRequest struct {
	Name       *string `json:"name,omitempty"`
	Email      *string `json:"email,omitempty"`
	Title      *string `json:"title,omitempty"`
	Division   *string `json:"division,omitempty"`
	Company    *string `json:"company,omitempty"`
	Country    *string `json:"country,omitempty"`
	Phone      *string `json:"phone,omitempty"`
	JobTitle   *string `json:"job_title,omitempty"`
	Department *string `json:"department,omitempty"`
	Language   *string `json:"language,omitempty"`
	Timezone   *string `json:"timezone,omitempty"`
	// Attributes replaces the user's free-form attribute set (A2), which a
	// client can project into its tokens via a claim mapping. Omitted (nil) =
	// unchanged; an empty object clears every attribute. Admin-only — it is
	// deliberately absent from UpdateProfileRequest so a user cannot mint their
	// own claim values.
	Attributes *model.JSONMap `json:"attributes,omitempty"`
}

type UpdateProfileRequest struct {
	Name       *string `json:"name,omitempty"`
	Title      *string `json:"title,omitempty"`
	Division   *string `json:"division,omitempty"`
	Company    *string `json:"company,omitempty"`
	Country    *string `json:"country,omitempty"`
	Phone      *string `json:"phone,omitempty"`
	JobTitle   *string `json:"job_title,omitempty"`
	Department *string `json:"department,omitempty"`
	Language   *string `json:"language,omitempty"`
	Timezone   *string `json:"timezone,omitempty"`
}

// Response DTOs

type UserResponse struct {
	ID         uint          `json:"id"`
	Email      string        `json:"email"`
	Name       string        `json:"name"`
	Role       string        `json:"role"`
	IsVerified bool          `json:"is_verified"`
	Title      *string       `json:"title,omitempty"`
	Division   *string       `json:"division,omitempty"`
	Company    *string       `json:"company,omitempty"`
	Country    *string       `json:"country,omitempty"`
	Phone      *string       `json:"phone,omitempty"`
	JobTitle   *string       `json:"job_title,omitempty"`
	Department *string       `json:"department,omitempty"`
	Language   *string       `json:"language,omitempty"`
	Timezone   *string       `json:"timezone,omitempty"`
	Attributes model.JSONMap `json:"attributes,omitempty"`
	LastLogin  *time.Time    `json:"last_login,omitempty"`
	CreatedAt  time.Time     `json:"created_at"`
}

type UserListResponse struct {
	Users      []UserResponse `json:"users"`
	TotalCount int64          `json:"total_count"`
	Page       int            `json:"page"`
	PageSize   int            `json:"page_size"`
}
