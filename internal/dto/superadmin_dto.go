package dto

import "time"

// Request DTOs

type CreateSuperadminRequest struct {
	Email    string `json:"email"`
	Name     string `json:"name"`
	Password string `json:"password"`
}

type UpdateSuperadminRequest struct {
	Name     *string `json:"name,omitempty"`
	Email    *string `json:"email,omitempty"`
	Password *string `json:"password,omitempty"`
}

// Response DTOs

type SuperadminResponse struct {
	ID           uint       `json:"id"`
	Email        string     `json:"email"`
	Name         string     `json:"name"`
	IsVerified   bool       `json:"is_verified"`
	LastLogin    *time.Time `json:"last_login,omitempty"`
	FailedLogins int        `json:"failed_logins"`
	LockedUntil  *time.Time `json:"locked_until,omitempty"`
	CreatedAt    time.Time  `json:"created_at"`
	UpdatedAt    time.Time  `json:"updated_at"`
}

type SuperadminListResponse struct {
	Superadmins []SuperadminResponse `json:"superadmins"`
	TotalCount  int64                `json:"total_count"`
}
