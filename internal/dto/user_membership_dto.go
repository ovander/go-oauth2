package dto

import "time"

// UserAppMembershipResponse represents a user's membership in an app
type UserAppMembershipResponse struct {
	AppID     uint      `json:"app_id"`
	AppName   string    `json:"app_name"`
	ClientID  string    `json:"client_id"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
}

// UserAppMembershipsResponse is the response for listing user's app memberships
type UserAppMembershipsResponse struct {
	UserID      uint                        `json:"user_id"`
	Email       string                      `json:"email"`
	Name        string                      `json:"name"`
	Memberships []UserAppMembershipResponse `json:"memberships"`
	TotalCount  int                         `json:"total_count"`
}
