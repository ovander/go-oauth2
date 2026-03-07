package model

import (
	"time"
)

type AdminAction string

const (
	AdminActionUpdateRole         AdminAction = "update_role"
	AdminActionRemoveUser         AdminAction = "remove_user"
	AdminActionAddUser            AdminAction = "add_user"
	AdminActionResendVerification AdminAction = "resend_verification"
	AdminActionResetPassword      AdminAction = "reset_password"
	AdminActionRevokeTokens       AdminAction = "revoke_tokens"
	AdminActionUnlockUser         AdminAction = "unlock_user"
	AdminActionCreateSuperadmin   AdminAction = "create_superadmin"
	AdminActionUpdateSuperadmin   AdminAction = "update_superadmin"
	AdminActionDeleteSuperadmin   AdminAction = "delete_superadmin"
	AdminActionDeleteUser         AdminAction = "delete_user"
	AdminActionBlockUser          AdminAction = "block_user"
)

type AdminLog struct {
	ID           uint                   `gorm:"primaryKey" json:"id"`
	AdminID      uint                   `gorm:"column:admin_id;index" json:"admin_id"`
	AppID        *uint                  `gorm:"column:app_id;index" json:"app_id,omitempty"`
	TargetUserID *uint                  `gorm:"column:target_user_id;index" json:"target_user_id,omitempty"`
	Action       AdminAction            `gorm:"type:varchar(50);index" json:"action"`
	Details      map[string]interface{} `gorm:"type:jsonb;serializer:json" json:"details"`
	Admin        *User                  `gorm:"foreignKey:AdminID" json:"admin,omitempty"`
	App          *App                   `gorm:"foreignKey:AppID" json:"app,omitempty"`
	TargetUser   *User                  `gorm:"foreignKey:TargetUserID" json:"target_user,omitempty"`
	CreatedAt    time.Time              `gorm:"column:inserted_at;index" json:"created_at"`
}

func (AdminLog) TableName() string {
	return "admin_logs"
}
