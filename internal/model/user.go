package model

import "time"

type UserRole string

const (
	RoleAdmin     UserRole = "admin"
	RoleDeveloper UserRole = "developer"
	RoleAuditor   UserRole = "auditor"
)

type UserStatus string

const (
	UserStatusActive   UserStatus = "active"
	UserStatusDisabled UserStatus = "disabled"
)

type User struct {
	ID           uint       `gorm:"primaryKey" json:"id"`
	Name         string     `gorm:"size:100;not null" json:"name"`
	Email        string     `gorm:"size:255;uniqueIndex;not null" json:"email"`
	PasswordHash string     `gorm:"size:255;not null" json:"-"`
	Role         UserRole   `gorm:"size:20;not null" json:"role"`
	Department   string     `gorm:"size:100" json:"department"`
	Status       UserStatus `gorm:"size:20;not null;default:active" json:"status"`
	LastLoginAt  *time.Time `json:"lastLoginAt"`
	CreatedAt    time.Time  `json:"createdAt"`
	UpdatedAt    time.Time  `json:"updatedAt"`
}

func (User) TableName() string {
	return "users"
}
