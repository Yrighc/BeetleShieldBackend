package model

import "time"

type AuditAction string

const (
	AuditActionLoginSuccess     AuditAction = "auth.login.success"
	AuditActionLoginFailure     AuditAction = "auth.login.failure"
	AuditActionAppUpload        AuditAction = "app.upload"
	AuditActionAppDelete        AuditAction = "app.delete"
	AuditActionHardeningCreate  AuditAction = "hardening_task.create"
	AuditActionStrategySave     AuditAction = "strategy.save"
	AuditActionUserCreate       AuditAction = "user.create"
	AuditActionUserUpdate       AuditAction = "user.update"
	AuditActionUserStatusChange AuditAction = "user.update_status"
)

// AuditLog is intentionally FK-free. ActorEmail is a denormalized snapshot so
// login failures against nonexistent users still show the attempted identity.
type AuditLog struct {
	ID          uint        `gorm:"primaryKey" json:"id"`
	ActorUserID uint        `gorm:"index" json:"actorUserId"`
	ActorEmail  string      `gorm:"size:255" json:"actorEmail"`
	Action      AuditAction `gorm:"size:60;index" json:"action"`
	TargetType  string      `gorm:"size:30" json:"targetType"`
	TargetID    uint        `json:"targetId"`
	Detail      string      `gorm:"size:255" json:"detail"`
	IP          string      `gorm:"size:64" json:"ip"`
	Success     bool        `json:"success"`
	CreatedAt   time.Time   `gorm:"index" json:"createdAt"`
}

func (AuditLog) TableName() string {
	return "audit_logs"
}
