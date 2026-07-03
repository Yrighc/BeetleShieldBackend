package model

import "time"

// APIRequestLog is intentionally separate from AuditLog: it captures raw
// HTTP traffic metadata (method/path/status/latency) for every /api/v1/*
// request regardless of whether the underlying handler considers the
// operation a business-significant "audit" event. No FK constraints, no
// request/response body (avoids logging secrets and keeps storage small).
type APIRequestLog struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	Method      string    `gorm:"size:10;index" json:"method"`
	Path        string    `gorm:"size:255;index" json:"path"`
	Status      int       `gorm:"index" json:"status"`
	LatencyMS   int64     `json:"latencyMs"`
	ClientIP    string    `gorm:"size:64" json:"clientIp"`
	ActorUserID uint      `gorm:"index" json:"actorUserId"`
	CreatedAt   time.Time `gorm:"index" json:"createdAt"`
}

func (APIRequestLog) TableName() string {
	return "api_request_logs"
}
