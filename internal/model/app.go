package model

import "time"

type AppTag string

const (
	AppTagFinance   AppTag = "finance"
	AppTagGame      AppTag = "game"
	AppTagTool      AppTag = "tool"
	AppTagEcommerce AppTag = "ecommerce"
)

type AppStatus string

const (
	AppStatusUnprotected AppStatus = "unprotected"
	AppStatusProcessing  AppStatus = "processing"
	AppStatusCompleted   AppStatus = "completed"
	AppStatusFailed      AppStatus = "failed"
)

type RiskLevel string

const (
	RiskLevelLow      RiskLevel = "low"
	RiskLevelMedium   RiskLevel = "medium"
	RiskLevelHigh     RiskLevel = "high"
	RiskLevelCritical RiskLevel = "critical"
)

type App struct {
	ID          uint       `gorm:"primaryKey" json:"id"`
	Name        string     `gorm:"size:200;not null" json:"name"`
	PackageName string     `gorm:"size:255;index;not null" json:"packageName"`
	Version     string     `gorm:"size:50" json:"version"`
	Tag         AppTag     `gorm:"size:20;not null" json:"tag"`
	Status      AppStatus  `gorm:"size:20;not null;default:unprotected" json:"status"`
	RiskLevel   *RiskLevel `gorm:"size:20" json:"riskLevel"`
	FileSize    int64      `json:"fileSize"`
	ObjectKey   string     `gorm:"size:500;not null" json:"-"`
	MD5         string     `gorm:"size:32;not null" json:"md5"`
	SHA256      string     `gorm:"size:64;not null" json:"sha256"`
	UploadedBy  uint       `gorm:"not null" json:"uploadedBy"`
	CreatedAt   time.Time  `json:"createdAt"`
	UpdatedAt   time.Time  `json:"updatedAt"`
}

func (App) TableName() string {
	return "apps"
}
