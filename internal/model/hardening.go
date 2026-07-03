package model

import "time"

type HardeningTaskStatus string

const (
	HardeningTaskStatusQueued    HardeningTaskStatus = "queued"
	HardeningTaskStatusRunning   HardeningTaskStatus = "running"
	HardeningTaskStatusCompleted HardeningTaskStatus = "completed"
	HardeningTaskStatusFailed    HardeningTaskStatus = "failed"
)

type HardeningStepStatus string

const (
	HardeningStepStatusWaiting HardeningStepStatus = "waiting"
	HardeningStepStatusRunning HardeningStepStatus = "running"
	HardeningStepStatusSuccess HardeningStepStatus = "success"
	HardeningStepStatusFailed  HardeningStepStatus = "failed"
)

type HardeningStepKey string

const (
	HardeningStepPrepareInput     HardeningStepKey = "prepare_input"
	HardeningStepParsePackage     HardeningStepKey = "parse_package"
	HardeningStepApplyStrategy    HardeningStepKey = "apply_strategy"
	HardeningStepRunEngine        HardeningStepKey = "run_engine"
	HardeningStepCollectArtifacts HardeningStepKey = "collect_artifacts"
	HardeningStepUploadArtifacts  HardeningStepKey = "upload_artifacts"
)

type HardeningLogLevel string

const (
	HardeningLogLevelInfo    HardeningLogLevel = "info"
	HardeningLogLevelWarn    HardeningLogLevel = "warn"
	HardeningLogLevelError   HardeningLogLevel = "error"
	HardeningLogLevelSuccess HardeningLogLevel = "success"
)

type HardeningTask struct {
	ID                  uint                `gorm:"primaryKey" json:"id"`
	TaskNo              string              `gorm:"size:40;uniqueIndex;not null" json:"taskNo"`
	AppID               uint                `gorm:"index;not null" json:"appId"`
	App                 App                 `gorm:"foreignKey:AppID" json:"app,omitempty"`
	Status              HardeningTaskStatus `gorm:"size:20;index;not null" json:"status"`
	StrategyName        string              `gorm:"size:120;not null" json:"strategyName"`
	StrategySnapshot    Strategy            `gorm:"serializer:json" json:"strategySnapshot"`
	UnsignedObjectKey   string              `gorm:"size:500" json:"unsignedObjectKey"`
	UnsignedFileSize    int64               `json:"unsignedFileSize"`
	UnsignedSHA256      string              `gorm:"size:64" json:"unsignedSha256"`
	SignedTestObjectKey string              `gorm:"size:500" json:"signedTestObjectKey"`
	SignedTestFileSize  int64               `json:"signedTestFileSize"`
	SignedTestSHA256    string              `gorm:"size:64" json:"signedTestSha256"`
	ErrorSummary        string              `gorm:"size:500" json:"errorSummary"`
	CreatedBy           uint                `gorm:"not null" json:"createdBy"`
	StartedAt           *time.Time          `json:"startedAt"`
	FinishedAt          *time.Time          `json:"finishedAt"`
	CreatedAt           time.Time           `json:"createdAt"`
	UpdatedAt           time.Time           `json:"updatedAt"`
}

func (HardeningTask) TableName() string {
	return "hardening_tasks"
}

type HardeningStep struct {
	ID           uint                `gorm:"primaryKey" json:"id"`
	TaskID       uint                `gorm:"index;not null" json:"taskId"`
	StepKey      HardeningStepKey    `gorm:"size:40;index;not null" json:"stepKey"`
	Name         string              `gorm:"size:80;not null" json:"name"`
	Status       HardeningStepStatus `gorm:"size:20;not null" json:"status"`
	SortOrder    int                 `gorm:"not null" json:"sortOrder"`
	StartedAt    *time.Time          `json:"startedAt"`
	FinishedAt   *time.Time          `json:"finishedAt"`
	ErrorMessage string              `gorm:"size:500" json:"errorMessage"`
	CreatedAt    time.Time           `json:"createdAt"`
	UpdatedAt    time.Time           `json:"updatedAt"`
}

func (HardeningStep) TableName() string {
	return "hardening_steps"
}

type HardeningLog struct {
	ID        uint              `gorm:"primaryKey" json:"id"`
	TaskID    uint              `gorm:"index;not null" json:"taskId"`
	StepID    *uint             `gorm:"index" json:"stepId"`
	Level     HardeningLogLevel `gorm:"size:20;not null" json:"level"`
	Message   string            `gorm:"type:text;not null" json:"message"`
	CreatedAt time.Time         `json:"createdAt"`
}

func (HardeningLog) TableName() string {
	return "hardening_logs"
}
