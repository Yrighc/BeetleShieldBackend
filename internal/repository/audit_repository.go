package repository

import (
	"time"

	"gorm.io/gorm"

	"beetleshield-backend/internal/model"
)

type AuditListFilter struct {
	ActorUserID uint
	Action      string
	TargetType  string
	Success     *bool
	StartTime   *time.Time
	EndTime     *time.Time
	Page        int
	PageSize    int
}

type AuditRepository struct {
	db *gorm.DB
}

func NewAuditRepository(db *gorm.DB) *AuditRepository {
	return &AuditRepository{db: db}
}

func (r *AuditRepository) Record(log *model.AuditLog) error {
	return r.db.Create(log).Error
}

func (r *AuditRepository) List(filter AuditListFilter) ([]model.AuditLog, int64, error) {
	query := r.db.Model(&model.AuditLog{})
	if filter.ActorUserID != 0 {
		query = query.Where("actor_user_id = ?", filter.ActorUserID)
	}
	if filter.Action != "" {
		query = query.Where("action = ?", filter.Action)
	}
	if filter.TargetType != "" {
		query = query.Where("target_type = ?", filter.TargetType)
	}
	if filter.Success != nil {
		query = query.Where("success = ?", *filter.Success)
	}
	if filter.StartTime != nil {
		query = query.Where("created_at >= ?", *filter.StartTime)
	}
	if filter.EndTime != nil {
		query = query.Where("created_at <= ?", *filter.EndTime)
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	page := filter.Page
	if page < 1 {
		page = 1
	}
	pageSize := filter.PageSize
	if pageSize < 1 {
		pageSize = 20
	}

	var logs []model.AuditLog
	if err := query.Order("created_at DESC, id DESC").
		Offset((page - 1) * pageSize).
		Limit(pageSize).
		Find(&logs).Error; err != nil {
		return nil, 0, err
	}
	return logs, total, nil
}
