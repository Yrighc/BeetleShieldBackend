package repository

import (
	"time"

	"gorm.io/gorm"

	"beetleshield-backend/internal/model"
)

type APIRequestLogListFilter struct {
	Method      string
	Path        string
	Status      *int
	ActorUserID uint
	StartTime   *time.Time
	EndTime     *time.Time
	Page        int
	PageSize    int
}

type APIRequestLogRepository struct {
	db *gorm.DB
}

func NewAPIRequestLogRepository(db *gorm.DB) *APIRequestLogRepository {
	return &APIRequestLogRepository{db: db}
}

func (r *APIRequestLogRepository) Record(log *model.APIRequestLog) error {
	return r.db.Create(log).Error
}

func (r *APIRequestLogRepository) List(filter APIRequestLogListFilter) ([]model.APIRequestLog, int64, error) {
	query := r.db.Model(&model.APIRequestLog{})

	if filter.Method != "" {
		query = query.Where("method = ?", filter.Method)
	}
	if filter.Path != "" {
		query = query.Where("path = ?", filter.Path)
	}
	if filter.Status != nil {
		query = query.Where("status = ?", *filter.Status)
	}
	if filter.ActorUserID != 0 {
		query = query.Where("actor_user_id = ?", filter.ActorUserID)
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

	var logs []model.APIRequestLog
	err := query.Order("created_at DESC, id DESC").
		Offset((page - 1) * pageSize).
		Limit(pageSize).
		Find(&logs).Error
	return logs, total, err
}
