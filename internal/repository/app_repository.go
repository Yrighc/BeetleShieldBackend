package repository

import (
	"gorm.io/gorm"

	"beetleshield-backend/internal/model"
)

type AppListFilter struct {
	Search   string
	Status   string
	Tag      string
	Page     int
	PageSize int
}

type AppRepository struct {
	db *gorm.DB
}

func NewAppRepository(db *gorm.DB) *AppRepository {
	return &AppRepository{db: db}
}

func (r *AppRepository) Create(app *model.App) error {
	return r.db.Create(app).Error
}

func (r *AppRepository) FindByID(id uint) (*model.App, error) {
	var app model.App
	if err := r.db.First(&app, id).Error; err != nil {
		return nil, err
	}
	return &app, nil
}

func (r *AppRepository) Delete(id uint) error {
	return r.db.Delete(&model.App{}, id).Error
}

func (r *AppRepository) List(filter AppListFilter) ([]model.App, int64, error) {
	query := r.db.Model(&model.App{})

	if filter.Search != "" {
		like := "%" + filter.Search + "%"
		query = query.Where("name ILIKE ? OR package_name ILIKE ?", like, like)
	}
	if filter.Status != "" {
		query = query.Where("status = ?", filter.Status)
	}
	if filter.Tag != "" {
		query = query.Where("tag = ?", filter.Tag)
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
		pageSize = 10
	}

	var apps []model.App
	if err := query.Order("created_at DESC").
		Offset((page - 1) * pageSize).
		Limit(pageSize).
		Find(&apps).Error; err != nil {
		return nil, 0, err
	}

	return apps, total, nil
}

func (r *AppRepository) UpdateStatus(id uint, status model.AppStatus) error {
	return requireUpdatedRow(r.db.Model(&model.App{}).Where("id = ?", id).Update("status", status))
}
