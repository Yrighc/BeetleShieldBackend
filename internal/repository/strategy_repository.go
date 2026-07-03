package repository

import (
	"gorm.io/gorm"

	"beetleshield-backend/internal/model"
)

type StrategyRepository struct {
	db *gorm.DB
}

type StrategyListFilter struct {
	Search   string
	Page     int
	PageSize int
}

func NewStrategyRepository(db *gorm.DB) *StrategyRepository {
	return &StrategyRepository{db: db}
}

func (r *StrategyRepository) GetCurrent() (*model.Strategy, error) {
	var strategy model.Strategy
	if err := r.db.Where("is_default = ?", true).Order("id ASC").First(&strategy).Error; err != nil {
		return nil, err
	}
	return &strategy, nil
}

func (r *StrategyRepository) SaveCurrent(strategy *model.Strategy) error {
	strategy.Name = "默认加固策略"
	strategy.IsDefault = true

	var existing model.Strategy
	err := r.db.Where("is_default = ?", true).Order("id ASC").First(&existing).Error
	if err == nil {
		strategy.ID = existing.ID
		strategy.CreatedBy = existing.CreatedBy
	} else if err != gorm.ErrRecordNotFound {
		return err
	}
	return r.db.Save(strategy).Error
}

func (r *StrategyRepository) Save(strategy *model.Strategy) error {
	return r.SaveCurrent(strategy)
}

func (r *StrategyRepository) List(filter StrategyListFilter) ([]model.Strategy, int64, error) {
	query := r.db.Model(&model.Strategy{}).Where("is_default = ?", false)

	if filter.Search != "" {
		like := "%" + filter.Search + "%"
		query = query.Where("name ILIKE ? OR description ILIKE ?", like, like)
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

	var strategies []model.Strategy
	if err := query.Order("created_at DESC").
		Offset((page - 1) * pageSize).
		Limit(pageSize).
		Find(&strategies).Error; err != nil {
		return nil, 0, err
	}
	return strategies, total, nil
}

func (r *StrategyRepository) FindByID(id uint) (*model.Strategy, error) {
	var strategy model.Strategy
	if err := r.db.First(&strategy, id).Error; err != nil {
		return nil, err
	}
	return &strategy, nil
}

func (r *StrategyRepository) FindRegularByID(id uint) (*model.Strategy, error) {
	var strategy model.Strategy
	if err := r.db.Where("is_default = ?", false).First(&strategy, id).Error; err != nil {
		return nil, err
	}
	return &strategy, nil
}

func (r *StrategyRepository) Create(strategy *model.Strategy) error {
	strategy.IsDefault = false
	return r.db.Create(strategy).Error
}

func (r *StrategyRepository) Update(strategy *model.Strategy) error {
	strategy.IsDefault = false
	return r.db.Save(strategy).Error
}

func (r *StrategyRepository) Delete(id uint) error {
	return r.db.Delete(&model.Strategy{}, id).Error
}

func (r *StrategyRepository) NameExists(name string, excludeID uint) (bool, error) {
	query := r.db.Model(&model.Strategy{}).Where("is_default = ? AND name = ?", false, name)
	if excludeID > 0 {
		query = query.Where("id <> ?", excludeID)
	}

	var count int64
	if err := query.Count(&count).Error; err != nil {
		return false, err
	}
	return count > 0, nil
}

func (r *StrategyRepository) PromoteLegacyCurrent() (*model.Strategy, error) {
	var strategy model.Strategy
	if err := r.db.Order("id ASC").First(&strategy).Error; err != nil {
		return nil, err
	}
	strategy.Name = "默认加固策略"
	strategy.IsDefault = true
	if err := r.db.Save(&strategy).Error; err != nil {
		return nil, err
	}
	return &strategy, nil
}
