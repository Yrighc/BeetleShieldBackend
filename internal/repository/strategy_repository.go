package repository

import (
	"gorm.io/gorm"

	"beetleshield-backend/internal/model"
)

type StrategyRepository struct {
	db *gorm.DB
}

func NewStrategyRepository(db *gorm.DB) *StrategyRepository {
	return &StrategyRepository{db: db}
}

func (r *StrategyRepository) GetCurrent() (*model.Strategy, error) {
	var strategy model.Strategy
	if err := r.db.Order("id ASC").First(&strategy).Error; err != nil {
		return nil, err
	}
	return &strategy, nil
}

func (r *StrategyRepository) Save(strategy *model.Strategy) error {
	var existing model.Strategy
	err := r.db.Order("id ASC").First(&existing).Error
	if err == nil {
		strategy.ID = existing.ID
	} else if err != gorm.ErrRecordNotFound {
		return err
	}
	return r.db.Save(strategy).Error
}
