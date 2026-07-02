package repository

import (
	"time"

	"gorm.io/gorm"

	"beetleshield-backend/internal/model"
)

type UserRepository struct {
	db *gorm.DB
}

func NewUserRepository(db *gorm.DB) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) FindByEmail(email string) (*model.User, error) {
	var user model.User
	if err := r.db.Where("email = ?", email).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *UserRepository) FindByID(id uint) (*model.User, error) {
	var user model.User
	if err := r.db.First(&user, id).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *UserRepository) UpdateLastLogin(id uint) error {
	now := time.Now()
	return r.db.Model(&model.User{}).Where("id = ?", id).Update("last_login_at", now).Error
}

func (r *UserRepository) Create(user *model.User) error {
	return r.db.Create(user).Error
}

func (r *UserRepository) DeleteByEmail(email string) error {
	return r.db.Unscoped().Where("email = ?", email).Delete(&model.User{}).Error
}

type UserListFilter struct {
	Search   string
	Role     string
	Page     int
	PageSize int
}

func (r *UserRepository) List(filter UserListFilter) ([]model.User, int64, error) {
	query := r.db.Model(&model.User{})

	if filter.Search != "" {
		like := "%" + filter.Search + "%"
		query = query.Where("name ILIKE ? OR email ILIKE ?", like, like)
	}
	if filter.Role != "" {
		query = query.Where("role = ?", filter.Role)
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

	var users []model.User
	if err := query.Order("created_at DESC").
		Offset((page - 1) * pageSize).
		Limit(pageSize).
		Find(&users).Error; err != nil {
		return nil, 0, err
	}

	return users, total, nil
}

func (r *UserRepository) Update(id uint, updates map[string]interface{}) error {
	return r.db.Model(&model.User{}).Where("id = ?", id).Updates(updates).Error
}

func (r *UserRepository) UpdateStatus(id uint, status model.UserStatus) error {
	return r.db.Model(&model.User{}).Where("id = ?", id).Update("status", status).Error
}
