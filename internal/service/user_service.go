package service

import (
	"errors"

	"beetleshield-backend/internal/model"
	"beetleshield-backend/internal/pkg/hash"
	"beetleshield-backend/internal/repository"
)

var (
	ErrEmailAlreadyExists = errors.New("email already exists")
	ErrCannotDisableSelf  = errors.New("cannot disable your own account")
	ErrUserNotFound       = errors.New("user not found")
)

type CreateUserInput struct {
	Name       string
	Email      string
	Password   string
	Role       model.UserRole
	Department string
}

type UpdateUserInput struct {
	Name       *string
	Department *string
	Role       *model.UserRole
}

type UserService struct {
	userRepo *repository.UserRepository
}

func NewUserService(userRepo *repository.UserRepository) *UserService {
	return &UserService{userRepo: userRepo}
}

func (s *UserService) List(filter repository.UserListFilter) ([]model.User, int64, error) {
	return s.userRepo.List(filter)
}

func (s *UserService) Create(input CreateUserInput) (*model.User, error) {
	if _, err := s.userRepo.FindByEmail(input.Email); err == nil {
		return nil, ErrEmailAlreadyExists
	}

	hashed, err := hash.HashPassword(input.Password)
	if err != nil {
		return nil, err
	}

	user := &model.User{
		Name:         input.Name,
		Email:        input.Email,
		PasswordHash: hashed,
		Role:         input.Role,
		Department:   input.Department,
		Status:       model.UserStatusActive,
	}
	if err := s.userRepo.Create(user); err != nil {
		return nil, err
	}
	return user, nil
}

func (s *UserService) Update(id uint, input UpdateUserInput) (*model.User, error) {
	if _, err := s.userRepo.FindByID(id); err != nil {
		return nil, ErrUserNotFound
	}

	updates := map[string]interface{}{}
	if input.Name != nil {
		updates["name"] = *input.Name
	}
	if input.Department != nil {
		updates["department"] = *input.Department
	}
	if input.Role != nil {
		updates["role"] = *input.Role
	}

	if len(updates) > 0 {
		if err := s.userRepo.Update(id, updates); err != nil {
			return nil, err
		}
	}

	return s.userRepo.FindByID(id)
}

func (s *UserService) UpdateStatus(id uint, status model.UserStatus, currentUserID uint) error {
	if _, err := s.userRepo.FindByID(id); err != nil {
		return ErrUserNotFound
	}

	if id == currentUserID && status == model.UserStatusDisabled {
		return ErrCannotDisableSelf
	}

	return s.userRepo.UpdateStatus(id, status)
}
