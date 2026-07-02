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
	Name        string
	Email       string
	Password    string
	Role        model.UserRole
	Department  string
	ActorUserID uint
	IP          string
}

type UpdateUserInput struct {
	Name       *string
	Department *string
	Role       *model.UserRole
}

type UserService struct {
	userRepo     *repository.UserRepository
	auditService *AuditService
}

func NewUserService(userRepo *repository.UserRepository, auditService *AuditService) *UserService {
	return &UserService{userRepo: userRepo, auditService: auditService}
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
	s.recordAudit(RecordAuditInput{
		ActorUserID: input.ActorUserID,
		Action:      model.AuditActionUserCreate,
		TargetType:  "user",
		TargetID:    user.ID,
		Detail:      user.Email + " (" + string(user.Role) + ")",
		IP:          input.IP,
		Success:     true,
	})
	return user, nil
}

func (s *UserService) Update(id uint, input UpdateUserInput, actorUserID uint, ip string) (*model.User, error) {
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

	s.recordAudit(RecordAuditInput{
		ActorUserID: actorUserID,
		Action:      model.AuditActionUserUpdate,
		TargetType:  "user",
		TargetID:    id,
		Detail:      "用户资料已更新",
		IP:          ip,
		Success:     true,
	})
	return s.userRepo.FindByID(id)
}

func (s *UserService) UpdateStatus(id uint, status model.UserStatus, currentUserID uint, ip string) error {
	if _, err := s.userRepo.FindByID(id); err != nil {
		return ErrUserNotFound
	}

	if id == currentUserID && status == model.UserStatusDisabled {
		return ErrCannotDisableSelf
	}

	if err := s.userRepo.UpdateStatus(id, status); err != nil {
		return err
	}
	statusLabel := "启用"
	if status == model.UserStatusDisabled {
		statusLabel = "禁用"
	}
	s.recordAudit(RecordAuditInput{
		ActorUserID: currentUserID,
		Action:      model.AuditActionUserStatusChange,
		TargetType:  "user",
		TargetID:    id,
		Detail:      "状态变更为 " + statusLabel,
		IP:          ip,
		Success:     true,
	})
	return nil
}

func (s *UserService) recordAudit(input RecordAuditInput) {
	if s.auditService != nil {
		s.auditService.Record(input)
	}
}
