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

func (s *UserService) Create(input CreateUserInput) (user *model.User, err error) {
	defer func() {
		targetID := uint(0)
		detail := input.Email
		if user != nil {
			targetID = user.ID
			detail = user.Email + " (" + string(user.Role) + ")"
		}
		if err != nil {
			detail = input.Email + " - " + err.Error()
		}
		s.auditService.Record(RecordAuditInput{
			ActorUserID: input.ActorUserID,
			Action:      model.AuditActionUserCreate,
			TargetType:  "user",
			TargetID:    targetID,
			Detail:      detail,
			IP:          input.IP,
			Success:     err == nil,
		})
	}()

	if _, findErr := s.userRepo.FindByEmail(input.Email); findErr == nil {
		return nil, ErrEmailAlreadyExists
	}

	hashed, hashErr := hash.HashPassword(input.Password)
	if hashErr != nil {
		return nil, hashErr
	}

	user = &model.User{
		Name:         input.Name,
		Email:        input.Email,
		PasswordHash: hashed,
		Role:         input.Role,
		Department:   input.Department,
		Status:       model.UserStatusActive,
	}
	if err = s.userRepo.Create(user); err != nil {
		return nil, err
	}
	return user, nil
}

func (s *UserService) Update(id uint, input UpdateUserInput, actorUserID uint, ip string) (user *model.User, err error) {
	defer func() {
		detail := "用户资料已更新"
		if err != nil {
			detail = "更新用户失败 - " + err.Error()
		}
		s.auditService.Record(RecordAuditInput{
			ActorUserID: actorUserID,
			Action:      model.AuditActionUserUpdate,
			TargetType:  "user",
			TargetID:    id,
			Detail:      detail,
			IP:          ip,
			Success:     err == nil,
		})
	}()

	if _, err = s.userRepo.FindByID(id); err != nil {
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
		if err = s.userRepo.Update(id, updates); err != nil {
			return nil, err
		}
	}

	user, err = s.userRepo.FindByID(id)
	return user, err
}

func (s *UserService) UpdateStatus(id uint, status model.UserStatus, currentUserID uint, ip string) (err error) {
	defer func() {
		detail := "状态变更失败 - "
		if err == nil {
			statusLabel := "启用"
			if status == model.UserStatusDisabled {
				statusLabel = "禁用"
			}
			detail = "状态变更为 " + statusLabel
		} else {
			detail += err.Error()
		}
		s.auditService.Record(RecordAuditInput{
			ActorUserID: currentUserID,
			Action:      model.AuditActionUserStatusChange,
			TargetType:  "user",
			TargetID:    id,
			Detail:      detail,
			IP:          ip,
			Success:     err == nil,
		})
	}()

	if _, err = s.userRepo.FindByID(id); err != nil {
		return ErrUserNotFound
	}

	if id == currentUserID && status == model.UserStatusDisabled {
		return ErrCannotDisableSelf
	}

	if err = s.userRepo.UpdateStatus(id, status); err != nil {
		return err
	}
	return nil
}
