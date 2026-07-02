package service

import (
	"errors"

	"beetleshield-backend/internal/model"
	"beetleshield-backend/internal/pkg/hash"
	"beetleshield-backend/internal/pkg/jwtutil"
	"beetleshield-backend/internal/repository"
)

var (
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrUserDisabled       = errors.New("user account is disabled")
)

type AuthService struct {
	userRepo       *repository.UserRepository
	jwtSecret      string
	jwtExpireHours int
}

func NewAuthService(userRepo *repository.UserRepository, jwtSecret string, jwtExpireHours int) *AuthService {
	return &AuthService{userRepo: userRepo, jwtSecret: jwtSecret, jwtExpireHours: jwtExpireHours}
}

func (s *AuthService) Login(email, password string) (string, *model.User, error) {
	user, err := s.userRepo.FindByEmail(email)
	if err != nil {
		return "", nil, ErrInvalidCredentials
	}

	if !hash.CheckPassword(user.PasswordHash, password) {
		return "", nil, ErrInvalidCredentials
	}

	if user.Status == model.UserStatusDisabled {
		return "", nil, ErrUserDisabled
	}

	token, err := jwtutil.GenerateToken(s.jwtSecret, user.ID, string(user.Role), s.jwtExpireHours)
	if err != nil {
		return "", nil, err
	}

	_ = s.userRepo.UpdateLastLogin(user.ID)

	return token, user, nil
}

func (s *AuthService) GetUserByID(id uint) (*model.User, error) {
	return s.userRepo.FindByID(id)
}
