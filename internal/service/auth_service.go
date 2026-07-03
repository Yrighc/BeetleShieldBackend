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
	auditService   *AuditService
}

func NewAuthService(userRepo *repository.UserRepository, jwtSecret string, jwtExpireHours int, auditService *AuditService) *AuthService {
	return &AuthService{userRepo: userRepo, jwtSecret: jwtSecret, jwtExpireHours: jwtExpireHours, auditService: auditService}
}

// Login 是一个用户登录方法，接收邮箱和密码作为参数
// 返回JWT令牌、用户信息和可能的错误
func (s *AuthService) Login(email, password, ip string) (string, *model.User, error) {
	// 通过邮箱查找用户，如果查找失败则返回无效凭据错误
	user, err := s.userRepo.FindByEmail(email)
	if err != nil {
		s.recordLoginFailure(email, ip)
		return "", nil, ErrInvalidCredentials
	}

	// 验证密码是否正确，如果不正确则返回无效凭据错误
	if !hash.CheckPassword(user.PasswordHash, password) {
		s.recordLoginFailure(email, ip)
		return "", nil, ErrInvalidCredentials
	}

	// 检查用户状态是否为禁用，如果是禁用状态则返回用户被禁用错误
	if user.Status == model.UserStatusDisabled {
		s.recordLoginFailure(email, ip)
		return "", nil, ErrUserDisabled
	}

	// 生成JWT令牌，包含用户ID、角色和过期时间
	token, err := jwtutil.GenerateToken(s.jwtSecret, user.ID, string(user.Role), s.jwtExpireHours)
	if err != nil {
		return "", nil, err
	}

	// 更新用户最后登录时间，忽略可能的错误
	_ = s.userRepo.UpdateLastLogin(user.ID)

	s.auditService.Record(RecordAuditInput{
		ActorUserID: user.ID,
		ActorEmail:  user.Email,
		Action:      model.AuditActionLoginSuccess,
		IP:          ip,
		Success:     true,
	})

	// 返回生成的令牌、用户信息和nil错误
	return token, user, nil
}

func (s *AuthService) GetUserByID(id uint) (*model.User, error) {
	return s.userRepo.FindByID(id)
}

func (s *AuthService) recordLoginFailure(email, ip string) {
	s.auditService.Record(RecordAuditInput{
		ActorEmail: email,
		Action:     model.AuditActionLoginFailure,
		IP:         ip,
		Success:    false,
	})
}

