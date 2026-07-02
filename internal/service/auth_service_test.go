package service_test

import (
	"testing"

	"beetleshield-backend/internal/config"
	"beetleshield-backend/internal/db"
	"beetleshield-backend/internal/model"
	"beetleshield-backend/internal/pkg/hash"
	"beetleshield-backend/internal/repository"
	"beetleshield-backend/internal/service"
)

func setupTestUserRepo(t *testing.T) *repository.UserRepository {
	t.Helper()
	cfg := &config.Config{
		DBHost: "localhost", DBPort: "5432",
		DBUser: "root", DBPassword: "root",
		DBName: "beetleshield", DBSSLMode: "disable",
	}
	database, err := db.Connect(cfg)
	if err != nil {
		t.Fatalf("Connect() error = %v (is `make dev-up` running?)", err)
	}
	if err := db.Migrate(database); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}
	return repository.NewUserRepository(database)
}

func TestAuthService_Login(t *testing.T) {
	repo := setupTestUserRepo(t)

	hashed, err := hash.HashPassword("Password123!")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	testUser := model.User{
		Name: "测试用户", Email: "auth-test@beetleshield.com",
		PasswordHash: hashed, Role: model.RoleDeveloper,
		Status: model.UserStatusActive,
	}
	repo.DeleteByEmail(testUser.Email)
	if err := repo.Create(&testUser); err != nil {
		t.Fatalf("create test user: %v", err)
	}
	defer repo.DeleteByEmail(testUser.Email)

	authService := service.NewAuthService(repo, "test-secret", 1, nil)

	t.Run("valid credentials", func(t *testing.T) {
		token, user, err := authService.Login(testUser.Email, "Password123!", "")
		if err != nil {
			t.Fatalf("Login() error = %v", err)
		}
		if token == "" {
			t.Error("expected non-empty token")
		}
		if user.Email != testUser.Email {
			t.Errorf("Email = %q, want %q", user.Email, testUser.Email)
		}
	})

	t.Run("wrong password", func(t *testing.T) {
		_, _, err := authService.Login(testUser.Email, "wrong-password", "")
		if err != service.ErrInvalidCredentials {
			t.Errorf("err = %v, want %v", err, service.ErrInvalidCredentials)
		}
	})

	t.Run("unknown email", func(t *testing.T) {
		_, _, err := authService.Login("nobody@beetleshield.com", "whatever", "")
		if err != service.ErrInvalidCredentials {
			t.Errorf("err = %v, want %v", err, service.ErrInvalidCredentials)
		}
	})
}

func setupAuthAuditService(t *testing.T) (*repository.UserRepository, *service.AuditService, uint, string) {
	t.Helper()
	cfg := &config.Config{
		DBHost: "localhost", DBPort: "5432",
		DBUser: "root", DBPassword: "root",
		DBName: "beetleshield", DBSSLMode: "disable",
	}
	database, err := db.Connect(cfg)
	if err != nil {
		t.Fatalf("Connect() error = %v (is Postgres running?)", err)
	}
	if err := db.Migrate(database); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}
	marker := "auth-audit-test"
	database.Unscoped().Where("ip = ?", marker).Delete(&model.AuditLog{})
	t.Cleanup(func() {
		database.Unscoped().Where("ip = ?", marker).Delete(&model.AuditLog{})
	})
	return repository.NewUserRepository(database), service.NewAuditService(repository.NewAuditRepository(database)), uint(0), marker
}

func TestAuthServiceLogin_SuccessRecordsAuditEntry(t *testing.T) {
	userRepo, auditService, _, marker := setupAuthAuditService(t)
	hashed, err := hash.HashPassword("Password123!")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	email := "auth-audit-success@beetleshield.com"
	userRepo.DeleteByEmail(email)
	t.Cleanup(func() { userRepo.DeleteByEmail(email) })
	user := model.User{
		Name: "审计登录成功用户", Email: email,
		PasswordHash: hashed, Role: model.RoleDeveloper, Status: model.UserStatusActive,
	}
	if err := userRepo.Create(&user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	authService := service.NewAuthService(userRepo, "test-secret", 1, auditService)
	if _, _, err := authService.Login(email, "Password123!", marker); err != nil {
		t.Fatalf("Login() error = %v", err)
	}

	logs, total, err := auditService.List(repository.AuditListFilter{
		ActorUserID: user.ID,
		Action:      string(model.AuditActionLoginSuccess),
		Page:        1,
		PageSize:    10,
	})
	if err != nil {
		t.Fatalf("audit List() error = %v", err)
	}
	if total != 1 || len(logs) != 1 || !logs[0].Success || logs[0].ActorEmail != email {
		t.Fatalf("unexpected login success audit rows len=%d total=%d rows=%+v", len(logs), total, logs)
	}
}

func TestAuthServiceLogin_FailureRecordsAuditEntryWithoutActorID(t *testing.T) {
	userRepo, auditService, _, marker := setupAuthAuditService(t)
	hashed, err := hash.HashPassword("Password123!")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	email := "auth-audit-failure@beetleshield.com"
	userRepo.DeleteByEmail(email)
	t.Cleanup(func() { userRepo.DeleteByEmail(email) })
	user := model.User{
		Name: "审计登录失败用户", Email: email,
		PasswordHash: hashed, Role: model.RoleDeveloper, Status: model.UserStatusActive,
	}
	if err := userRepo.Create(&user); err != nil {
		t.Fatalf("create user: %v", err)
	}

	authService := service.NewAuthService(userRepo, "test-secret", 1, auditService)
	_, _, err = authService.Login(email, "wrong-password", marker)
	if err != service.ErrInvalidCredentials {
		t.Fatalf("Login() error = %v, want %v", err, service.ErrInvalidCredentials)
	}

	logs, total, err := auditService.List(repository.AuditListFilter{
		Action:   string(model.AuditActionLoginFailure),
		Page:     1,
		PageSize: 10,
	})
	if err != nil {
		t.Fatalf("audit List() error = %v", err)
	}
	var matched []model.AuditLog
	for _, log := range logs {
		if log.IP == marker && log.ActorEmail == email {
			matched = append(matched, log)
		}
	}
	if total < 1 || len(matched) != 1 || matched[0].Success || matched[0].ActorUserID != 0 {
		t.Fatalf("unexpected login failure audit rows matched=%+v total=%d", matched, total)
	}
}
