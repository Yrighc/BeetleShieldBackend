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

	authService := service.NewAuthService(repo, "test-secret", 1)

	t.Run("valid credentials", func(t *testing.T) {
		token, user, err := authService.Login(testUser.Email, "Password123!")
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
		_, _, err := authService.Login(testUser.Email, "wrong-password")
		if err != service.ErrInvalidCredentials {
			t.Errorf("err = %v, want %v", err, service.ErrInvalidCredentials)
		}
	})

	t.Run("unknown email", func(t *testing.T) {
		_, _, err := authService.Login("nobody@beetleshield.com", "whatever")
		if err != service.ErrInvalidCredentials {
			t.Errorf("err = %v, want %v", err, service.ErrInvalidCredentials)
		}
	})
}
