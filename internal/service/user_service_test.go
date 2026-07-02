package service_test

import (
	"testing"

	"beetleshield-backend/internal/model"
	"beetleshield-backend/internal/service"
)

func TestUserService_Create(t *testing.T) {
	repo := setupTestUserRepo(t)
	svc := service.NewUserService(repo)

	repo.DeleteByEmail("usersvc-1@beetleshield.com")
	t.Cleanup(func() { repo.DeleteByEmail("usersvc-1@beetleshield.com") })

	user, err := svc.Create(service.CreateUserInput{
		Name: "测试开发", Email: "usersvc-1@beetleshield.com", Password: "Password123!",
		Role: model.RoleDeveloper, Department: "研发部",
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if user.Email != "usersvc-1@beetleshield.com" {
		t.Errorf("Email = %q, want %q", user.Email, "usersvc-1@beetleshield.com")
	}
	if user.PasswordHash == "Password123!" {
		t.Error("password was not hashed")
	}

	_, err = svc.Create(service.CreateUserInput{
		Name: "重复邮箱", Email: "usersvc-1@beetleshield.com", Password: "Password123!",
		Role: model.RoleDeveloper,
	})
	if err != service.ErrEmailAlreadyExists {
		t.Errorf("err = %v, want %v", err, service.ErrEmailAlreadyExists)
	}
}

func TestUserService_Update(t *testing.T) {
	repo := setupTestUserRepo(t)
	svc := service.NewUserService(repo)

	repo.DeleteByEmail("usersvc-2@beetleshield.com")
	t.Cleanup(func() { repo.DeleteByEmail("usersvc-2@beetleshield.com") })

	user, err := svc.Create(service.CreateUserInput{
		Name: "待编辑", Email: "usersvc-2@beetleshield.com", Password: "Password123!",
		Role: model.RoleDeveloper, Department: "研发部",
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	newName := "已编辑"
	newDept := "安全部"
	newRole := model.RoleAuditor
	updated, err := svc.Update(user.ID, service.UpdateUserInput{
		Name: &newName, Department: &newDept, Role: &newRole,
	})
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}
	if updated.Name != newName || updated.Department != newDept || updated.Role != newRole {
		t.Errorf("Update() did not apply: %+v", updated)
	}

	_, err = svc.Update(999999, service.UpdateUserInput{Name: &newName})
	if err != service.ErrUserNotFound {
		t.Errorf("err = %v, want %v", err, service.ErrUserNotFound)
	}
}

func TestUserService_UpdateStatus(t *testing.T) {
	repo := setupTestUserRepo(t)
	svc := service.NewUserService(repo)

	repo.DeleteByEmail("usersvc-3@beetleshield.com")
	t.Cleanup(func() { repo.DeleteByEmail("usersvc-3@beetleshield.com") })

	user, err := svc.Create(service.CreateUserInput{
		Name: "待禁用", Email: "usersvc-3@beetleshield.com", Password: "Password123!",
		Role: model.RoleDeveloper,
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	if err := svc.UpdateStatus(user.ID, model.UserStatusDisabled, 999999); err != nil {
		t.Fatalf("UpdateStatus() error = %v", err)
	}
	disabled, err := repo.FindByID(user.ID)
	if err != nil {
		t.Fatalf("FindByID() error = %v", err)
	}
	if disabled.Status != model.UserStatusDisabled {
		t.Errorf("Status = %q, want %q", disabled.Status, model.UserStatusDisabled)
	}

	err = svc.UpdateStatus(user.ID, model.UserStatusDisabled, user.ID)
	if err != service.ErrCannotDisableSelf {
		t.Errorf("err = %v, want %v", err, service.ErrCannotDisableSelf)
	}
}
