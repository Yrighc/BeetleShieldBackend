package repository

import (
	"testing"

	"beetleshield-backend/internal/config"
	"beetleshield-backend/internal/db"
	"beetleshield-backend/internal/model"
)

func setupUserRepo(t *testing.T) *UserRepository {
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
	database.Unscoped().Where("email LIKE ?", "usertest-%@beetleshield.com").Delete(&model.User{})
	t.Cleanup(func() {
		database.Unscoped().Where("email LIKE ?", "usertest-%@beetleshield.com").Delete(&model.User{})
	})
	return NewUserRepository(database)
}

func TestUserRepository_ListFilters(t *testing.T) {
	repo := setupUserRepo(t)

	users := []model.User{
		{Name: "张三", Email: "usertest-1@beetleshield.com", PasswordHash: "x",
			Role: model.RoleAdmin, Status: model.UserStatusActive},
		{Name: "李四", Email: "usertest-2@beetleshield.com", PasswordHash: "x",
			Role: model.RoleDeveloper, Status: model.UserStatusActive},
	}
	for i := range users {
		if err := repo.Create(&users[i]); err != nil {
			t.Fatalf("Create() error = %v", err)
		}
	}

	result, total, err := repo.List(UserListFilter{Role: "admin", Page: 1, PageSize: 10})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	found := false
	for _, u := range result {
		if u.Email == "usertest-1@beetleshield.com" {
			found = true
		}
		if u.Role != model.RoleAdmin {
			t.Errorf("role filter leaked non-admin user: %+v", u)
		}
	}
	if !found || total < 1 {
		t.Errorf("unexpected role-filtered result: %+v total=%d", result, total)
	}

	result, total, err = repo.List(UserListFilter{Search: "李四", Page: 1, PageSize: 10})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if total != 1 || result[0].Email != "usertest-2@beetleshield.com" {
		t.Errorf("unexpected search result: %+v total=%d", result, total)
	}
}

func TestUserRepository_UpdateAndUpdateStatus(t *testing.T) {
	repo := setupUserRepo(t)

	user := model.User{
		Name: "王五", Email: "usertest-3@beetleshield.com", PasswordHash: "x",
		Role: model.RoleDeveloper, Status: model.UserStatusActive,
	}
	if err := repo.Create(&user); err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	if err := repo.Update(user.ID, map[string]interface{}{"name": "王五五", "department": "安全部"}); err != nil {
		t.Fatalf("Update() error = %v", err)
	}
	updated, err := repo.FindByID(user.ID)
	if err != nil {
		t.Fatalf("FindByID() error = %v", err)
	}
	if updated.Name != "王五五" || updated.Department != "安全部" {
		t.Errorf("Update() did not apply: %+v", updated)
	}

	if err := repo.UpdateStatus(user.ID, model.UserStatusDisabled); err != nil {
		t.Fatalf("UpdateStatus() error = %v", err)
	}
	disabled, err := repo.FindByID(user.ID)
	if err != nil {
		t.Fatalf("FindByID() error = %v", err)
	}
	if disabled.Status != model.UserStatusDisabled {
		t.Errorf("Status = %q, want %q", disabled.Status, model.UserStatusDisabled)
	}
}
