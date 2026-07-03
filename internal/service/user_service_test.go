package service_test

import (
	"fmt"
	"testing"
	"time"

	"beetleshield-backend/internal/config"
	"beetleshield-backend/internal/db"
	"beetleshield-backend/internal/model"
	"beetleshield-backend/internal/repository"
	"beetleshield-backend/internal/service"
)

func setupUserServiceWithAudit(t *testing.T) (*service.UserService, *service.AuditService, string, uint) {
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
	marker := fmt.Sprintf("user-audit-%d", time.Now().UnixNano())
	actorID := uint(time.Now().UnixNano()%1_000_000_000 + 500_000)
	t.Cleanup(func() {
		database.Unscoped().Where("ip = ?", marker).Delete(&model.AuditLog{})
	})
	userRepo := repository.NewUserRepository(database)
	auditService := service.NewAuditService(repository.NewAuditRepository(database))

	return service.NewUserService(userRepo, auditService), auditService, marker, actorID
}

func TestUserService_Create(t *testing.T) {
	repo := setupTestUserRepo(t)
	svc := service.NewUserService(repo, nil)

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
	svc := service.NewUserService(repo, nil)

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
	}, 0, "")
	if err != nil {
		t.Fatalf("Update() error = %v", err)
	}
	if updated.Name != newName || updated.Department != newDept || updated.Role != newRole {
		t.Errorf("Update() did not apply: %+v", updated)
	}

	_, err = svc.Update(999999, service.UpdateUserInput{Name: &newName}, 0, "")
	if err != service.ErrUserNotFound {
		t.Errorf("err = %v, want %v", err, service.ErrUserNotFound)
	}
}

func TestUserService_UpdateStatus(t *testing.T) {
	repo := setupTestUserRepo(t)
	svc := service.NewUserService(repo, nil)

	repo.DeleteByEmail("usersvc-3@beetleshield.com")
	t.Cleanup(func() { repo.DeleteByEmail("usersvc-3@beetleshield.com") })

	user, err := svc.Create(service.CreateUserInput{
		Name: "待禁用", Email: "usersvc-3@beetleshield.com", Password: "Password123!",
		Role: model.RoleDeveloper,
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	if err := svc.UpdateStatus(user.ID, model.UserStatusDisabled, 999999, ""); err != nil {
		t.Fatalf("UpdateStatus() error = %v", err)
	}
	disabled, err := repo.FindByID(user.ID)
	if err != nil {
		t.Fatalf("FindByID() error = %v", err)
	}
	if disabled.Status != model.UserStatusDisabled {
		t.Errorf("Status = %q, want %q", disabled.Status, model.UserStatusDisabled)
	}

	err = svc.UpdateStatus(user.ID, model.UserStatusDisabled, user.ID, "")
	if err != service.ErrCannotDisableSelf {
		t.Errorf("err = %v, want %v", err, service.ErrCannotDisableSelf)
	}
}

func TestUserService_UpdateStatus_AdminDisablesAnotherAdmin(t *testing.T) {
	repo := setupTestUserRepo(t)
	svc := service.NewUserService(repo, nil)

	repo.DeleteByEmail("usersvc-admin-a@beetleshield.com")
	repo.DeleteByEmail("usersvc-admin-b@beetleshield.com")
	t.Cleanup(func() {
		repo.DeleteByEmail("usersvc-admin-a@beetleshield.com")
		repo.DeleteByEmail("usersvc-admin-b@beetleshield.com")
	})

	adminA, err := svc.Create(service.CreateUserInput{
		Name: "管理员甲", Email: "usersvc-admin-a@beetleshield.com", Password: "Password123!",
		Role: model.RoleAdmin,
	})
	if err != nil {
		t.Fatalf("Create() adminA error = %v", err)
	}

	adminB, err := svc.Create(service.CreateUserInput{
		Name: "管理员乙", Email: "usersvc-admin-b@beetleshield.com", Password: "Password123!",
		Role: model.RoleAdmin,
	})
	if err != nil {
		t.Fatalf("Create() adminB error = %v", err)
	}

	if err := svc.UpdateStatus(adminB.ID, model.UserStatusDisabled, adminA.ID, ""); err != nil {
		t.Fatalf("UpdateStatus() error = %v", err)
	}

	disabled, err := repo.FindByID(adminB.ID)
	if err != nil {
		t.Fatalf("FindByID() error = %v", err)
	}
	if disabled.Status != model.UserStatusDisabled {
		t.Errorf("Status = %q, want %q", disabled.Status, model.UserStatusDisabled)
	}
}

// filterAuditLogsByTargetID narrows a List() result to rows matching a
// specific TargetID client-side, since repository.AuditListFilter has no
// TargetID field (pre-existing behavior, not something to fix here).
func filterAuditLogsByTargetID(logs []model.AuditLog, targetID uint) []model.AuditLog {
	var out []model.AuditLog
	for _, l := range logs {
		if l.TargetID == targetID {
			out = append(out, l)
		}
	}
	return out
}

func TestUserService_Create_DuplicateEmailRecordsFailureAudit(t *testing.T) {
	svc, auditService, marker, actorID := setupUserServiceWithAudit(t)

	email := fmt.Sprintf("usersvc-dup-%d@beetleshield.com", time.Now().UnixNano())

	user, err := svc.Create(service.CreateUserInput{
		Name: "去重用户", Email: email, Password: "Password123!",
		Role: model.RoleDeveloper, ActorUserID: actorID, IP: marker,
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	// Second Create with the same email must fail with ErrEmailAlreadyExists,
	// and (unlike before this retrofit) must still produce an audit row.
	_, err = svc.Create(service.CreateUserInput{
		Name: "重复邮箱用户", Email: email, Password: "Password123!",
		Role: model.RoleDeveloper, ActorUserID: actorID, IP: marker,
	})
	if err != service.ErrEmailAlreadyExists {
		t.Fatalf("err = %v, want %v", err, service.ErrEmailAlreadyExists)
	}

	logs, _, err := auditService.List(repository.AuditListFilter{
		ActorUserID: actorID,
		Action:      string(model.AuditActionUserCreate),
		Page:        1,
		PageSize:    10,
	})
	if err != nil {
		t.Fatalf("audit List() error = %v", err)
	}

	failures := filterAuditLogsByTargetID(logs, 0)
	var falseCount int
	for _, l := range failures {
		if !l.Success {
			falseCount++
		}
	}
	if falseCount != 1 {
		t.Fatalf("expected exactly one Success:false user.create row with TargetID:0, got %d (rows=%+v)", falseCount, logs)
	}
	for _, l := range failures {
		if !l.Success && l.TargetType != "user" {
			t.Errorf("TargetType = %q, want %q", l.TargetType, "user")
		}
	}
	_ = user
}

func TestUserService_Update_NotFoundRecordsFailureAudit(t *testing.T) {
	svc, auditService, marker, actorID := setupUserServiceWithAudit(t)
	_ = marker

	const missingID uint = 999999999
	newName := "不存在的用户"

	_, err := svc.Update(missingID, service.UpdateUserInput{Name: &newName}, actorID, marker)
	if err != service.ErrUserNotFound {
		t.Fatalf("err = %v, want %v", err, service.ErrUserNotFound)
	}

	logs, _, err := auditService.List(repository.AuditListFilter{
		ActorUserID: actorID,
		Action:      string(model.AuditActionUserUpdate),
		Page:        1,
		PageSize:    10,
	})
	if err != nil {
		t.Fatalf("audit List() error = %v", err)
	}

	matches := filterAuditLogsByTargetID(logs, missingID)
	if len(matches) != 1 {
		t.Fatalf("expected exactly one user.update row with TargetID:%d, got %d (rows=%+v)", missingID, len(matches), logs)
	}
	if matches[0].Success {
		t.Errorf("Success = true, want false")
	}
	if matches[0].TargetType != "user" {
		t.Errorf("TargetType = %q, want %q", matches[0].TargetType, "user")
	}
}

func TestUserService_UpdateStatus_CannotDisableSelfRecordsFailureAudit(t *testing.T) {
	svc, auditService, marker, actorID := setupUserServiceWithAudit(t)

	email := fmt.Sprintf("usersvc-selfdisable-%d@beetleshield.com", time.Now().UnixNano())
	user, err := svc.Create(service.CreateUserInput{
		Name: "自我禁用测试", Email: email, Password: "Password123!",
		Role: model.RoleAdmin, ActorUserID: actorID, IP: marker,
	})
	if err != nil {
		t.Fatalf("Create() error = %v", err)
	}

	err = svc.UpdateStatus(user.ID, model.UserStatusDisabled, user.ID, marker)
	if err != service.ErrCannotDisableSelf {
		t.Fatalf("err = %v, want %v", err, service.ErrCannotDisableSelf)
	}

	logs, _, err := auditService.List(repository.AuditListFilter{
		ActorUserID: user.ID,
		Action:      string(model.AuditActionUserStatusChange),
		Page:        1,
		PageSize:    10,
	})
	if err != nil {
		t.Fatalf("audit List() error = %v", err)
	}

	matches := filterAuditLogsByTargetID(logs, user.ID)
	if len(matches) != 1 {
		t.Fatalf("expected exactly one user.update_status row with TargetID:%d, got %d (rows=%+v)", user.ID, len(matches), logs)
	}
	if matches[0].Success {
		t.Errorf("Success = true, want false")
	}
	if matches[0].TargetType != "user" {
		t.Errorf("TargetType = %q, want %q", matches[0].TargetType, "user")
	}
}
