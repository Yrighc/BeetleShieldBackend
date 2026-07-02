# BeetleShield Backend — User Management + RBAC Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a role-based access control (RBAC) middleware and a complete user-management CRUD (list/create/update/enable-disable) to the already-merged BeetleShield backend, and retrofit role checks onto the existing application-management write routes.

**Architecture:** One new `middleware.RequireRole` gin middleware, layered the same way as the existing `handler → service → repository → model` stack used for app management (Tasks 9-14 of the prior sub-project). `UserRepository` (already exists from the login sub-project) gains list/update/status methods; a new `UserService` adds business rules (email uniqueness, self-disable guard); a new `UserHandler` exposes them under `/api/v1/users`, gated to `admin` only. The existing `/api/v1/apps/*` write routes (`upload`, `delete`, `download-url`) get `RequireRole(admin, developer)` added.

**Tech Stack:** Same as the existing codebase — Go, Gin, GORM/PostgreSQL, no new dependencies.

Reference spec: [`docs/superpowers/specs/2026-07-02-backend-user-management-rbac-design.md`](../specs/2026-07-02-backend-user-management-rbac-design.md)

## Global Constraints

- Module name: `beetleshield-backend`. API prefix `/api/v1`; every response uses `{code int, message string, data any}` (code `0` = success) via the existing `internal/pkg/response` package.
- Local dev Postgres: `root`/`root`@`localhost:5432`/`beetleshield` (pre-existing `pg12-dev` container on this machine — do not run `make dev-up`/`docker compose up`; see the base plan's Global Constraints for the full story). MinIO: `admin`/`yuan801200`@`localhost:9000` (only relevant to already-existing app-management tests touched in Task 5).
- Role → route mapping (from the spec):
  - `GET /apps`, `GET /apps/:id` → `admin` / `developer` / `auditor` (unrestricted, already the case)
  - `POST /apps/upload`, `DELETE /apps/:id`, `GET /apps/:id/download-url` → `admin` / `developer` only (Task 5 adds this)
  - `GET /users`, `POST /users`, `PATCH /users/:id`, `PATCH /users/:id/status` → `admin` only
- No `DELETE /users/:id` endpoint. No email/password changes via `PATCH /users/:id`. Admin cannot disable their own account via `PATCH /users/:id/status`.
- `POST /users` requires the caller (admin) to set the new user's initial password directly in the request body; no email/invite flow.
- `users.role` ∈ {`admin`, `developer`, `auditor`}; `users.status` ∈ {`active`, `disabled`} (both already defined in `internal/model/user.go`, unchanged).

---

## File Structure

```
internal/
├── middleware/
│   ├── rbac.go              (new)
│   └── rbac_test.go         (new)
├── repository/
│   ├── user_repository.go   (modify — add List/Update/UpdateStatus)
│   └── user_repository_test.go (new)
├── service/
│   ├── user_service.go      (new)
│   └── user_service_test.go (new)
├── handler/
│   ├── user_handler.go      (new)
│   ├── user_handler_test.go (new)
│   └── app_handler_test.go  (modify — add RBAC regression test)
└── router/
    └── router.go             (modify — /users group in Task 4, /apps role gate in Task 5)
cmd/server/main.go             (modify — wire UserService/UserHandler, Task 4)
```

---

### Task 1: RBAC role-check middleware

**Files:**
- Create: `internal/middleware/rbac.go`
- Test: `internal/middleware/rbac_test.go`

**Interfaces:**
- Consumes: `middleware.ContextRoleKey` (existing, `internal/middleware/auth.go:15`), `middleware.JWTAuth` (existing), `response.Error` (existing).
- Produces: `middleware.RequireRole(roles ...model.UserRole) gin.HandlerFunc` — consumed by `internal/router/router.go` in Task 4 (new `/users` group) and Task 5 (retrofitted onto `/apps` write routes).

- [ ] **Step 1: Write the failing test**

Create `internal/middleware/rbac_test.go`:

```go
package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"beetleshield-backend/internal/model"
	"beetleshield-backend/internal/pkg/jwtutil"
)

func setupRBACRouter(secret string, allowedRoles ...model.UserRole) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(JWTAuth(secret))
	r.GET("/protected", RequireRole(allowedRoles...), func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"ok": true})
	})
	return r
}

func TestRequireRole_AllowedRolePasses(t *testing.T) {
	secret := "test-secret"
	r := setupRBACRouter(secret, model.RoleAdmin)
	token, err := jwtutil.GenerateToken(secret, 1, string(model.RoleAdmin), 1)
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d, body=%s", w.Code, http.StatusOK, w.Body.String())
	}
}

func TestRequireRole_DisallowedRoleForbidden(t *testing.T) {
	secret := "test-secret"
	r := setupRBACRouter(secret, model.RoleAdmin)
	token, err := jwtutil.GenerateToken(secret, 1, string(model.RoleAuditor), 1)
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d, body=%s", w.Code, http.StatusForbidden, w.Body.String())
	}
}

func TestRequireRole_MissingTokenUnauthorized(t *testing.T) {
	r := setupRBACRouter("test-secret", model.RoleAdmin)
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestRequireRole_MultipleAllowedRoles(t *testing.T) {
	secret := "test-secret"
	r := setupRBACRouter(secret, model.RoleAdmin, model.RoleDeveloper)
	token, err := jwtutil.GenerateToken(secret, 2, string(model.RoleDeveloper), 1)
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", w.Code, http.StatusOK)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/middleware/... -v -run TestRequireRole`
Expected: FAIL — package doesn't compile (`RequireRole` undefined).

- [ ] **Step 3: Implement**

Create `internal/middleware/rbac.go`:

```go
package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"

	"beetleshield-backend/internal/model"
	"beetleshield-backend/internal/pkg/response"
)

func RequireRole(roles ...model.UserRole) gin.HandlerFunc {
	allowed := make(map[model.UserRole]bool, len(roles))
	for _, r := range roles {
		allowed[r] = true
	}

	return func(c *gin.Context) {
		role := model.UserRole(c.GetString(ContextRoleKey))
		if !allowed[role] {
			response.Error(c, http.StatusForbidden, 40302, "insufficient permissions")
			c.Abort()
			return
		}
		c.Next()
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/middleware/... -v`
Expected: PASS (all `TestRequireRole_*` tests, plus the pre-existing `TestJWTAuth_*` tests still passing)

- [ ] **Step 5: Commit**

```bash
git add internal/middleware/rbac.go internal/middleware/rbac_test.go
git commit -m "feat: add RequireRole RBAC middleware"
```

---

### Task 2: User repository — list, update, status extensions

**Files:**
- Modify: `internal/repository/user_repository.go`
- Test: `internal/repository/user_repository_test.go`

**Interfaces:**
- Consumes: `model.User`, `model.UserRole`, `model.UserStatus` (existing).
- Produces: `repository.UserListFilter{Search, Role string, Page, PageSize int}`, `UserRepository.List(filter UserListFilter) ([]model.User, int64, error)`, `Update(id uint, updates map[string]interface{}) error`, `UpdateStatus(id uint, status model.UserStatus) error` — consumed by `internal/service/user_service.go` (Task 3).

- [ ] **Step 1: Write the failing test**

Create `internal/repository/user_repository_test.go`:

```go
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
	if total != 1 || result[0].Email != "usertest-1@beetleshield.com" {
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/repository/... -v -run TestUserRepository`
Expected: FAIL — `UserListFilter`, `List`, `Update`, `UpdateStatus` undefined on `*UserRepository`.

- [ ] **Step 3: Implement**

Modify `internal/repository/user_repository.go` — append the following after the existing `DeleteByEmail` method (keep everything above unchanged):

```go
type UserListFilter struct {
	Search   string
	Role     string
	Page     int
	PageSize int
}

func (r *UserRepository) List(filter UserListFilter) ([]model.User, int64, error) {
	query := r.db.Model(&model.User{})

	if filter.Search != "" {
		like := "%" + filter.Search + "%"
		query = query.Where("name ILIKE ? OR email ILIKE ?", like, like)
	}
	if filter.Role != "" {
		query = query.Where("role = ?", filter.Role)
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	page := filter.Page
	if page < 1 {
		page = 1
	}
	pageSize := filter.PageSize
	if pageSize < 1 {
		pageSize = 10
	}

	var users []model.User
	if err := query.Order("created_at DESC").
		Offset((page - 1) * pageSize).
		Limit(pageSize).
		Find(&users).Error; err != nil {
		return nil, 0, err
	}

	return users, total, nil
}

func (r *UserRepository) Update(id uint, updates map[string]interface{}) error {
	return r.db.Model(&model.User{}).Where("id = ?", id).Updates(updates).Error
}

func (r *UserRepository) UpdateStatus(id uint, status model.UserStatus) error {
	return r.db.Model(&model.User{}).Where("id = ?", id).Update("status", status).Error
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/repository/... -v`
Expected: PASS (all repository tests, including the new `TestUserRepository_*` and the pre-existing `TestAppRepository_*`)

- [ ] **Step 5: Commit**

```bash
git add internal/repository/user_repository.go internal/repository/user_repository_test.go
git commit -m "feat: add user list/update/status-update to user repository"
```

---

### Task 3: User service (business logic)

**Files:**
- Create: `internal/service/user_service.go`
- Test: `internal/service/user_service_test.go`

**Interfaces:**
- Consumes: `repository.UserRepository`/`UserListFilter` (Task 2), `hash.HashPassword` (existing), `model.User`/`UserRole`/`UserStatus` (existing), `setupTestUserRepo` test helper (existing, defined in `internal/service/auth_service_test.go`, same `service_test` package).
- Produces: `service.CreateUserInput{Name, Email, Password string, Role model.UserRole, Department string}`, `service.UpdateUserInput{Name, Department *string, Role *model.UserRole}`, `service.UserService` with `NewUserService(userRepo *repository.UserRepository) *UserService`, `List(filter repository.UserListFilter) ([]model.User, int64, error)`, `Create(input CreateUserInput) (*model.User, error)`, `Update(id uint, input UpdateUserInput) (*model.User, error)`, `UpdateStatus(id uint, status model.UserStatus, currentUserID uint) error`, and sentinel errors `ErrEmailAlreadyExists`, `ErrCannotDisableSelf`, `ErrUserNotFound` — consumed by `internal/handler/user_handler.go` (Task 4).

- [ ] **Step 1: Write the failing test**

Create `internal/service/user_service_test.go`:

```go
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
```

Note: `setupTestUserRepo(t)` is already defined in `internal/service/auth_service_test.go` (same `service_test` package) and returns a `*repository.UserRepository` connected to the live local Postgres — reuse it rather than duplicating the connection setup.

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/service/... -v -run TestUserService`
Expected: FAIL — `service.NewUserService`, `CreateUserInput`, etc. undefined.

- [ ] **Step 3: Implement**

Create `internal/service/user_service.go`:

```go
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
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/service/... -v -run TestUserService`
Expected: PASS (`TestUserService_Create`, `TestUserService_Update`, `TestUserService_UpdateStatus`)

- [ ] **Step 5: Commit**

```bash
git add internal/service/user_service.go internal/service/user_service_test.go
git commit -m "feat: add user service (create/update/status with business rules)"
```

---

### Task 4: User handler, router wiring, main.go wiring

**Files:**
- Create: `internal/handler/user_handler.go`
- Test: `internal/handler/user_handler_test.go`
- Modify: `internal/router/router.go`
- Modify: `cmd/server/main.go`

**Interfaces:**
- Consumes: `service.UserService`/`CreateUserInput`/`UpdateUserInput` (Task 3), `repository.UserListFilter` (Task 2), `middleware.RequireRole` (Task 1), `middleware.ContextUserIDKey` (existing), `response.Success`/`Error` (existing).
- Produces: `handler.UserHandler` with `NewUserHandler(userService *service.UserService) *UserHandler`, `List`, `Create`, `Update`, `UpdateStatus` (all `func(c *gin.Context)`) — wired into `router.Deps.UserHandler` (new field alongside the existing `JWTSecret`/`AuthHandler`/`AppHandler`).

- [ ] **Step 1: Write the failing end-to-end test**

Create `internal/handler/user_handler_test.go`:

```go
package handler_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"beetleshield-backend/internal/config"
	"beetleshield-backend/internal/db"
	"beetleshield-backend/internal/handler"
	"beetleshield-backend/internal/model"
	"beetleshield-backend/internal/pkg/hash"
	"beetleshield-backend/internal/repository"
	"beetleshield-backend/internal/router"
	"beetleshield-backend/internal/service"
)

func setupUserRouter(t *testing.T) (*httptest.Server, string, string, func()) {
	t.Helper()
	cfg := &config.Config{
		DBHost: "localhost", DBPort: "5432",
		DBUser: "root", DBPassword: "root",
		DBName: "beetleshield", DBSSLMode: "disable",
		JWTSecret: "test-secret", JWTExpireHours: 1,
	}
	database, err := db.Connect(cfg)
	if err != nil {
		t.Fatalf("Connect() error = %v (is Postgres running?)", err)
	}
	if err := db.Migrate(database); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}

	userRepo := repository.NewUserRepository(database)

	hashed, _ := hash.HashPassword("Password123!")
	adminUser := model.User{
		Name: "用户接口管理员", Email: "userhandler-admin@beetleshield.com",
		PasswordHash: hashed, Role: model.RoleAdmin, Status: model.UserStatusActive,
	}
	userRepo.DeleteByEmail(adminUser.Email)
	if err := userRepo.Create(&adminUser); err != nil {
		t.Fatalf("create admin user: %v", err)
	}

	auditorUser := model.User{
		Name: "用户接口审计员", Email: "userhandler-auditor@beetleshield.com",
		PasswordHash: hashed, Role: model.RoleAuditor, Status: model.UserStatusActive,
	}
	userRepo.DeleteByEmail(auditorUser.Email)
	if err := userRepo.Create(&auditorUser); err != nil {
		t.Fatalf("create auditor user: %v", err)
	}

	authService := service.NewAuthService(userRepo, cfg.JWTSecret, cfg.JWTExpireHours)
	adminToken, _, err := authService.Login(adminUser.Email, "Password123!")
	if err != nil {
		t.Fatalf("admin Login() error = %v", err)
	}
	auditorToken, _, err := authService.Login(auditorUser.Email, "Password123!")
	if err != nil {
		t.Fatalf("auditor Login() error = %v", err)
	}
	authHandler := handler.NewAuthHandler(authService)

	userService := service.NewUserService(userRepo)
	userHandler := handler.NewUserHandler(userService)

	r := router.New(router.Deps{
		JWTSecret:   cfg.JWTSecret,
		AuthHandler: authHandler,
		UserHandler: userHandler,
	})
	srv := httptest.NewServer(r)

	cleanup := func() {
		userRepo.DeleteByEmail(adminUser.Email)
		userRepo.DeleteByEmail(auditorUser.Email)
		database.Unscoped().Where("email LIKE ?", "userhandler-created-%@beetleshield.com").Delete(&model.User{})
		srv.Close()
	}
	return srv, adminToken, auditorToken, cleanup
}

func TestUserCreateListUpdateStatus_AsAdmin(t *testing.T) {
	srv, adminToken, _, cleanup := setupUserRouter(t)
	defer cleanup()

	body, _ := json.Marshal(map[string]string{
		"name": "新建开发者", "email": "userhandler-created-1@beetleshield.com",
		"password": "Password123!", "role": "developer", "department": "研发部",
	})
	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/users", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+adminToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("create request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("create status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var createResp struct {
		Data model.User `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&createResp); err != nil {
		t.Fatalf("decode create response: %v", err)
	}
	userID := createResp.Data.ID
	if userID == 0 {
		t.Fatal("expected non-zero user ID")
	}

	listReq, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/users?role=developer", nil)
	listReq.Header.Set("Authorization", "Bearer "+adminToken)
	listResp, err := http.DefaultClient.Do(listReq)
	if err != nil {
		t.Fatalf("list request: %v", err)
	}
	defer listResp.Body.Close()
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("list status = %d, want %d", listResp.StatusCode, http.StatusOK)
	}

	updateBody, _ := json.Marshal(map[string]string{"department": "安全部"})
	updateReq, _ := http.NewRequest(http.MethodPatch, fmt.Sprintf("%s/api/v1/users/%d", srv.URL, userID), bytes.NewReader(updateBody))
	updateReq.Header.Set("Content-Type", "application/json")
	updateReq.Header.Set("Authorization", "Bearer "+adminToken)
	updateResp, err := http.DefaultClient.Do(updateReq)
	if err != nil {
		t.Fatalf("update request: %v", err)
	}
	defer updateResp.Body.Close()
	if updateResp.StatusCode != http.StatusOK {
		t.Fatalf("update status = %d, want %d", updateResp.StatusCode, http.StatusOK)
	}

	statusBody, _ := json.Marshal(map[string]string{"status": "disabled"})
	statusReq, _ := http.NewRequest(http.MethodPatch, fmt.Sprintf("%s/api/v1/users/%d/status", srv.URL, userID), bytes.NewReader(statusBody))
	statusReq.Header.Set("Content-Type", "application/json")
	statusReq.Header.Set("Authorization", "Bearer "+adminToken)
	statusResp, err := http.DefaultClient.Do(statusReq)
	if err != nil {
		t.Fatalf("status request: %v", err)
	}
	defer statusResp.Body.Close()
	if statusResp.StatusCode != http.StatusOK {
		t.Fatalf("status update status = %d, want %d", statusResp.StatusCode, http.StatusOK)
	}
}

func TestUserRoutes_RequireAdminRole(t *testing.T) {
	srv, _, auditorToken, cleanup := setupUserRouter(t)
	defer cleanup()

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/users", nil)
	req.Header.Set("Authorization", "Bearer "+auditorToken)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("list request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
}

func TestUserCreate_DuplicateEmailConflict(t *testing.T) {
	srv, adminToken, _, cleanup := setupUserRouter(t)
	defer cleanup()

	body, _ := json.Marshal(map[string]string{
		"name": "重复用户", "email": "userhandler-created-2@beetleshield.com",
		"password": "Password123!", "role": "developer",
	})

	for i := 0; i < 2; i++ {
		req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/users", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Authorization", "Bearer "+adminToken)
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("create request %d: %v", i, err)
		}
		resp.Body.Close()
		if i == 0 && resp.StatusCode != http.StatusOK {
			t.Fatalf("first create status = %d, want %d", resp.StatusCode, http.StatusOK)
		}
		if i == 1 && resp.StatusCode != http.StatusConflict {
			t.Fatalf("second create status = %d, want %d", resp.StatusCode, http.StatusConflict)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/handler/... -v -run TestUser`
Expected: FAIL — package doesn't compile (`handler.NewUserHandler`, `router.Deps.UserHandler` undefined).

- [ ] **Step 3: Implement the user handler**

Create `internal/handler/user_handler.go`:

```go
package handler

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"beetleshield-backend/internal/middleware"
	"beetleshield-backend/internal/model"
	"beetleshield-backend/internal/pkg/response"
	"beetleshield-backend/internal/repository"
	"beetleshield-backend/internal/service"
)

type UserHandler struct {
	userService *service.UserService
}

func NewUserHandler(userService *service.UserService) *UserHandler {
	return &UserHandler{userService: userService}
}

var validUserRoles = map[model.UserRole]bool{
	model.RoleAdmin:     true,
	model.RoleDeveloper: true,
	model.RoleAuditor:   true,
}

var validUserStatuses = map[model.UserStatus]bool{
	model.UserStatusActive:   true,
	model.UserStatusDisabled: true,
}

func (h *UserHandler) List(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("pageSize", "10"))

	filter := repository.UserListFilter{
		Search:   c.Query("search"),
		Role:     c.Query("role"),
		Page:     page,
		PageSize: pageSize,
	}

	users, total, err := h.userService.List(filter)
	if err != nil {
		response.Error(c, http.StatusInternalServerError, 50005, "查询用户列表失败")
		return
	}

	response.Success(c, http.StatusOK, gin.H{
		"items": users,
		"total": total,
	})
}

type createUserRequest struct {
	Name       string         `json:"name" binding:"required"`
	Email      string         `json:"email" binding:"required,email"`
	Password   string         `json:"password" binding:"required,min=8"`
	Role       model.UserRole `json:"role" binding:"required"`
	Department string         `json:"department"`
}

func (h *UserHandler) Create(c *gin.Context) {
	var req createUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, 40007, err.Error())
		return
	}
	if !validUserRoles[req.Role] {
		response.Error(c, http.StatusBadRequest, 40008, "无效的用户角色")
		return
	}

	user, err := h.userService.Create(service.CreateUserInput{
		Name:       req.Name,
		Email:      req.Email,
		Password:   req.Password,
		Role:       req.Role,
		Department: req.Department,
	})
	if err != nil {
		if errors.Is(err, service.ErrEmailAlreadyExists) {
			response.Error(c, http.StatusConflict, 40901, "邮箱已被使用")
			return
		}
		response.Error(c, http.StatusInternalServerError, 50006, "创建用户失败")
		return
	}

	response.Success(c, http.StatusOK, user)
}

type updateUserRequest struct {
	Name       *string         `json:"name"`
	Department *string         `json:"department"`
	Role       *model.UserRole `json:"role"`
}

func (h *UserHandler) Update(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		response.Error(c, http.StatusBadRequest, 40009, "非法的用户 ID")
		return
	}

	var req updateUserRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, 40007, err.Error())
		return
	}
	if req.Role != nil && !validUserRoles[*req.Role] {
		response.Error(c, http.StatusBadRequest, 40008, "无效的用户角色")
		return
	}

	user, err := h.userService.Update(uint(id), service.UpdateUserInput{
		Name:       req.Name,
		Department: req.Department,
		Role:       req.Role,
	})
	if err != nil {
		if errors.Is(err, service.ErrUserNotFound) {
			response.Error(c, http.StatusNotFound, 40403, "用户不存在")
			return
		}
		response.Error(c, http.StatusInternalServerError, 50007, "更新用户失败")
		return
	}

	response.Success(c, http.StatusOK, user)
}

type updateUserStatusRequest struct {
	Status model.UserStatus `json:"status" binding:"required"`
}

func (h *UserHandler) UpdateStatus(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		response.Error(c, http.StatusBadRequest, 40009, "非法的用户 ID")
		return
	}

	var req updateUserStatusRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, 40007, err.Error())
		return
	}
	if !validUserStatuses[req.Status] {
		response.Error(c, http.StatusBadRequest, 40010, "无效的用户状态")
		return
	}

	currentUserID := c.GetUint(middleware.ContextUserIDKey)

	if err := h.userService.UpdateStatus(uint(id), req.Status, currentUserID); err != nil {
		switch {
		case errors.Is(err, service.ErrUserNotFound):
			response.Error(c, http.StatusNotFound, 40403, "用户不存在")
		case errors.Is(err, service.ErrCannotDisableSelf):
			response.Error(c, http.StatusForbidden, 40303, "不能禁用自己的账号")
		default:
			response.Error(c, http.StatusInternalServerError, 50008, "更新用户状态失败")
		}
		return
	}

	response.Success(c, http.StatusOK, nil)
}
```

- [ ] **Step 4: Wire the `/users` routes into the router**

Modify `internal/router/router.go` — add a `UserHandler` field to `Deps` and a new `/users` group. Full new file content:

```go
package router

import (
	"github.com/gin-gonic/gin"

	"beetleshield-backend/internal/handler"
	"beetleshield-backend/internal/middleware"
	"beetleshield-backend/internal/model"
)

type Deps struct {
	JWTSecret   string
	AuthHandler *handler.AuthHandler
	AppHandler  *handler.AppHandler
	UserHandler *handler.UserHandler
}

func New(deps Deps) *gin.Engine {
	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery(), middleware.CORS())

	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	v1 := r.Group("/api/v1")
	{
		auth := v1.Group("/auth")
		{
			auth.POST("/login", deps.AuthHandler.Login)
			auth.GET("/me", middleware.JWTAuth(deps.JWTSecret), deps.AuthHandler.Me)
		}

		apps := v1.Group("/apps")
		apps.Use(middleware.JWTAuth(deps.JWTSecret))
		{
			apps.POST("/upload", deps.AppHandler.Upload)
			apps.GET("", deps.AppHandler.List)
			apps.GET("/:id", deps.AppHandler.Get)
			apps.DELETE("/:id", deps.AppHandler.Delete)
			apps.GET("/:id/download-url", deps.AppHandler.DownloadURL)
		}

		users := v1.Group("/users")
		users.Use(middleware.JWTAuth(deps.JWTSecret), middleware.RequireRole(model.RoleAdmin))
		{
			users.GET("", deps.UserHandler.List)
			users.POST("", deps.UserHandler.Create)
			users.PATCH("/:id", deps.UserHandler.Update)
			users.PATCH("/:id/status", deps.UserHandler.UpdateStatus)
		}
	}

	return r
}
```

Note: this step intentionally does NOT yet add `RequireRole` to the `apps` write routes — that's Task 5, kept separate so it gets its own review gate given it changes already-shipped, already-tested behavior.

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/handler/... -v -run TestUser`
Expected: PASS (`TestUserCreateListUpdateStatus_AsAdmin`, `TestUserRoutes_RequireAdminRole`, `TestUserCreate_DuplicateEmailConflict`)

- [ ] **Step 6: Wire `UserService`/`UserHandler` into `main.go`**

Modify `cmd/server/main.go` — full new file content:

```go
package main

import (
	"context"
	"log"

	"beetleshield-backend/internal/config"
	"beetleshield-backend/internal/db"
	"beetleshield-backend/internal/handler"
	"beetleshield-backend/internal/pkg/storage"
	"beetleshield-backend/internal/repository"
	"beetleshield-backend/internal/router"
	"beetleshield-backend/internal/service"
)

func main() {
	cfg, err := config.Load(".env")
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	database, err := db.Connect(cfg)
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}

	if err := db.Migrate(database); err != nil {
		log.Fatalf("failed to migrate database: %v", err)
	}

	if err := db.SeedAdmin(database, cfg.AdminEmail, cfg.AdminPassword); err != nil {
		log.Fatalf("failed to seed admin account: %v", err)
	}

	storageClient, err := storage.NewMinioStorage(cfg.MinioEndpoint, cfg.MinioAccessKey, cfg.MinioSecretKey, cfg.MinioBucket, cfg.MinioUseSSL)
	if err != nil {
		log.Fatalf("failed to init storage client: %v", err)
	}
	if err := storageClient.EnsureBucket(context.Background()); err != nil {
		log.Fatalf("failed to ensure minio bucket: %v", err)
	}

	userRepo := repository.NewUserRepository(database)
	authService := service.NewAuthService(userRepo, cfg.JWTSecret, cfg.JWTExpireHours)
	authHandler := handler.NewAuthHandler(authService)

	userService := service.NewUserService(userRepo)
	userHandler := handler.NewUserHandler(userService)

	appRepo := repository.NewAppRepository(database)
	appService := service.NewAppService(appRepo, storageClient, cfg.MaxUploadSizeMB)
	appHandler := handler.NewAppHandler(appService)

	r := router.New(router.Deps{
		JWTSecret:   cfg.JWTSecret,
		AuthHandler: authHandler,
		AppHandler:  appHandler,
		UserHandler: userHandler,
	})

	if err := r.Run(":" + cfg.ServerPort); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}
```

- [ ] **Step 7: Manually verify with curl**

```bash
go run ./cmd/server &
sleep 1
TOKEN=$(curl -s -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@beetleshield.com","password":"ChangeMe123!"}' | jq -r '.data.token')
curl -s http://localhost:8080/api/v1/users -H "Authorization: Bearer $TOKEN"
kill %1
```

Expected: JSON with `"code":0` and a `data.items` array containing at least the seeded admin user.

- [ ] **Step 8: Commit**

```bash
git add internal/handler/user_handler.go internal/handler/user_handler_test.go internal/router/router.go cmd/server/main.go
git commit -m "feat: wire user management endpoints through router and main"
```

---

### Task 5: Retrofit RBAC onto existing app-management write routes

**Files:**
- Modify: `internal/router/router.go`
- Modify: `internal/handler/app_handler_test.go`

**Interfaces:**
- Consumes: `middleware.RequireRole` (Task 1), existing `router.Deps`/`handler.AppHandler` (unchanged shapes).
- Produces: nothing new — this task only changes route wiring and adds regression coverage.

- [ ] **Step 1: Modify the existing app-handler test's setup helper to also produce an auditor-role token**

Modify `internal/handler/app_handler_test.go` — replace the existing `setupFullRouter` function (currently returns `(*httptest.Server, string, func())`) with this version (returns an additional auditor token):

```go
func setupFullRouter(t *testing.T) (*httptest.Server, string, string, func()) {
	t.Helper()
	cfg := &config.Config{
		DBHost: "localhost", DBPort: "5432",
		DBUser: "root", DBPassword: "root",
		DBName: "beetleshield", DBSSLMode: "disable",
		JWTSecret: "test-secret", JWTExpireHours: 1,
		MaxUploadSizeMB: 10,
	}
	database, err := db.Connect(cfg)
	if err != nil {
		t.Fatalf("Connect() error = %v (is `make dev-up` running?)", err)
	}
	if err := db.Migrate(database); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}

	userRepo := repository.NewUserRepository(database)
	hashed, _ := hash.HashPassword("Password123!")
	testUser := model.User{
		Name: "应用接口测试用户", Email: "apphandler-test@beetleshield.com",
		PasswordHash: hashed, Role: model.RoleDeveloper, Status: model.UserStatusActive,
	}
	userRepo.DeleteByEmail(testUser.Email)
	if err := userRepo.Create(&testUser); err != nil {
		t.Fatalf("create test user: %v", err)
	}

	auditorUser := model.User{
		Name: "应用接口审计员", Email: "apphandler-auditor@beetleshield.com",
		PasswordHash: hashed, Role: model.RoleAuditor, Status: model.UserStatusActive,
	}
	userRepo.DeleteByEmail(auditorUser.Email)
	if err := userRepo.Create(&auditorUser); err != nil {
		t.Fatalf("create auditor user: %v", err)
	}

	authService := service.NewAuthService(userRepo, cfg.JWTSecret, cfg.JWTExpireHours)
	token, _, err := authService.Login(testUser.Email, "Password123!")
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	auditorToken, _, err := authService.Login(auditorUser.Email, "Password123!")
	if err != nil {
		t.Fatalf("auditor Login() error = %v", err)
	}
	authHandler := handler.NewAuthHandler(authService)

	st, err := storage.NewMinioStorage("localhost:9000", "admin", "yuan801200", "test-bucket", false)
	if err != nil {
		t.Fatalf("NewMinioStorage() error = %v", err)
	}
	if err := st.EnsureBucket(context.Background()); err != nil {
		t.Fatalf("EnsureBucket() error = %v", err)
	}
	appRepo := repository.NewAppRepository(database)
	appService := service.NewAppService(appRepo, st, cfg.MaxUploadSizeMB)
	appHandler := handler.NewAppHandler(appService)

	r := router.New(router.Deps{
		JWTSecret:   cfg.JWTSecret,
		AuthHandler: authHandler,
		AppHandler:  appHandler,
	})
	srv := httptest.NewServer(r)

	cleanup := func() {
		userRepo.DeleteByEmail(testUser.Email)
		userRepo.DeleteByEmail(auditorUser.Email)
		database.Unscoped().Where("package_name LIKE ?", "com.handlertest.%").Delete(&model.App{})
		srv.Close()
	}
	return srv, token, auditorToken, cleanup
}
```

Update the two existing call sites in the same file to match the new 4-value return:
- In `TestAppUploadListGetDownloadDelete`, change `srv, token, cleanup := setupFullRouter(t)` to `srv, token, _, cleanup := setupFullRouter(t)`
- In `TestAppList_RequiresAuth`, change `srv, _, cleanup := setupFullRouter(t)` to `srv, _, _, cleanup := setupFullRouter(t)`

- [ ] **Step 2: Write the failing RBAC regression test**

Append to `internal/handler/app_handler_test.go`:

```go
func TestAppWriteRoutes_RequireAdminOrDeveloperRole(t *testing.T) {
	srv, _, auditorToken, cleanup := setupFullRouter(t)
	defer cleanup()

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	if err := w.WriteField("tag", "tool"); err != nil {
		t.Fatalf("WriteField(tag): %v", err)
	}
	if err := w.WriteField("packageName", "com.handlertest.rbac"); err != nil {
		t.Fatalf("WriteField(packageName): %v", err)
	}
	if err := w.WriteField("version", "1.0.0"); err != nil {
		t.Fatalf("WriteField(version): %v", err)
	}
	part, err := w.CreateFormFile("file", "rbac.aab")
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	if _, err := part.Write([]byte("rbac test content")); err != nil {
		t.Fatalf("write part: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}

	uploadReq, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/apps/upload", &buf)
	uploadReq.Header.Set("Content-Type", w.FormDataContentType())
	uploadReq.Header.Set("Authorization", "Bearer "+auditorToken)
	uploadResp, err := http.DefaultClient.Do(uploadReq)
	if err != nil {
		t.Fatalf("upload request: %v", err)
	}
	defer uploadResp.Body.Close()
	if uploadResp.StatusCode != http.StatusForbidden {
		t.Fatalf("upload status = %d, want %d", uploadResp.StatusCode, http.StatusForbidden)
	}

	listReq, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/apps", nil)
	listReq.Header.Set("Authorization", "Bearer "+auditorToken)
	listResp, err := http.DefaultClient.Do(listReq)
	if err != nil {
		t.Fatalf("list request: %v", err)
	}
	defer listResp.Body.Close()
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("list status = %d, want %d (read routes must stay open to auditor)", listResp.StatusCode, http.StatusOK)
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/handler/... -v -run TestAppWriteRoutes_RequireAdminOrDeveloperRole`
Expected: FAIL — the auditor account currently gets 200 (or another non-403 status) on upload, since `RequireRole` isn't yet applied to `/apps/upload`.

- [ ] **Step 4: Add `RequireRole` to the three app-management write routes**

Modify `internal/router/router.go` — full new file content:

```go
package router

import (
	"github.com/gin-gonic/gin"

	"beetleshield-backend/internal/handler"
	"beetleshield-backend/internal/middleware"
	"beetleshield-backend/internal/model"
)

type Deps struct {
	JWTSecret   string
	AuthHandler *handler.AuthHandler
	AppHandler  *handler.AppHandler
	UserHandler *handler.UserHandler
}

func New(deps Deps) *gin.Engine {
	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery(), middleware.CORS())

	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	v1 := r.Group("/api/v1")
	{
		auth := v1.Group("/auth")
		{
			auth.POST("/login", deps.AuthHandler.Login)
			auth.GET("/me", middleware.JWTAuth(deps.JWTSecret), deps.AuthHandler.Me)
		}

		writeRoles := middleware.RequireRole(model.RoleAdmin, model.RoleDeveloper)

		apps := v1.Group("/apps")
		apps.Use(middleware.JWTAuth(deps.JWTSecret))
		{
			apps.POST("/upload", writeRoles, deps.AppHandler.Upload)
			apps.GET("", deps.AppHandler.List)
			apps.GET("/:id", deps.AppHandler.Get)
			apps.DELETE("/:id", writeRoles, deps.AppHandler.Delete)
			apps.GET("/:id/download-url", writeRoles, deps.AppHandler.DownloadURL)
		}

		users := v1.Group("/users")
		users.Use(middleware.JWTAuth(deps.JWTSecret), middleware.RequireRole(model.RoleAdmin))
		{
			users.GET("", deps.UserHandler.List)
			users.POST("", deps.UserHandler.Create)
			users.PATCH("/:id", deps.UserHandler.Update)
			users.PATCH("/:id/status", deps.UserHandler.UpdateStatus)
		}
	}

	return r
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/handler/... -v`
Expected: PASS — all handler tests, including `TestAppWriteRoutes_RequireAdminOrDeveloperRole` (new), `TestAppUploadListGetDownloadDelete` and `TestAppList_RequiresAuth` (unaffected — the test user in those has `RoleDeveloper`, still allowed), and all `TestUser*`/`TestLogin*` tests.

- [ ] **Step 6: Run the full project test suite**

```bash
go test ./... -count=1 -v
```

Expected: every package reports `ok`, no failures anywhere in the repo (config, db, middleware, pkg/hash, pkg/jwtutil, pkg/manifest, pkg/response, pkg/storage, repository, service, handler).

- [ ] **Step 7: Commit**

```bash
git add internal/router/router.go internal/handler/app_handler_test.go
git commit -m "feat: retrofit RBAC onto app-management write routes"
```

---

## Post-plan note

This completes sub-project two (user management + RBAC). The next sub-projects, in the order recorded in the base design spec, are: strategy center, hardening pipeline (engine integration), reports, log audit, and the dashboard aggregation endpoints — each should go through its own brainstorming → spec → plan cycle rather than being bolted onto this one.
