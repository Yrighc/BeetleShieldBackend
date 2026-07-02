# BeetleShield Backend — Audit Log System Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a read-only audit trail of key write operations (login, app upload/delete, hardening task creation, strategy save, user create/update/status-change) to the already-merged BeetleShield backend, queryable by any authenticated role via `GET /api/v1/audit-logs`.

**Architecture:** Same `handler → service → repository → model` layering as every other module. A new `AuditService` is injected as a dependency into the five existing services that need to emit audit records (`AuthService`, `AppService`, `HardeningService`, `StrategyService`, `UserService`) — each of those calls `auditService.Record(...)` once, after its own primary write succeeds. `AuditService.Record` never returns an error and never panics: a failed audit write is logged to stdout and otherwise swallowed, so a transient audit-table problem can never block or roll back a real business operation (same "best-effort, log-and-continue" pattern already used for MinIO cleanup in the hardening worker).

**Tech Stack:** Same as the existing codebase — Go, Gin, GORM/PostgreSQL, no new dependencies. `audit_logs` gets no FK constraints, consistent with the rest of the schema.

Reference spec: [`docs/superpowers/specs/2026-07-02-backend-audit-log-design.md`](../specs/2026-07-02-backend-audit-log-design.md)

## Global Constraints

- Module name: `beetleshield-backend`. API prefix `/api/v1`; every response uses `{code int, message string, data any}` (code `0` = success) via `internal/pkg/response`.
- Local dev Postgres: `root`/`root`@`localhost:5432`/`beetleshield` (pre-existing `pg12-dev` container — do not run `make dev-up`/`docker compose up`). The shared DB is not pristine; scope test data/assertions with unique emails/prefixes per test, not table-wide counts, as established in every prior sub-project.
- Route: `GET /audit-logs` → any authenticated role (`admin`/`developer`/`auditor`), just `JWTAuth`, no `RequireRole`.
- `audit_logs` has no foreign keys. `ActorUserID`/`TargetID` are plain `uint` columns.
- `AuditService.Record` is fire-and-forget: signature is `func (s *AuditService) Record(input RecordAuditInput)` — no returned error. Internally it calls the repository and, on error, does `log.Printf("audit: failed to record %s: %v", input.Action, err)` and returns.
- Only login records both success and failure. Every other action records **only on success** — no audit rows for validation failures (duplicate email, invalid dex level, etc.).
- `Detail` is a short fixed-format string per action (see Task 4/5 below for exact wording) — no field-level diffing.
- Every retrofitted service method gets its actor/IP threaded from the handler via `c.GetUint(middleware.ContextUserIDKey)` / `c.ClientIP()`, following the exact pattern already used for `CreatedBy`/`UpdatedBy` elsewhere in this codebase.

---

## File Structure

```
internal/
├── model/
│   └── audit.go                     (new)
├── db/
│   ├── db.go                        (modify — add &model.AuditLog{} to Migrate)
│   └── db_test.go                   (modify — append TestMigrate_AuditLogsTable)
├── repository/
│   ├── audit_repository.go          (new)
│   └── audit_repository_test.go     (new)
├── service/
│   ├── audit_service.go             (new)
│   ├── audit_service_test.go        (new)
│   ├── auth_service.go              (modify — Login gains ip param + audit calls)
│   ├── auth_service_test.go         (modify — call sites)
│   ├── app_service.go               (modify — Upload/Delete gain IP/actor + audit calls)
│   ├── app_service_test.go          (modify — call sites)
│   ├── hardening_service.go         (modify — Create gains IP + audit call)
│   ├── hardening_service_test.go    (modify — call sites)
│   ├── strategy_service.go          (modify — Save gains ip param + audit call)
│   ├── strategy_service_test.go     (modify — call sites)
│   ├── user_service.go              (modify — Create/Update/UpdateStatus gain IP/actor + audit calls)
│   └── user_service_test.go         (modify — call sites)
├── handler/
│   ├── audit_handler.go             (new)
│   ├── audit_handler_test.go        (new)
│   ├── auth_handler.go              (modify — pass c.ClientIP())
│   ├── auth_handler_test.go         (modify — constructor call site)
│   ├── app_handler.go               (modify — pass actor/IP)
│   ├── app_handler_test.go          (modify — constructor call site)
│   ├── hardening_handler.go         (modify — pass c.ClientIP())
│   ├── hardening_handler_test.go    (modify — constructor call sites)
│   ├── strategy_handler.go          (modify — pass c.ClientIP())
│   ├── strategy_handler_test.go     (modify — constructor call sites)
│   ├── user_handler.go              (modify — pass actor/IP)
│   └── user_handler_test.go         (modify — constructor call site)
└── router/
    └── router.go                    (modify — /audit-logs group)
cmd/server/main.go                   (modify — wire AuditRepository/Service/Handler + inject into other 5 services)
```

---

### Task 1: Audit log model, migration, repository

**Files:**
- Create: `internal/model/audit.go`
- Modify: `internal/db/db.go`, `internal/db/db_test.go`
- Create: `internal/repository/audit_repository.go`, `internal/repository/audit_repository_test.go`

**Interfaces:**
- Produces: `model.AuditAction` (9 constants), `model.AuditLog`, `repository.AuditListFilter`, `repository.NewAuditRepository`, `(*AuditRepository).Record`, `(*AuditRepository).List` — consumed by `internal/service/audit_service.go` (Task 2).

- [ ] **Step 1: Write the model**

Create `internal/model/audit.go`:

```go
package model

import "time"

type AuditAction string

const (
	AuditActionLoginSuccess     AuditAction = "auth.login.success"
	AuditActionLoginFailure     AuditAction = "auth.login.failure"
	AuditActionAppUpload        AuditAction = "app.upload"
	AuditActionAppDelete        AuditAction = "app.delete"
	AuditActionHardeningCreate  AuditAction = "hardening_task.create"
	AuditActionStrategySave     AuditAction = "strategy.save"
	AuditActionUserCreate       AuditAction = "user.create"
	AuditActionUserUpdate       AuditAction = "user.update"
	AuditActionUserStatusChange AuditAction = "user.update_status"
)

// AuditLog is intentionally FK-free (see internal/db/db.go): ActorUserID and
// TargetID are plain columns, not GORM associations. ActorEmail is a
// deliberate denormalized snapshot — a failed login attempt against a
// nonexistent email has no real ActorUserID to point at, but the audit trail
// still needs to say which email was tried.
type AuditLog struct {
	ID          uint        `gorm:"primaryKey" json:"id"`
	ActorUserID uint        `gorm:"index" json:"actorUserId"`
	ActorEmail  string      `gorm:"size:255" json:"actorEmail"`
	Action      AuditAction `gorm:"size:60;index" json:"action"`
	TargetType  string      `gorm:"size:30" json:"targetType"`
	TargetID    uint        `json:"targetId"`
	Detail      string      `gorm:"size:255" json:"detail"`
	IP          string      `gorm:"size:64" json:"ip"`
	Success     bool        `json:"success"`
	CreatedAt   time.Time   `gorm:"index" json:"createdAt"`
}

func (AuditLog) TableName() string {
	return "audit_logs"
}
```

- [ ] **Step 2: Write the failing migration test**

Append to `internal/db/db_test.go` (follow the exact pattern of the existing `TestMigrate_*` tests in that file — read the file first to match its setup helper):

```go
func TestMigrate_AuditLogsTable(t *testing.T) {
	database := setupTestDB(t) // reuse whatever the file's existing tests use to get a connected+migrated *gorm.DB
	if !database.Migrator().HasTable(&model.AuditLog{}) {
		t.Fatal("expected audit_logs table to exist after Migrate()")
	}
	if database.Migrator().HasConstraint(&model.AuditLog{}, "ActorUserID") {
		t.Fatal("audit_logs.actor_user_id must not have a foreign key constraint")
	}
}
```

Run `go test ./internal/db/... -run TestMigrate_AuditLogsTable` — confirm it fails (table doesn't exist yet).

- [ ] **Step 3: Wire the migration**

In `internal/db/db.go`, add `&model.AuditLog{}` to the `AutoMigrate(...)` call in `Migrate()` (same list that already has `User`, `App`, `Strategy`, `HardeningTask`, `HardeningStep`, `HardeningLog`). Since `DisableForeignKeyConstraintWhenMigrating: true` is already set globally, no extra drop-constraint logic is needed for this table.

Run the test from Step 2 again — confirm it passes.

- [ ] **Step 4: Write the repository**

Create `internal/repository/audit_repository.go`:

```go
package repository

import (
	"time"

	"gorm.io/gorm"

	"beetleshield-backend/internal/model"
)

type AuditListFilter struct {
	ActorUserID uint
	Action      string
	TargetType  string
	Success     *bool
	StartTime   *time.Time
	EndTime     *time.Time
	Page        int
	PageSize    int
}

type AuditRepository struct {
	db *gorm.DB
}

func NewAuditRepository(db *gorm.DB) *AuditRepository {
	return &AuditRepository{db: db}
}

func (r *AuditRepository) Record(log *model.AuditLog) error {
	return r.db.Create(log).Error
}

func (r *AuditRepository) List(filter AuditListFilter) ([]model.AuditLog, int64, error) {
	query := r.db.Model(&model.AuditLog{})

	if filter.ActorUserID != 0 {
		query = query.Where("actor_user_id = ?", filter.ActorUserID)
	}
	if filter.Action != "" {
		query = query.Where("action = ?", filter.Action)
	}
	if filter.TargetType != "" {
		query = query.Where("target_type = ?", filter.TargetType)
	}
	if filter.Success != nil {
		query = query.Where("success = ?", *filter.Success)
	}
	if filter.StartTime != nil {
		query = query.Where("created_at >= ?", *filter.StartTime)
	}
	if filter.EndTime != nil {
		query = query.Where("created_at <= ?", *filter.EndTime)
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
		pageSize = 20
	}

	var logs []model.AuditLog
	err := query.Order("created_at DESC, id DESC").
		Offset((page - 1) * pageSize).
		Limit(pageSize).
		Find(&logs).Error
	return logs, total, err
}
```

- [ ] **Step 5: Write repository tests**

Create `internal/repository/audit_repository_test.go`. Follow the connection/cleanup pattern used by every other `*_repository_test.go` in this package (connect to the local Postgres, `db.Migrate`, scope test rows by a unique marker, clean up in `t.Cleanup`). Cover:
- `Record` then `List` with no filter returns it
- `List` filtering by `Action`, by `TargetType`, by `Success` (both `true` and `false` pointer values), by `StartTime`/`EndTime` range — each isolated to rows created by that test (filter additionally by a unique `IP` or `Detail` marker string per test to avoid cross-test pollution in the shared DB, since `audit_logs` has no natural per-test scoping column like `task_no`/`package_name` elsewhere)
- Pagination: create 3 rows, `PageSize: 2` returns 2 items + `total: 3`

Run `go test ./internal/repository/... -run TestAudit` — confirm green.

---

### Task 2: Audit service

**Files:**
- Create: `internal/service/audit_service.go`, `internal/service/audit_service_test.go`

**Interfaces:**
- Consumes: `repository.AuditRepository`/`AuditListFilter` (Task 1).
- Produces: `service.RecordAuditInput`, `service.NewAuditService`, `(*AuditService).Record`, `(*AuditService).List` — consumed by Task 3 (handler) and Tasks 4/5 (the five retrofitted services).

- [ ] **Step 1: Write the service**

Create `internal/service/audit_service.go`:

```go
package service

import (
	"log"

	"beetleshield-backend/internal/model"
	"beetleshield-backend/internal/repository"
)

type RecordAuditInput struct {
	ActorUserID uint
	ActorEmail  string
	Action      model.AuditAction
	TargetType  string
	TargetID    uint
	Detail      string
	IP          string
	Success     bool
}

type AuditService struct {
	auditRepo *repository.AuditRepository
}

func NewAuditService(auditRepo *repository.AuditRepository) *AuditService {
	return &AuditService{auditRepo: auditRepo}
}

// Record is fire-and-forget by design: audit logging is a side concern, and
// a transient failure writing to audit_logs must never roll back or fail an
// otherwise-successful business operation (app upload, user creation, ...).
// Callers do not check a return value; failures are only visible in the
// server log.
func (s *AuditService) Record(input RecordAuditInput) {
	entry := &model.AuditLog{
		ActorUserID: input.ActorUserID,
		ActorEmail:  input.ActorEmail,
		Action:      input.Action,
		TargetType:  input.TargetType,
		TargetID:    input.TargetID,
		Detail:      input.Detail,
		IP:          input.IP,
		Success:     input.Success,
	}
	if err := s.auditRepo.Record(entry); err != nil {
		log.Printf("audit: failed to record %s: %v", input.Action, err)
	}
}

func (s *AuditService) List(filter repository.AuditListFilter) ([]model.AuditLog, int64, error) {
	return s.auditRepo.List(filter)
}
```

- [ ] **Step 2: Write service tests**

Create `internal/service/audit_service_test.go` (package `service_test`, following this codebase's existing black-box test convention for service tests — check `strategy_service_test.go` for the exact setup pattern: real local Postgres, `db.Migrate`, `repository.NewAuditRepository(database)`). Cover:
- `Record` then `List` round-trip returns the entry with matching fields
- `Record` does not panic and `List` still works normally when given a filter that matches nothing (sanity check, not a fault-injection test — a true DB-failure fault injection isn't practical here since `AuditRepository` has no test-seam for failure the way GORM callback-based fault injection is used elsewhere; if the reviewer subagent judges this insufficient, a `Callback().Create().Before("gorm:create")` fault-injection test mirroring the pattern already used in `hardening_repository_test.go`/`hardening_worker_test.go` is acceptable but not required)

Run `go test ./internal/service/... -run TestAudit` — confirm green.

---

### Task 3: Audit handler, router wiring, main.go wiring (read path only)

**Files:**
- Create: `internal/handler/audit_handler.go`, `internal/handler/audit_handler_test.go`
- Modify: `internal/router/router.go`, `cmd/server/main.go`

**Interfaces:**
- Consumes: `service.AuditService` (Task 2), existing `middleware.JWTAuth`, `response.Success`/`Error`.
- Produces: `handler.AuditHandler` with `NewAuditHandler(auditService *service.AuditService) *AuditHandler`, `List(c *gin.Context)` — wired into `router.Deps.AuditHandler` (new field) and `main.go`.

This task makes `GET /audit-logs` fully functional end-to-end, but does **not** yet wire `AuditService` into the other five services — that's Tasks 4 and 5, kept separate so this task's end state still compiles and is independently testable (the audit log table will just be empty until Task 4/5 land).

- [ ] **Step 1: Write the failing end-to-end test**

Create `internal/handler/audit_handler_test.go`. Follow the exact structure of `internal/handler/strategy_handler_test.go`'s `setupStrategyRouter` (real Postgres connect + migrate, create admin/developer/auditor users via `userRepo`, log in each via `authService.Login` to get tokens, build `router.New(router.Deps{...})` with `httptest.NewServer`). Seed a few `AuditLog` rows directly via `repository.NewAuditRepository(database).Record(...)` (not through any HTTP call, since nothing produces real audit rows yet). Cover:
- `GET /audit-logs` with each of the 3 role tokens returns `200` and the seeded rows in the response `items`/`total` shape
- Query filters (`action`, `targetType`, `success=true`/`false`) narrow the result set correctly
- No token → `401`

Run `go test ./internal/handler/... -run TestAudit` — confirm it fails to compile (handler doesn't exist yet).

- [ ] **Step 2: Write the handler**

Create `internal/handler/audit_handler.go`:

```go
package handler

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"

	"beetleshield-backend/internal/pkg/response"
	"beetleshield-backend/internal/repository"
	"beetleshield-backend/internal/service"
)

type AuditHandler struct {
	auditService *service.AuditService
}

func NewAuditHandler(auditService *service.AuditService) *AuditHandler {
	return &AuditHandler{auditService: auditService}
}

func (h *AuditHandler) List(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("pageSize", "20"))
	actorUserID, _ := strconv.ParseUint(c.DefaultQuery("actorUserId", "0"), 10, 64)

	filter := repository.AuditListFilter{
		ActorUserID: uint(actorUserID),
		Action:      c.Query("action"),
		TargetType:  c.Query("targetType"),
		Page:        page,
		PageSize:    pageSize,
	}

	if successParam := c.Query("success"); successParam != "" {
		success := successParam == "true"
		filter.Success = &success
	}
	if startParam := c.Query("startTime"); startParam != "" {
		t, err := time.Parse(time.RFC3339, startParam)
		if err != nil {
			response.Error(c, http.StatusBadRequest, 40030, "非法的开始时间")
			return
		}
		filter.StartTime = &t
	}
	if endParam := c.Query("endTime"); endParam != "" {
		t, err := time.Parse(time.RFC3339, endParam)
		if err != nil {
			response.Error(c, http.StatusBadRequest, 40031, "非法的结束时间")
			return
		}
		filter.EndTime = &t
	}

	logs, total, err := h.auditService.List(filter)
	if err != nil {
		response.Error(c, http.StatusInternalServerError, 50030, "查询审计日志失败")
		return
	}

	response.Success(c, http.StatusOK, gin.H{
		"items": logs,
		"total": total,
	})
}
```

Run the Step 1 test — confirm it now fails at `router.Deps` (no `AuditHandler` field yet), not at compiling the handler package itself.

- [ ] **Step 3: Wire the router**

In `internal/router/router.go`: add `AuditHandler *handler.AuditHandler` to `Deps`. Add a new route group:

```go
auditLogs := v1.Group("/audit-logs")
auditLogs.Use(middleware.JWTAuth(deps.JWTSecret))
{
	auditLogs.GET("", deps.AuditHandler.List)
}
```

- [ ] **Step 4: Wire main.go**

In `cmd/server/main.go`, after the existing `hardeningRepo := repository.NewHardeningRepository(database)` line, add:

```go
auditRepo := repository.NewAuditRepository(database)
auditService := service.NewAuditService(auditRepo)
auditHandler := handler.NewAuditHandler(auditService)
```

Add `AuditHandler: auditHandler,` to the `router.Deps{...}` literal. (Injecting `auditService` into the other 5 services' constructors happens in Tasks 4/5, not here.)

Run the Step 1 test again — confirm it passes. Run `go build ./...` — confirm the whole module still compiles.

---

### Task 4: Retrofit AuthService and AppService with audit recording

**Files:**
- Modify: `internal/service/auth_service.go`, `internal/service/auth_service_test.go`
- Modify: `internal/service/app_service.go`, `internal/service/app_service_test.go`
- Modify: `internal/handler/auth_handler.go`, `internal/handler/auth_handler_test.go`
- Modify: `internal/handler/app_handler.go`, `internal/handler/app_handler_test.go`
- Modify: `cmd/server/main.go`

**Interfaces:**
- Consumes: `service.AuditService`/`RecordAuditInput` (Task 2).
- Changes signatures: `AuthService.Login(email, password string)` → `Login(email, password, ip string)`; `NewAuthService(...)` gains a trailing `auditService *AuditService` param. `AppService.Delete(ctx, id uint)` → `Delete(ctx, id, actorUserID uint, ip string)`; `UploadInput` gains an `IP string` field; `NewAppService(...)` gains a trailing `auditService *AuditService` param.

- [ ] **Step 1: Retrofit AuthService**

In `internal/service/auth_service.go`:

Add `auditService *AuditService` field to the `AuthService` struct. Change `NewAuthService` to:

```go
func NewAuthService(userRepo *repository.UserRepository, jwtSecret string, jwtExpireHours int, auditService *AuditService) *AuthService {
	return &AuthService{userRepo: userRepo, jwtSecret: jwtSecret, jwtExpireHours: jwtExpireHours, auditService: auditService}
}
```

Change `Login` to take an `ip string` param and record on every exit path. All three failure branches (unknown email, wrong password, disabled account) record identically as a login failure with `ActorUserID: 0` — this is deliberate: don't leak via the audit trail whether the attempted email belongs to a real (if disabled) account:

```go
func (s *AuthService) Login(email, password, ip string) (string, *model.User, error) {
	user, err := s.userRepo.FindByEmail(email)
	if err != nil {
		s.recordLoginFailure(email, ip)
		return "", nil, ErrInvalidCredentials
	}

	if !hash.CheckPassword(user.PasswordHash, password) {
		s.recordLoginFailure(email, ip)
		return "", nil, ErrInvalidCredentials
	}

	if user.Status == model.UserStatusDisabled {
		s.recordLoginFailure(email, ip)
		return "", nil, ErrUserDisabled
	}

	token, err := jwtutil.GenerateToken(s.jwtSecret, user.ID, string(user.Role), s.jwtExpireHours)
	if err != nil {
		return "", nil, err
	}

	_ = s.userRepo.UpdateLastLogin(user.ID)

	s.auditService.Record(RecordAuditInput{
		ActorUserID: user.ID, ActorEmail: user.Email,
		Action: model.AuditActionLoginSuccess, IP: ip, Success: true,
	})

	return token, user, nil
}

func (s *AuthService) recordLoginFailure(email, ip string) {
	s.auditService.Record(RecordAuditInput{
		ActorEmail: email, Action: model.AuditActionLoginFailure, IP: ip, Success: false,
	})
}
```

Update every existing call site of `NewAuthService` and `.Login(...)` to match the new signatures:
- `NewAuthService(...)` call sites (append `, auditSvc` — see Step 5 below for how each test constructs a throwaway `*AuditService`): `cmd/server/main.go:55`, `internal/handler/auth_handler_test.go:47`, `internal/handler/strategy_handler_test.go:56`, `internal/handler/hardening_handler_test.go:149`, `internal/handler/app_handler_test.go:61`, `internal/handler/user_handler_test.go:58`, `internal/service/auth_service_test.go:49`
- `.Login(...)` call sites (append `, ""` for the ip argument — no test in this codebase currently asserts on the recorded IP value, so an empty string is fine everywhere except the new audit-focused tests written in Step 6 below): `internal/handler/auth_handler.go:34` (this one passes `c.ClientIP()` instead, not `""` — see Step 3), `internal/handler/strategy_handler_test.go:57,61`, `internal/handler/hardening_handler_test.go:150,154,158`, `internal/handler/user_handler_test.go:59,63`, `internal/handler/app_handler_test.go:62,66`, `internal/service/auth_service_test.go:52,65,72`

- [ ] **Step 2: Retrofit AppService**

In `internal/service/app_service.go`:

Add `auditService *AuditService` field to `AppService`. Add `IP string` field to `UploadInput`. Change `NewAppService` to:

```go
func NewAppService(appRepo *repository.AppRepository, hardeningRepo *repository.HardeningRepository, storage *storage.MinioStorage, maxUploadSizeMB int64, auditService *AuditService) *AppService {
	return &AppService{appRepo: appRepo, hardeningRepo: hardeningRepo, storage: storage, maxUploadSizeMB: maxUploadSizeMB, auditService: auditService}
}
```

In `Upload`, right after `s.appRepo.Create(app)` succeeds (before the final `return app, nil`), add:

```go
s.auditService.Record(RecordAuditInput{
	ActorUserID: input.UploadedBy, Action: model.AuditActionAppUpload,
	TargetType: "app", TargetID: app.ID, Detail: app.Name + " (" + app.PackageName + ")",
	IP: input.IP, Success: true,
})
```

Change `Delete` to accept the caller's identity (it currently doesn't receive one at all):

```go
func (s *AppService) Delete(ctx context.Context, id uint, actorUserID uint, ip string) error {
	app, err := s.appRepo.FindByID(id)
	if err != nil {
		return ErrAppNotFound
	}

	hasActive, err := s.hardeningRepo.HasActiveTaskForApp(id)
	if err != nil {
		return fmt.Errorf("check active hardening task: %w", err)
	}
	if hasActive {
		return ErrAppHasActiveHardeningTask
	}

	if err := s.appRepo.Delete(id); err != nil {
		return fmt.Errorf("delete app record: %w", err)
	}
	_ = s.storage.DeleteObject(ctx, app.ObjectKey)

	s.auditService.Record(RecordAuditInput{
		ActorUserID: actorUserID, Action: model.AuditActionAppDelete,
		TargetType: "app", TargetID: app.ID, Detail: app.Name + " (" + app.PackageName + ")",
		IP: ip, Success: true,
	})

	return nil
}
```

Update every existing call site:
- `NewAppService(...)`: `cmd/server/main.go:63`, `internal/handler/app_handler_test.go:81`, `internal/service/app_service_test.go:68` — append `, auditSvc`
- `svc.Delete(ctx, id)` → `svc.Delete(ctx, id, 0, "")`: `internal/service/app_service_test.go:87,134` (these are `t.Cleanup` calls where the actor doesn't matter)
- `h.appService.Delete(c.Request.Context(), uint(id))` in `internal/handler/app_handler.go:120` → `h.appService.Delete(c.Request.Context(), uint(id), c.GetUint(middleware.ContextUserIDKey), c.ClientIP())` (this file already imports `middleware` for the same pattern used elsewhere — check the existing imports, `app_handler.go` already has `beetleshield-backend/internal/middleware` imported for `middleware.ContextUserIDKey` in `Upload`)

`UploadInput{...}` literals at the 4 call sites in `internal/service/app_service_test.go` (lines 77, 126, 147, 163) don't need changes — `IP` defaults to `""` when omitted from the struct literal, which is fine for tests that don't assert on it.

- [ ] **Step 3: Update handlers to pass real IP/actor**

`internal/handler/auth_handler.go`: change `token, user, err := h.authService.Login(req.Email, req.Password)` to `token, user, err := h.authService.Login(req.Email, req.Password, c.ClientIP())`.

`internal/handler/app_handler.go`: in `Upload`, add `IP: c.ClientIP(),` to the `service.UploadInput{...}` literal. In `Delete`, change the call as described in Step 2 above.

- [ ] **Step 4: Update main.go wiring**

In `cmd/server/main.go`: move the `auditRepo`/`auditService`/`auditHandler` construction (added in Task 3 Step 4) to occur *before* `authService`/`appService` are constructed (it already needs to, since `hardeningRepo` — a dependency of `appService` — is constructed before `appService` today; just make sure `auditService` exists before its first consumer). Update:
- `service.NewAuthService(userRepo, cfg.JWTSecret, cfg.JWTExpireHours)` → `service.NewAuthService(userRepo, cfg.JWTSecret, cfg.JWTExpireHours, auditService)`
- `service.NewAppService(appRepo, hardeningRepo, storageClient, cfg.MaxUploadSizeMB)` → `service.NewAppService(appRepo, hardeningRepo, storageClient, cfg.MaxUploadSizeMB, auditService)`

Run `go build ./...` — confirm it compiles.

- [ ] **Step 5: Fix every remaining test compile error**

Every handler test file that constructs `service.NewAuthService(...)` or `service.NewAppService(...)` needs a throwaway `*service.AuditService` to pass in. Add this helper once near the top of each affected test file (or reuse if the file already has a similar local helper convention — check first):

```go
func newTestAuditService(database *gorm.DB) *service.AuditService {
	return service.NewAuditService(repository.NewAuditRepository(database))
}
```

Then pass `newTestAuditService(database)` as the new trailing constructor argument at every site listed in Steps 1 and 2 above. Run `go build ./... && go vet ./...` — fix any remaining mismatches until both are clean.

- [ ] **Step 6: Write audit-focused regression tests**

Append to `internal/service/auth_service_test.go`:
- `TestAuthServiceLogin_SuccessRecordsAuditEntry`: log in successfully, then query `auditRepo.List` (or `auditService.List`) filtered by the test's unique email, assert one `AuditActionLoginSuccess` row with `Success: true` and the right `ActorUserID`.
- `TestAuthServiceLogin_FailureRecordsAuditEntryWithoutActorID`: attempt login with a wrong password, assert one `AuditActionLoginFailure` row with `ActorUserID: 0` and `ActorEmail` equal to the attempted email.

Append to `internal/service/app_service_test.go`:
- A test verifying a successful `Upload` produces one `AuditActionAppUpload` row with the right `TargetID`.
- A test verifying a successful `Delete` produces one `AuditActionAppDelete` row.

Run `go test ./internal/service/... ./internal/handler/...` — confirm everything is green.

---

### Task 5: Retrofit HardeningService, StrategyService, UserService with audit recording

**Files:**
- Modify: `internal/service/hardening_service.go`, `internal/service/hardening_service_test.go`
- Modify: `internal/service/strategy_service.go`, `internal/service/strategy_service_test.go`
- Modify: `internal/service/user_service.go`, `internal/service/user_service_test.go`
- Modify: `internal/handler/hardening_handler.go`, `internal/handler/hardening_handler_test.go`
- Modify: `internal/handler/strategy_handler.go`, `internal/handler/strategy_handler_test.go`
- Modify: `internal/handler/user_handler.go`, `internal/handler/user_handler_test.go`
- Modify: `cmd/server/main.go`

**Interfaces:**
- Consumes: `service.AuditService`/`RecordAuditInput` (Task 2).
- Changes signatures: `CreateHardeningTaskInput` gains `IP string`; `NewHardeningService(...)` gains a trailing `auditService *AuditService` param. `StrategyService.Save(input, updatedBy uint)` → `Save(input, updatedBy uint, ip string)`; `NewStrategyService(...)` gains a trailing `auditService *AuditService` param. `CreateUserInput` gains `ActorUserID uint` + `IP string`; `UserService.Update(id, input)` → `Update(id, input, actorUserID uint, ip string)`; `UserService.UpdateStatus(id, status, currentUserID uint)` → `UpdateStatus(id, status, currentUserID uint, ip string)`; `NewUserService(...)` gains a trailing `auditService *AuditService` param.

- [ ] **Step 1: Retrofit HardeningService**

In `internal/service/hardening_service.go`: add `auditService *AuditService` field, add `IP string` to `CreateHardeningTaskInput`, update `NewHardeningService` to take a trailing `auditService *AuditService` param. In `Create`, right after `s.hardeningRepo.CreateTaskWithStepsForApp(...)` succeeds (before the final `return s.Get(task.ID)`), add:

```go
s.auditService.Record(RecordAuditInput{
	ActorUserID: input.CreatedBy, Action: model.AuditActionHardeningCreate,
	TargetType: "hardening_task", TargetID: task.ID, Detail: app.Name + " / " + task.TaskNo,
	IP: input.IP, Success: true,
})
```

(`app` is already in scope from the earlier `s.appRepo.FindByID(input.AppID)` call in this method.)

Update call sites:
- `NewHardeningService(...)`: `cmd/server/main.go`, `internal/handler/hardening_handler_test.go:181`, `internal/service/hardening_service_test.go:110` — append `, auditSvc` (construct via the `newTestAuditService` helper from Task 4 Step 5 in test files; add that same helper to `hardening_service_test.go` if it's a different package/file that doesn't already have it)
- `CreateHardeningTaskInput{...}` literals across `internal/service/hardening_service_test.go` (9 call sites: lines 144, 177, 182, 193, 223, 279, 313, 369) and `internal/handler/hardening_handler.go:41` don't need changes — `IP` defaults to `""` when omitted.
- `internal/handler/hardening_handler.go`: add `IP: c.ClientIP(),` to the `service.CreateHardeningTaskInput{...}` literal in `Create`.

- [ ] **Step 2: Retrofit StrategyService**

In `internal/service/strategy_service.go`: add `auditService *AuditService` field, update `NewStrategyService` to take a trailing `auditService *AuditService` param, change `Save` to `Save(input SaveStrategyInput, updatedBy uint, ip string) (*model.Strategy, error)`. Right after `s.strategyRepo.Save(strategy)` succeeds (before `return strategy, nil`), add:

```go
s.auditService.Record(RecordAuditInput{
	ActorUserID: updatedBy, Action: model.AuditActionStrategySave,
	TargetType: "strategy", TargetID: strategy.ID, Detail: "全局加固策略已更新",
	IP: ip, Success: true,
})
```

Update call sites:
- `NewStrategyService(...)`: `cmd/server/main.go`, `internal/handler/strategy_handler_test.go:68`, `internal/handler/hardening_handler_test.go:179`, `internal/service/strategy_service_test.go` (5 sites: lines 36, 58, 71, 97), `internal/service/hardening_service_test.go:109` — append `, auditSvc`
- `svc.Save(service.SaveStrategyInput{...}, someUint)` call sites in `internal/service/strategy_service_test.go` (lines 73, 80, 87, 99) → append `, ""` for the new `ip` param
- `internal/handler/strategy_handler.go`: `h.strategyService.Save(service.SaveStrategyInput{...}, userID)` → add `, c.ClientIP()` as a third argument

- [ ] **Step 3: Retrofit UserService**

In `internal/service/user_service.go`: add `auditService *AuditService` field, update `NewUserService` to take a trailing `auditService *AuditService` param. Add `ActorUserID uint` and `IP string` fields to `CreateUserInput`. Change `Update` to `Update(id uint, input UpdateUserInput, actorUserID uint, ip string) (*model.User, error)`. Change `UpdateStatus` to `UpdateStatus(id uint, status model.UserStatus, currentUserID uint, ip string) error`.

In `Create`, right after `s.userRepo.Create(user)` succeeds (before `return user, nil`):

```go
s.auditService.Record(RecordAuditInput{
	ActorUserID: input.ActorUserID, Action: model.AuditActionUserCreate,
	TargetType: "user", TargetID: user.ID, Detail: user.Email + " (" + string(user.Role) + ")",
	IP: input.IP, Success: true,
})
```

In `Update`, right after the `if len(updates) > 0 { ... }` block succeeds, before `return s.userRepo.FindByID(id)`:

```go
s.auditService.Record(RecordAuditInput{
	ActorUserID: actorUserID, Action: model.AuditActionUserUpdate,
	TargetType: "user", TargetID: id, Detail: "用户资料已更新",
	IP: ip, Success: true,
})
```

(Record this even when `len(updates) == 0` — an update call with no fields set is still a no-op success path, not worth special-casing.)

In `UpdateStatus`, right after `s.userRepo.UpdateStatus(id, status)` succeeds:

```go
statusLabel := "启用"
if status == model.UserStatusDisabled {
	statusLabel = "禁用"
}
s.auditService.Record(RecordAuditInput{
	ActorUserID: currentUserID, Action: model.AuditActionUserStatusChange,
	TargetType: "user", TargetID: id, Detail: "状态变更为 " + statusLabel,
	IP: ip, Success: true,
})
return nil
```

(Replace the current bare `return s.userRepo.UpdateStatus(id, status)` — capture its error first, only record+return-nil on success, keep returning the error unchanged on failure.)

Update call sites:
- `NewUserService(...)`: `cmd/server/main.go`, `internal/handler/user_handler_test.go:69`, `internal/service/user_service_test.go` (4 sites: lines 12, 42, 76, 108) — append `, auditSvc`
- `CreateUserInput{...}` literals: `internal/handler/user_handler.go:78` needs `ActorUserID: c.GetUint(middleware.ContextUserIDKey), IP: c.ClientIP(),` added to the literal; the 6 literals in `internal/service/user_service_test.go` (lines 17, 31, 47, 81, 117, 125) don't need changes (fields default to zero values)
- `svc.Update(id, input)` call sites in `internal/service/user_service_test.go` (lines 58, 68) → append `, 0, ""`
- `svc.UpdateStatus(id, status, currentUserID)` call sites in `internal/service/user_service_test.go` (lines 89, 100, 133) → append `, ""`
- `internal/handler/user_handler.go`: `h.userService.Update(uint(id), service.UpdateUserInput{...})` → add `, c.GetUint(middleware.ContextUserIDKey), c.ClientIP()`; `h.userService.UpdateStatus(uint(id), req.Status, currentUserID)` → add `, c.ClientIP()`

- [ ] **Step 4: Update main.go wiring**

In `cmd/server/main.go`:
- `service.NewHardeningService(hardeningRepo, appRepo, strategyService, storageClient, cfg.DPTDefaultVMPRules)` → append `, auditService`
- `service.NewStrategyService(strategyRepo)` → `service.NewStrategyService(strategyRepo, auditService)` — and make sure this line still runs *before* `hardeningService` is constructed, since `hardeningService` depends on `strategyService` (check current ordering in the file — `strategyService`/`strategyRepo` are already constructed before `hardeningRepo`/`hardeningService` today)
- `service.NewUserService(userRepo)` → `service.NewUserService(userRepo, auditService)`

Run `go build ./...` — confirm clean.

- [ ] **Step 5: Fix every remaining test compile error**

Same mechanical pass as Task 4 Step 5: every remaining `NewHardeningService`/`NewStrategyService`/`NewUserService` call site in test files needs `newTestAuditService(database)` (or a locally-scoped equivalent — reuse the same helper if the test file is in the same package as one that already has it, otherwise add a copy) appended as the trailing constructor argument. Run `go build ./... && go vet ./...` and iterate until clean.

- [ ] **Step 6: Write audit-focused regression tests**

Mirror Task 4 Step 6's pattern:
- `internal/service/hardening_service_test.go`: successful `Create` produces one `AuditActionHardeningCreate` row.
- `internal/service/strategy_service_test.go`: successful `Save` produces one `AuditActionStrategySave` row; a validation-failure `Save` (bad `DexLevel`) produces none.
- `internal/service/user_service_test.go`: successful `Create` produces one `AuditActionUserCreate` row (and a duplicate-email failure produces none); successful `Update` produces one `AuditActionUserUpdate` row; successful `UpdateStatus` produces one `AuditActionUserStatusChange` row with the right `Detail` (启用/禁用).

- [ ] **Step 7: Full regression run**

Run `go build ./... && go vet ./... && go test ./... -count=1` from the repo root. Every package must pass, including the full `internal/handler`, `internal/service`, `internal/repository`, `internal/worker` suites (none of those three services' retrofits should have broken anything outside audit-log-specific code, but the constructor signature changes ripple through every handler test file that builds a full router — verify none were missed).

---

## Post-plan note

This completes sub-project five (audit log system). The base design spec's remaining backlog — reports (加固报告/安全评分) and the Dashboard aggregation endpoints — are unscheduled; each should go through its own brainstorming → spec → plan cycle before being started, same as this one.
