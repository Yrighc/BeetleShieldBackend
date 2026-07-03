# BeetleShield Backend — Failure Audit Expansion + API Request Log Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** (1) Make `AppService.Upload/Delete`, `HardeningService.Create`, `StrategyService.Save`, `UserService.Create/Update/UpdateStatus` record an audit entry on failure as well as success (same `AuditAction` constants, `Success` field distinguishes), via a single `defer`-based call per method instead of duplicating `Record` at every error branch. (2) Add a brand-new, independent `api_request_logs` subsystem (Gin middleware + table + read-only endpoint) covering every `/api/v1/*` request's method/path/status/latency/clientIP/actorUserID — no request/response bodies, no `/health`. (3) Rewire the frontend's "API 交互审计" tab to the new endpoint and fix two real filtering bugs (level dropdown no-op on 2 tabs; hardcoded 100-row fetch capping search/pagination).

**Architecture:** Same `handler → service → repository → model` layering as every other module for the new `api_request_logs` subsystem. The middleware lives in `internal/middleware` and depends only on a small local `RequestLogRecorder` interface (implemented by `*service.APIRequestLogService`) to avoid `middleware` importing `service`. The 7 failure-audit retrofits are refactors of existing methods only — no new types, just a `defer` + named return values replacing the current "call `Record` once at the end of the success path" pattern.

**Tech Stack:** Same as existing codebase — Go, Gin, GORM/Postgres, no new dependencies.

Reference spec: [`docs/superpowers/specs/2026-07-03-backend-audit-expansion-design.md`](../specs/2026-07-03-backend-audit-expansion-design.md)

## Global Constraints

- Module name: `beetleshield-backend`. API prefix `/api/v1`; unified `{code,message,data}` envelope via `internal/pkg/response`.
- Local dev Postgres: `root`/`root`@`localhost:5432`/`beetleshield` (pre-existing `pg12-dev` container). Shared DB is not pristine — scope test assertions with unique markers, not table-wide counts.
- `api_request_logs` has no FK constraints, consistent with `audit_logs` and the rest of the schema.
- `APIRequestLogService.Record` is fire-and-forget (log-and-swallow on write failure), same contract as `AuditService.Record`.
- The request-log middleware must be registered as the **first** middleware on the `/api/v1` group (before any subgroup's `JWTAuth`/`RequireRole`), so its post-`c.Next()` logging code — which runs after `c.Next()` returns, per Gin's outer-wraps-inner execution order — sees the final response status and any `ContextUserIDKey` set by inner auth middleware.
- `GET /api/v1/api-logs` is readable by any authenticated role (`JWTAuth` only, no `RequireRole`), matching `/audit-logs`.
- The 7 failure-audit retrofits change each method's *internal* control flow (named returns + defer) but not its exported signature — no caller updates needed anywhere.
- `HardeningService.Create` is the one method where `TargetType` legitimately differs by outcome: success keeps the existing `hardening_task`/`task.ID` (already shipped and tested — do not change), failure uses `app`/`input.AppID` (the only target known before a task exists).

---

## File Structure

```
internal/
├── model/
│   └── api_request_log.go          (new)
├── db/
│   └── db.go                       (modify — add &model.APIRequestLog{} to Migrate)
├── middleware/
│   ├── request_log.go               (new)
│   └── request_log_test.go          (new)
├── repository/
│   ├── api_request_log_repository.go       (new)
│   └── api_request_log_repository_test.go  (new)
├── service/
│   ├── api_request_log_service.go       (new)
│   ├── api_request_log_service_test.go  (new)
│   ├── app_service.go                    (modify — Upload/Delete defer-based audit)
│   ├── app_service_test.go               (modify — add failure-path audit tests)
│   ├── hardening_service.go               (modify — Create defer-based audit)
│   ├── hardening_service_test.go          (modify — add failure-path audit tests)
│   ├── strategy_service.go                (modify — Save defer-based audit)
│   ├── strategy_service_test.go           (modify — add failure-path audit tests)
│   ├── user_service.go                    (modify — Create/Update/UpdateStatus defer-based audit)
│   └── user_service_test.go               (modify — add failure-path audit tests)
├── handler/
│   ├── api_request_log_handler.go       (new)
│   └── api_request_log_handler_test.go  (new)
└── router/
    └── router.go                     (modify — v1.Use(RequestLog), /api-logs group)
cmd/server/main.go                    (modify — wire APIRequestLogRepository/Service/Handler)
```

Frontend (`/Users/yrighc/work/hzyz/project/BeetleShieldFrontend`):
```
src/api/apiLogs.ts        (new)
src/pages/Logs.tsx        (modify)
```

---

### Task 1: API request log model, migration, repository

**Files:**
- Create: `internal/model/api_request_log.go`
- Modify: `internal/db/db.go`
- Create: `internal/repository/api_request_log_repository.go`, `internal/repository/api_request_log_repository_test.go`

**Interfaces:**
- Produces: `model.APIRequestLog`, `repository.APIRequestLogListFilter`, `repository.NewAPIRequestLogRepository`, `(*APIRequestLogRepository).Record`, `(*APIRequestLogRepository).List` — consumed by Task 2.

- [ ] **Step 1: Model**

Create `internal/model/api_request_log.go`:

```go
package model

import "time"

// APIRequestLog is intentionally separate from AuditLog: it captures raw
// HTTP traffic metadata (method/path/status/latency) for every /api/v1/*
// request regardless of whether the underlying handler considers the
// operation a business-significant "audit" event. No FK constraints, no
// request/response body (avoids logging secrets and keeps storage small).
type APIRequestLog struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	Method      string    `gorm:"size:10;index" json:"method"`
	Path        string    `gorm:"size:255;index" json:"path"`
	Status      int       `gorm:"index" json:"status"`
	LatencyMS   int64     `json:"latencyMs"`
	ClientIP    string    `gorm:"size:64" json:"clientIp"`
	ActorUserID uint      `gorm:"index" json:"actorUserId"`
	CreatedAt   time.Time `gorm:"index" json:"createdAt"`
}

func (APIRequestLog) TableName() string {
	return "api_request_logs"
}
```

- [ ] **Step 2: Migration**

In `internal/db/db.go`, add `&model.APIRequestLog{}` to the `AutoMigrate(...)` list in `Migrate()`.

- [ ] **Step 3: Repository**

Create `internal/repository/api_request_log_repository.go`:

```go
package repository

import (
	"time"

	"gorm.io/gorm"

	"beetleshield-backend/internal/model"
)

type APIRequestLogListFilter struct {
	Method      string
	Path        string
	Status      *int
	ActorUserID uint
	StartTime   *time.Time
	EndTime     *time.Time
	Page        int
	PageSize    int
}

type APIRequestLogRepository struct {
	db *gorm.DB
}

func NewAPIRequestLogRepository(db *gorm.DB) *APIRequestLogRepository {
	return &APIRequestLogRepository{db: db}
}

func (r *APIRequestLogRepository) Record(log *model.APIRequestLog) error {
	return r.db.Create(log).Error
}

func (r *APIRequestLogRepository) List(filter APIRequestLogListFilter) ([]model.APIRequestLog, int64, error) {
	query := r.db.Model(&model.APIRequestLog{})

	if filter.Method != "" {
		query = query.Where("method = ?", filter.Method)
	}
	if filter.Path != "" {
		query = query.Where("path = ?", filter.Path)
	}
	if filter.Status != nil {
		query = query.Where("status = ?", *filter.Status)
	}
	if filter.ActorUserID != 0 {
		query = query.Where("actor_user_id = ?", filter.ActorUserID)
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

	var logs []model.APIRequestLog
	err := query.Order("created_at DESC, id DESC").
		Offset((page - 1) * pageSize).
		Limit(pageSize).
		Find(&logs).Error
	return logs, total, err
}
```

- [ ] **Step 4: Repository tests**

Create `internal/repository/api_request_log_repository_test.go` following the exact pattern of `internal/repository/audit_repository_test.go` (real local Postgres, unique per-test markers via a distinctive `Path` value since there's no natural per-test scoping column). Cover: `Record`+`List` round trip; filtering by `Method`, `Path`, `Status`, `ActorUserID`, time range; pagination (3 rows, `PageSize:2` → 2 items + `total:3`).

Run `go test ./internal/repository/... -run TestAPIRequestLog` — confirm green.

---

### Task 2: API request log service, middleware, handler, router/main.go wiring

**Files:**
- Create: `internal/service/api_request_log_service.go`, `internal/service/api_request_log_service_test.go`
- Create: `internal/middleware/request_log.go`, `internal/middleware/request_log_test.go`
- Create: `internal/handler/api_request_log_handler.go`, `internal/handler/api_request_log_handler_test.go`
- Modify: `internal/router/router.go`, `cmd/server/main.go`

**Interfaces:**
- Consumes: `repository.APIRequestLogRepository`/`APIRequestLogListFilter` (Task 1), `middleware.ContextUserIDKey` (existing).
- Produces: `service.APIRequestLogService` (satisfies `middleware.RequestLogRecorder`), `middleware.RequestLog(recorder) gin.HandlerFunc`, `handler.APIRequestLogHandler` — wired into `router.Deps.APIRequestLogHandler` (new field) and `main.go`.

- [ ] **Step 1: Service**

Create `internal/service/api_request_log_service.go`:

```go
package service

import (
	"log"

	"beetleshield-backend/internal/model"
	"beetleshield-backend/internal/repository"
)

type RecordAPIRequestInput struct {
	Method      string
	Path        string
	Status      int
	LatencyMS   int64
	ClientIP    string
	ActorUserID uint
}

type APIRequestLogService struct {
	repo *repository.APIRequestLogRepository
}

func NewAPIRequestLogService(repo *repository.APIRequestLogRepository) *APIRequestLogService {
	return &APIRequestLogService{repo: repo}
}

// Record is fire-and-forget, same contract as AuditService.Record: it runs
// after the response has already been written (from the request-log
// middleware's deferred call), so there is nothing meaningful to propagate
// an error to even if we wanted to — a write failure is logged and dropped.
func (s *APIRequestLogService) Record(input RecordAPIRequestInput) {
	if s == nil || s.repo == nil {
		log.Printf("api request log: failed to record %s %s: repository is not configured", input.Method, input.Path)
		return
	}
	entry := &model.APIRequestLog{
		Method:      input.Method,
		Path:        input.Path,
		Status:      input.Status,
		LatencyMS:   input.LatencyMS,
		ClientIP:    input.ClientIP,
		ActorUserID: input.ActorUserID,
	}
	if err := s.repo.Record(entry); err != nil {
		log.Printf("api request log: failed to record %s %s: %v", input.Method, input.Path, err)
	}
}

func (s *APIRequestLogService) List(filter repository.APIRequestLogListFilter) ([]model.APIRequestLog, int64, error) {
	return s.repo.List(filter)
}
```

- [ ] **Step 2: Middleware**

Create `internal/middleware/request_log.go`:

```go
package middleware

import (
	"time"

	"github.com/gin-gonic/gin"
)

// RequestLogEntry is the recorder-agnostic shape RequestLog hands off; it
// deliberately doesn't import beetleshield-backend/internal/service, so
// RequestLogRecorder is implemented by *service.APIRequestLogService via
// structural typing, avoiding a middleware -> service import.
type RequestLogEntry struct {
	Method      string
	Path        string
	Status      int
	LatencyMS   int64
	ClientIP    string
	ActorUserID uint
}

type RequestLogRecorder interface {
	Record(entry RequestLogEntry)
}

// RequestLog must be registered before any subgroup's JWTAuth/RequireRole so
// that its post-c.Next() code (which needs the final response status and
// any authenticated user ID set by inner auth middleware) runs last, per
// Gin's outer-wraps-inner execution order.
func RequestLog(recorder RequestLogRecorder) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()

		recorder.Record(RequestLogEntry{
			Method:      c.Request.Method,
			Path:        c.FullPath(),
			Status:      c.Writer.Status(),
			LatencyMS:   time.Since(start).Milliseconds(),
			ClientIP:    c.ClientIP(),
			ActorUserID: c.GetUint(ContextUserIDKey),
		})
	}
}
```

Note: `service.APIRequestLogService.Record` from Task 2 Step 1 takes a `RecordAPIRequestInput`, not a `middleware.RequestLogEntry` — these are structurally identical but distinct named types in different packages. Since Go interface satisfaction is structural on method signatures (not parameter type names), `*service.APIRequestLogService` does **not** automatically satisfy `middleware.RequestLogRecorder` unless its `Record` method's parameter type is literally `middleware.RequestLogEntry`. Resolve this by having `main.go` wrap the service in a tiny adapter closure when wiring the middleware (see Step 4), rather than making `service` import `middleware` or vice versa:

```go
// in main.go, when wiring:
requestLogRecorder := middleware.RequestLogRecorderFunc(func(entry middleware.RequestLogEntry) {
	apiRequestLogService.Record(service.RecordAPIRequestInput{
		Method: entry.Method, Path: entry.Path, Status: entry.Status,
		LatencyMS: entry.LatencyMS, ClientIP: entry.ClientIP, ActorUserID: entry.ActorUserID,
	})
})
```

Add this adapter type to `internal/middleware/request_log.go` alongside the interface:

```go
type RequestLogRecorderFunc func(entry RequestLogEntry)

func (f RequestLogRecorderFunc) Record(entry RequestLogEntry) { f(entry) }
```

- [ ] **Step 3: Handler**

Create `internal/handler/api_request_log_handler.go`, closely mirroring `internal/handler/audit_handler.go`'s `List` (page/pageSize/method/path/status/startTime/endTime query parsing):

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

type APIRequestLogHandler struct {
	svc *service.APIRequestLogService
}

func NewAPIRequestLogHandler(svc *service.APIRequestLogService) *APIRequestLogHandler {
	return &APIRequestLogHandler{svc: svc}
}

func (h *APIRequestLogHandler) List(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("pageSize", "20"))
	actorUserID, _ := strconv.ParseUint(c.DefaultQuery("actorUserId", "0"), 10, 64)

	filter := repository.APIRequestLogListFilter{
		Method:      c.Query("method"),
		Path:        c.Query("path"),
		ActorUserID: uint(actorUserID),
		Page:        page,
		PageSize:    pageSize,
	}

	if statusParam := c.Query("status"); statusParam != "" {
		status, err := strconv.Atoi(statusParam)
		if err != nil {
			response.Error(c, http.StatusBadRequest, 40040, "非法的状态码")
			return
		}
		filter.Status = &status
	}
	if startParam := c.Query("startTime"); startParam != "" {
		t, err := time.Parse(time.RFC3339, startParam)
		if err != nil {
			response.Error(c, http.StatusBadRequest, 40041, "非法的开始时间")
			return
		}
		filter.StartTime = &t
	}
	if endParam := c.Query("endTime"); endParam != "" {
		t, err := time.Parse(time.RFC3339, endParam)
		if err != nil {
			response.Error(c, http.StatusBadRequest, 40042, "非法的结束时间")
			return
		}
		filter.EndTime = &t
	}

	logs, total, err := h.svc.List(filter)
	if err != nil {
		response.Error(c, http.StatusInternalServerError, 50040, "查询 API 请求日志失败")
		return
	}

	response.Success(c, http.StatusOK, gin.H{"items": logs, "total": total})
}
```

- [ ] **Step 4: Router + main.go wiring**

In `internal/router/router.go`: add `APIRequestLogHandler *handler.APIRequestLogHandler` to `Deps`. Register the middleware as the very first thing on the `v1` group, and add the read route:

```go
v1 := r.Group("/api/v1")
v1.Use(middleware.RequestLog(deps.RequestLogRecorder))
{
	// ... existing subgroups unchanged ...

	apiLogs := v1.Group("/api-logs")
	apiLogs.Use(middleware.JWTAuth(deps.JWTSecret))
	{
		apiLogs.GET("", deps.APIRequestLogHandler.List)
	}
}
```

Add `RequestLogRecorder middleware.RequestLogRecorder` to `Deps` too (the adapter built in `main.go`, per Step 2).

In `cmd/server/main.go`, near the other repo/service construction at the top:

```go
apiRequestLogRepo := repository.NewAPIRequestLogRepository(database)
apiRequestLogService := service.NewAPIRequestLogService(apiRequestLogRepo)
apiRequestLogHandler := handler.NewAPIRequestLogHandler(apiRequestLogService)
requestLogRecorder := middleware.RequestLogRecorderFunc(func(entry middleware.RequestLogEntry) {
	apiRequestLogService.Record(service.RecordAPIRequestInput{
		Method: entry.Method, Path: entry.Path, Status: entry.Status,
		LatencyMS: entry.LatencyMS, ClientIP: entry.ClientIP, ActorUserID: entry.ActorUserID,
	})
})
```

Add `APIRequestLogHandler: apiRequestLogHandler,` and `RequestLogRecorder: requestLogRecorder,` to the `router.Deps{...}` literal. `main.go` needs a new import for `beetleshield-backend/internal/middleware`.

- [ ] **Step 5: Middleware + handler tests**

Create `internal/middleware/request_log_test.go`: a minimal `gin.Engine` with `RequestLog(fakeRecorder)` registered and one dummy route; assert the fake recorder captured the right `Method`/`Status` after a request, and that a route requiring a preceding auth-setting middleware has the right `ActorUserID` (simulate by setting `ContextUserIDKey` in a stub middleware registered after `RequestLog` but before the dummy handler, proving the outer-middleware-runs-last-on-the-way-out behavior).

Create `internal/handler/api_request_log_handler_test.go`: real end-to-end test hitting a couple of existing routes (e.g. `GET /api/v1/apps`, `GET /auth/login`) through a full `router.New(...)` with the middleware wired, then `GET /api/v1/api-logs` and assert the prior requests show up with correct `method`/`path`/`status`.

Run `go build ./... && go test ./internal/middleware/... ./internal/handler/... -run "RequestLog|APIRequestLog"` — confirm green.

---

### Task 3: Failure-audit retrofit — AppService.Upload and Delete

**Files:**
- Modify: `internal/service/app_service.go`, `internal/service/app_service_test.go`

**Interfaces:** No signature changes — internal control-flow refactor only.

- [ ] **Step 1: `Upload`**

Change the signature to named returns `func (s *AppService) Upload(ctx context.Context, input UploadInput) (app *model.App, err error)` and add the `defer` block described in the spec's "统一改造模式" section immediately after the opening brace, **before** any existing logic. Remove the existing single `s.auditService.Record(...)` call near the end of the function (the success case is now handled uniformly by the defer). Every existing `return nil, xxxErr` line stays completely unchanged — the named return values mean a bare value still gets assigned to `app`/`err` correctly. Double-check the final success return (`return app, nil`) still works with named returns (it does — explicit values in a `return` statement override the named vars, which is what the defer reads via closure since defers run after the return statement assigns to the named vars but before the function actually returns).

- [ ] **Step 2: `Delete`**

Same pattern: `func (s *AppService) Delete(ctx context.Context, id uint, actorUserID uint, ip string) (err error)`, defer block at the top using the already-fetched `app` variable (in scope for the whole function body already) — `app` is nil only if `s.appRepo.FindByID(id)` itself failed. Remove the existing `s.auditService.Record(...)` call near the end.

- [ ] **Step 3: Tests**

In `internal/service/app_service_test.go`, add regression tests (following the existing `findAuditLogForTarget`-style pattern already used in `internal/handler/app_handler_test.go` — either reuse that helper if `app_service_test.go` can import it, likely not since it's in a different test package `service_test` vs `handler_test`; add a local equivalent scoped to this package) for:
- `Upload` with an unsupported extension → one `Success:false` `app.upload` audit row with `TargetID:0`.
- `Upload` success (existing passing tests already exercise this) → confirm still exactly one `Success:true` row (no double-recording from the defer refactor).
- `Delete` on a nonexistent ID → one `Success:false` `app.delete` row with `TargetID` equal to the requested (nonexistent) ID.
- `Delete` on an app with an active hardening task → one `Success:false` row.

Run `go build ./... && go test ./internal/service/... -run TestAppService` — confirm green.

---

### Task 4: Failure-audit retrofit — HardeningService.Create and StrategyService.Save

**Files:**
- Modify: `internal/service/hardening_service.go`, `internal/service/hardening_service_test.go`
- Modify: `internal/service/strategy_service.go`, `internal/service/strategy_service_test.go`

**Interfaces:** No signature changes.

- [ ] **Step 1: `HardeningService.Create`**

Named returns: `func (s *HardeningService) Create(ctx context.Context, input CreateHardeningTaskInput) (detail *HardeningTaskDetail, err error)`. Defer block: if `err != nil`, record with `TargetType: "app"`, `TargetID: input.AppID` (the one thing always known, since `FindByID(input.AppID)` is the very first line); if `err == nil`, **do not touch** the existing success-path `Record` call (it already correctly uses `TargetType: "hardening_task"`, `TargetID: task.ID` — leave it exactly where it is, don't move it into the defer, to avoid touching an already-tested code path). The defer should look like:

```go
defer func() {
	if err != nil {
		s.auditService.Record(RecordAuditInput{
			ActorUserID: input.CreatedBy,
			Action:      model.AuditActionHardeningCreate,
			TargetType:  "app",
			TargetID:    input.AppID,
			Detail:      "创建加固任务失败 - " + err.Error(),
			IP:          input.IP,
			Success:     false,
		})
	}
}()
```

Placed right after the opening brace, before `_ = ctx`.

- [ ] **Step 2: `StrategyService.Save`**

Named returns: `func (s *StrategyService) Save(input SaveStrategyInput, updatedBy uint, ip string) (strategy *model.Strategy, err error)`. Move the existing success-path `Record` call into a `defer` (this one CAN be fully deferred since success/failure both fit the same `TargetType: "strategy"` shape):

```go
defer func() {
	targetID := uint(0)
	if strategy != nil {
		targetID = strategy.ID
	}
	detail := "全局加固策略已更新"
	if err != nil {
		detail = "策略保存失败 - " + err.Error()
	}
	s.auditService.Record(RecordAuditInput{
		ActorUserID: updatedBy,
		Action:      model.AuditActionStrategySave,
		TargetType:  "strategy",
		TargetID:    targetID,
		Detail:      detail,
		IP:          ip,
		Success:     err == nil,
	})
}()
```

Remove the old inline `Record` call at the end of the function.

- [ ] **Step 3: Tests**

`internal/service/hardening_service_test.go`: add a test creating a task for an app that already has an active task (existing `ErrActiveHardeningTaskExists` path) and assert one `Success:false` `hardening_task.create` row with `TargetType:"app"`. `internal/service/strategy_service_test.go`: add a test saving an invalid `DexLevel` and assert one `Success:false` `strategy.save` row.

Run `go build ./... && go test ./internal/service/... -run "TestHardeningService|TestStrategyService"` — confirm green.

---

### Task 5: Failure-audit retrofit — UserService.Create/Update/UpdateStatus

**Files:**
- Modify: `internal/service/user_service.go`, `internal/service/user_service_test.go`

**Interfaces:** No signature changes.

- [ ] **Step 1: `Create`**

Named returns: `func (s *UserService) Create(input CreateUserInput) (user *model.User, err error)`. Defer block, `TargetType: "user"`, `TargetID` is `user.ID` if `user != nil` else `0`, `Detail` is `input.Email` (+ `" - " + err.Error()` on failure, else the existing `user.Email + " (" + string(user.Role) + ")"` format). Remove the old inline `Record` call.

- [ ] **Step 2: `Update`**

Named returns: `func (s *UserService) Update(id uint, input UpdateUserInput, actorUserID uint, ip string) (user *model.User, err error)`. Defer block, `TargetType: "user"`, `TargetID: id` (always known from the param, works for both outcomes). Remove the old inline `Record` call.

- [ ] **Step 3: `UpdateStatus`**

Named returns: `func (s *UserService) UpdateStatus(id uint, status model.UserStatus, currentUserID uint, ip string) (err error)`. Defer block, `TargetType: "user"`, `TargetID: id`. Remove the old inline `Record` call; keep the existing `statusLabel` computation but guard it (only meaningful on success — on failure just say `"状态变更失败 - " + err.Error()`).

- [ ] **Step 4: Tests**

`internal/service/user_service_test.go`: add tests for `Create` with a duplicate email (existing `ErrEmailAlreadyExists` path) → `Success:false` `user.create` row with `TargetID:0`; `Update` on a nonexistent ID → `Success:false` `user.update` row with `TargetID` = the requested ID; `UpdateStatus` attempting to disable yourself → `Success:false` `user.update_status` row.

Run `go build ./... && go test ./internal/service/... -run TestUserService` — confirm green.

- [ ] **Step 5: Full backend regression**

Run `go build ./... && go vet ./... && go test ./... -count=1` from the repo root — every package must pass. Commit the backend changes (this plan's scope, Tasks 1–5) as one or more commits.

---

### Task 6: Frontend — real API request log tab + filter/pagination fixes

**Files (frontend repo, `/Users/yrighc/work/hzyz/project/BeetleShieldFrontend`):**
- Create: `src/api/apiLogs.ts`
- Modify: `src/api/types.ts` (add `APIRequestLog` type)
- Modify: `src/pages/Logs.tsx`

**Interfaces:** Consumes `GET /api/v1/api-logs` (Task 2).

- [ ] **Step 1: API client**

Add to `src/api/types.ts`:

```typescript
export interface APIRequestLog {
  id: number
  method: string
  path: string
  status: number
  latencyMs: number
  clientIp: string
  actorUserId: number
  createdAt: string
}
```

Create `src/api/apiLogs.ts`:

```typescript
import apiClient from './client'
import type { APIRequestLog, Paginated } from './types'

export interface ListAPIRequestLogsParams {
  page?: number
  pageSize?: number
  method?: string
  path?: string
  status?: number
  actorUserId?: number
  startTime?: string
  endTime?: string
}

export function listApiRequestLogs(params: ListAPIRequestLogsParams = {}): Promise<Paginated<APIRequestLog>> {
  return apiClient.get('/api-logs', { params }) as unknown as Promise<Paginated<APIRequestLog>>
}
```

- [ ] **Step 2: Rewire the "API 交互审计" tab**

In `src/pages/Logs.tsx`: replace `ApiLogRow`'s construction (currently `toApiRow(log: AuditLog)`) with a new `toApiRequestRow(log: APIRequestLog)` using the real fields (`method`, `path`, `status`, `latencyMs` formatted as `"${latencyMs}ms"`, `clientIp`). Add a `listApiRequestLogs` call to `loadLogs`'s `Promise.all` (alongside the existing `listHardeningTasks`/`listAuditLogs` calls), passing the same date-range params. Remove the old `apiRows = auditRows.filter(...).map(toApiRow)` derivation and the now-unused `toApiRow`/`DOWNLOAD_ACTIONS`-based non-download filtering for this tab specifically (download/alert tabs keep using `audit_logs` as before — only tab 2's data source changes).

- [ ] **Step 3: Fix the level-filter no-op bug**

Add a `statusToLevel(status: number): string` helper (`200-299 → 'SUCCESS'`, `300-499 → 'WARN'`, `500+ → 'ERROR'`) and use it in `filteredApiLogs`'s predicate so `logLevel` actually narrows tab 2's rows. For tab 3 (downloads), since there is no natural level concept, disable the level `<Select>` (set its `disabled` prop) when `activeTab === '3'`, with the existing value forced back to `'ALL'` on tab switch so a stale selection doesn't silently hide rows once the user switches away and back.

- [ ] **Step 4: Real server-side pagination**

Replace the fixed `pageSize: 100`/`pageSize: 50` one-shot fetches with real paginated state per tab: track `{page, pageSize}` per tab in component state, wire each antd `<Table>`'s `pagination` prop to `{current, pageSize, total, onChange}` (controlled, not the current uncontrolled `{pageSize: 10}`), and re-issue the relevant `list*` call with the new `page`/`pageSize` on `onChange` instead of re-slicing an already-fetched local array. `searchKey` free-text search still needs to run over data the backend hasn't been asked to filter by (none of `listAuditLogs`/`listApiRequestLogs`/`listHardeningTasks` support arbitrary keyword search server-side) — keep client-side keyword filtering on top of whatever page is currently loaded, but this plan does not attempt to add server-side full-text search; only the "silently missing rows beyond a fixed 100/50 cap" problem is in scope here.

- [ ] **Step 5: Manual verification**

Start both servers (`preview_start`), log in, exercise all 4 tabs: confirm tab 2 shows real HTTP method/path/status/latency for recent requests, confirm the level dropdown now visibly changes tab 2's rows and is disabled on tab 3, confirm switching pages on any tab issues a new network request (check `preview_network`) rather than just re-slicing local data.

---

## Post-plan note

This completes sub-project six. Reports (加固报告/安全评分) and the Dashboard aggregation endpoints remain unscheduled — each should go through its own brainstorming → spec → plan cycle before being started.
