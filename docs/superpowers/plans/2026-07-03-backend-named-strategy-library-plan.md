# Named Strategy Library Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Upgrade Strategy Center from a single global strategy into a default strategy plus a reusable named strategy library, and let hardening task creation choose a strategy by ID.

**Architecture:** Keep one `strategies` table and distinguish default versus named strategies with `is_default`. Strategy service resolves the concrete strategy for hardening, and hardening tasks continue freezing `StrategySnapshot` so later strategy edits do not affect history. Existing `/strategies/current` stays compatible while new `/strategies` CRUD manages only regular named strategies.

**Tech Stack:** Go, Gin, GORM, PostgreSQL, existing `{code,message,data}` response wrapper, existing service-level audit logging.

## Global Constraints

- Do not add a `projects` table.
- Do not bind strategies to `apps`.
- Do not modify APK/AAB upload flow.
- Preset templates remain backend constants, not database records.
- No database foreign key constraints.
- Use TDD: write failing tests before production code.
- Keep old `POST /hardening-tasks` behavior working when `strategyId` is omitted.

---

### Task 1: Strategy Model And Repository

**Files:**
- Modify: `internal/model/strategy.go`
- Modify: `internal/repository/strategy_repository.go`
- Modify: `internal/repository/strategy_repository_test.go`

**Interfaces:**
- Produces: `Strategy.Name`, `Strategy.Description`, `Strategy.IsDefault`, `Strategy.CreatedBy`.
- Produces: `StrategyListFilter`.
- Produces: `GetCurrent`, `SaveCurrent`, `List`, `FindByID`, `FindRegularByID`, `Create`, `Update`, `Delete`, `NameExists`, `PromoteLegacyCurrent`.

- [ ] **Step 1: Write failing repository tests**

Add tests for default-only current, regular list exclusion, name existence with exclude ID, regular find exclusion, and delete.

- [ ] **Step 2: Run repository tests to verify RED**

Run: `go test ./internal/repository -run 'TestStrategyRepository_' -v`

Expected: FAIL because new fields and repository methods do not exist.

- [ ] **Step 3: Implement model and repository**

Add metadata fields to `model.Strategy`. Replace single-row `Save` with `SaveCurrent`, add regular CRUD and list methods. Keep a `Save` wrapper if needed by older tests while migrating call sites.

- [ ] **Step 4: Run repository tests to verify GREEN**

Run: `go test ./internal/repository -run 'TestStrategyRepository_' -v`

Expected: PASS.

### Task 2: Strategy Service Semantics

**Files:**
- Modify: `internal/service/strategy_service.go`
- Modify: `internal/service/strategy_service_test.go`

**Interfaces:**
- Produces: `ErrStrategyNotFound`, `ErrStrategyNameRequired`, `ErrStrategyNameExists`, `ErrDefaultStrategyDelete`.
- Produces: `StrategyPayloadInput`.
- Produces: `SaveCurrent`, `List`, `Create`, `Get`, `Update`, `Delete`, `ResolveForHardening`.
- Consumes: repository methods from Task 1.

- [ ] **Step 1: Write failing service tests**

Add tests for legacy current promotion, named strategy create/list/update/delete validation, duplicate names, default-delete rejection, and `ResolveForHardening` for zero ID, named ID, default ID, and missing ID.

- [ ] **Step 2: Run service tests to verify RED**

Run: `go test ./internal/service -run 'TestStrategyService_' -v`

Expected: FAIL because service methods and errors do not exist.

- [ ] **Step 3: Implement strategy service**

Use one validation helper for strategy fields. `GetCurrent` promotes the oldest legacy row if there is no default row, or returns a finance-template default if the table is empty. `SaveCurrent` writes `Name="默认加固策略"` and `IsDefault=true`. Regular CRUD requires non-empty unique `Name` and always uses `IsDefault=false`.

- [ ] **Step 4: Run service tests to verify GREEN**

Run: `go test ./internal/service -run 'TestStrategyService_' -v`

Expected: PASS.

### Task 3: Strategy HTTP API

**Files:**
- Modify: `internal/handler/strategy_handler.go`
- Modify: `internal/router/router.go`
- Modify: `internal/handler/strategy_handler_test.go`

**Interfaces:**
- Consumes: strategy service methods from Task 2.
- Produces: `GET /api/v1/strategies`, `POST /api/v1/strategies`, `GET /api/v1/strategies/:id`, `PUT /api/v1/strategies/:id`, `DELETE /api/v1/strategies/:id`.

- [ ] **Step 1: Write failing handler tests**

Add tests that admin can create/update/delete a regular strategy, developer can list/get but cannot write, duplicate name returns 409, missing strategy returns 404, and `/strategies/current` is not swallowed by `/:id`.

- [ ] **Step 2: Run strategy handler tests to verify RED**

Run: `go test ./internal/handler -run 'TestStrategy' -v`

Expected: FAIL because new endpoints are missing.

- [ ] **Step 3: Implement handler and routes**

Add request parsing, response mapping, pagination defaults, and error mappings: name validation 400, duplicate 409, missing 404, invalid field values 400, default delete 409.

- [ ] **Step 4: Run strategy handler tests to verify GREEN**

Run: `go test ./internal/handler -run 'TestStrategy' -v`

Expected: PASS.

### Task 4: Hardening Task Strategy Selection

**Files:**
- Modify: `internal/service/hardening_service.go`
- Modify: `internal/handler/hardening_handler.go`
- Modify: `internal/service/hardening_service_test.go`
- Modify: `internal/handler/hardening_handler_test.go`

**Interfaces:**
- Consumes: `StrategyService.ResolveForHardening(strategyID uint)`.
- Produces: optional `strategyId` in `CreateHardeningTaskInput` and `createHardeningTaskRequest`.
- Produces: `ErrHardeningStrategyNotFound`.

- [ ] **Step 1: Write failing hardening service tests**

Add tests that `strategyId` freezes the selected named strategy and name, omitted `strategyId` uses default, missing `strategyId` returns strategy-not-found, and `strategyId` wins over `strategySnapshot`.

- [ ] **Step 2: Run hardening service tests to verify RED**

Run: `go test ./internal/service -run 'TestHardeningService_Create.*Strategy|TestHardeningService_CreateDefaults' -v`

Expected: FAIL because `strategyId` is not wired.

- [ ] **Step 3: Implement hardening service selection**

If `StrategyID > 0`, resolve by ID and ignore `StrategySnapshot`. If no ID and no snapshot, resolve default. Preserve legacy `StrategySnapshot` compatibility when no `StrategyID` is provided.

- [ ] **Step 4: Run hardening service tests to verify GREEN**

Run: `go test ./internal/service -run 'TestHardeningService_Create.*Strategy|TestHardeningService_CreateDefaults' -v`

Expected: PASS.

- [ ] **Step 5: Write failing hardening handler tests**

Add tests that `POST /hardening-tasks` accepts `strategyId` and returns 404 for missing strategy.

- [ ] **Step 6: Run hardening handler tests to verify RED**

Run: `go test ./internal/handler -run 'TestHardeningHandler_Create.*Strategy' -v`

Expected: FAIL because handler request does not include `strategyId` or map strategy-not-found.

- [ ] **Step 7: Implement hardening handler wiring**

Add `StrategyID uint json:"strategyId"` to the request and map `ErrHardeningStrategyNotFound` to 404 with message “加固策略不存在”.

- [ ] **Step 8: Run hardening handler tests to verify GREEN**

Run: `go test ./internal/handler -run 'TestHardeningHandler_Create.*Strategy' -v`

Expected: PASS.

### Task 5: Final Verification And Commit

**Files:**
- Modify: `internal/middleware/request_log.go`
- Modify: `internal/middleware/request_log_test.go`
- Modify as needed based on `gofmt`.

- [ ] **Step 1: Add request-log nil-recorder regression coverage**

During handler verification, tests that intentionally build partial router dependencies exposed a pre-existing `RequestLog(nil)` panic after responses were written. Add `TestRequestLog_NilRecorderIsNoop` and make `RequestLog` return after `c.Next()` when `recorder == nil`; this keeps production recording unchanged and lets handler tests run without recovery noise.

- [ ] **Step 2: Format**

Run: `gofmt -w internal/model/strategy.go internal/repository/strategy_repository.go internal/repository/strategy_repository_test.go internal/service/strategy_service.go internal/service/strategy_service_test.go internal/handler/strategy_handler.go internal/handler/strategy_handler_test.go internal/service/hardening_service.go internal/service/hardening_service_test.go internal/handler/hardening_handler.go internal/handler/hardening_handler_test.go internal/router/router.go`

- [ ] **Step 3: Run full tests**

Run: `make test`

Expected: PASS. If Postgres or MinIO are unavailable, run `make dev-up` first and rerun.

- [ ] **Step 4: Review diff**

Run: `git diff --check && git diff --stat`

Expected: no whitespace errors and only strategy/hardening related files changed.

- [ ] **Step 5: Commit**

Run:

```bash
git add docs/superpowers/plans/2026-07-03-backend-named-strategy-library-plan.md internal/model/strategy.go internal/repository/strategy_repository.go internal/repository/strategy_repository_test.go internal/service/strategy_service.go internal/service/strategy_service_test.go internal/handler/strategy_handler.go internal/handler/strategy_handler_test.go internal/service/hardening_service.go internal/service/hardening_service_test.go internal/handler/hardening_handler.go internal/handler/hardening_handler_test.go internal/router/router.go internal/middleware/request_log.go internal/middleware/request_log_test.go
git commit -m "feat: add named strategy library"
```
