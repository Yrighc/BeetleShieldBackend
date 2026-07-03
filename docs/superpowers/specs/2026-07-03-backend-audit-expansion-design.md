# BeetleShield 后端 - 子项目六：失败审计扩展 + 独立 API 请求日志

日期：2026-07-03

## 背景与范围

审计日志系统（子项目五）已合入并经过一轮 review 修复。前端"日志审计"页面基于它做了 4 个 tab：加固运行日志（`hardening_logs`，无关）、API 交互审计、交付下载记录、异常与警报日志——后两者已经用 `audit_logs` 的下载类 action / `success=false` 正确区分，工作正常。但排查后发现两处不足，用户已明确要求本子项目解决：

1. **"异常与警报日志"覆盖不全**：当前 `audit_logs` 只有登录会在失败时也记录（`success=false`），其余 6 个动作（应用上传/删除、加固任务创建、策略保存、用户增/改/启禁用）全部"只在成功时记录"——意味着一次被拒绝的上传、一次因活跃任务冲突被拒绝的加固创建、一次因邮箱重复被拒绝的建号，在审计日志里完全不可见。用户要求：**扩展为失败也记录**，复用同一套 `AuditAction` 常量，靠 `Success` 字段区分（不新增 `*.failed` 常量）。
2. **"API 交互审计"名不副实**：现在这个 tab 实际上是把 `audit_logs` 里非下载类的条目摘出来充数，没有真实的 method/path/latency 数据。用户要求：**新增一套基于 Gin 中间件的、与业务审计完全独立的 API 请求日志**（`api_request_logs`），只覆盖 `/api/v1/*`，只记元数据（method/path/status/latency/clientIP/actorUserId），不记 request/response body。

**本子项目范围**：
1. `AppService.Upload/Delete`、`HardeningService.Create`、`StrategyService.Save`、`UserService.Create/Update/UpdateStatus` 七个方法改为无论成功失败都调用一次 `auditService.Record`（用 `Success` 字段区分），而不是像现在这样只在成功路径末尾调用一次。
2. 新增 `api_request_logs` 表 + 中间件 + 只读查询接口 `GET /api/v1/api-logs`。
3. 前端：Logs.tsx 的"API 交互审计" tab 改接新接口；修复"级别"筛选器在 tab 2/3 上静默失效的问题；把当前写死 `pageSize:100` 的一次性拉取改成真正的服务端翻页。

**明确不在本子项目范围内**：
- 记录 request/response body（用户已确认不需要，且涉及脱敏，过度设计）。
- 记录 `/health` 等非 `/api/v1` 路由（用户已确认只记 `/api/v1/*`）。
- "异常与警报日志"里 hardening_logs 的 WARN/ERROR 部分——已经工作正常，不改。

## 失败审计：统一改造模式

七个方法目前都是"发生错误就直接 `return nil, err`，只有走到最后成功路径才调用一次 `s.auditService.Record(...)`"。给每个错误分支都手写一次 Record 调用会产生大量重复（`AppService.Upload` 有 9 个错误返回点）。改用**具名返回值 + `defer` 单点记录**：无论从哪个 `return` 退出，`defer` 里的一次 `Record` 调用都能看到最终的 `err`/返回值，用 `err == nil` 得出 `Success`。这是比"每个分支都插一行"更浅层、更不易漏改的写法。

以 `AppService.Upload` 为例（改造后骨架，中间业务逻辑不变）：

```go
func (s *AppService) Upload(ctx context.Context, input UploadInput) (app *model.App, err error) {
	defer func() {
		detail := input.FileHeader.Filename
		targetID := uint(0)
		if app != nil {
			detail = app.Name + " (" + app.PackageName + ")"
			targetID = app.ID
		}
		if err != nil {
			detail = detail + " - " + err.Error()
		}
		s.auditService.Record(RecordAuditInput{
			ActorUserID: input.UploadedBy,
			Action:      model.AuditActionAppUpload,
			TargetType:  "app",
			TargetID:    targetID,
			Detail:      detail,
			IP:          input.IP,
			Success:     err == nil,
		})
	}()

	// ... 函数体完全不变，包括原有的 9 个 `return nil, xxxErr` ...
}
```

各方法具体的 `TargetType`/`TargetID`/`Detail` 约定：

| 方法 | TargetType | TargetID（失败时） | Detail（失败时） |
|---|---|---|---|
| `AppService.Upload` | `app` | `0`（应用还未创建） | 上传文件名 + `" - " + err.Error()` |
| `AppService.Delete` | `app` | 请求的 `id`（一直已知） | 若 `app` 已查到用 名称+包名，否则 `"应用不存在"`，均追加错误信息 |
| `HardeningService.Create` | 成功时不变（`hardening_task`/`task.ID`）；**失败时改用** `app`/`input.AppID` | 见左 | 应用名 + `" - " + err.Error()`（失败时应用一定已知，因为 `FindByID` 是第一步） |
| `StrategyService.Save` | `strategy` | `0`（策略对象未落库） | `"策略保存失败 - " + err.Error()` |
| `UserService.Create` | `user` | `0`（用户未创建） | 尝试创建的邮箱 + `" - " + err.Error()` |
| `UserService.Update` | `user` | 请求的 `id`（一直已知） | `"更新用户失败 - " + err.Error()` |
| `UserService.UpdateStatus` | `user` | 请求的 `id`（一直已知） | `"状态变更为 X 失败 - " + err.Error()` |

`HardeningService.Create` 是唯一一个成功/失败 `TargetType` 不同的方法——失败时任务从未创建，`hardening_task`/`task.ID` 无意义，退而用请求中一直已知的 `app`/`input.AppID`；这是刻意的、保留现有已测试通过的成功路径行为的最小改动，而不是把成功路径也统一改成 `app`（那样要动已有测试的断言）。

## 新增：API 请求日志（`api_request_logs`）

### 数据模型

新表，无外键：

```go
type APIRequestLog struct {
	ID          uint      `gorm:"primaryKey" json:"id"`
	Method      string    `gorm:"size:10;index" json:"method"`
	Path        string    `gorm:"size:255;index" json:"path"`
	Status      int       `gorm:"index" json:"status"`
	LatencyMS   int64     `json:"latencyMs"`
	ClientIP    string    `gorm:"size:64" json:"clientIp"`
	ActorUserID uint      `gorm:"index" json:"actorUserId"` // 0 表示未认证请求（如 /auth/login 本身）
	CreatedAt   time.Time `gorm:"index" json:"createdAt"`
}
```

### 中间件

`internal/middleware/request_log.go`，新建 `RequestLog(recorder RequestLogRecorder) gin.HandlerFunc`（`RequestLogRecorder` 是一个只有 `Record(...)` 方法的小接口，由 `service.APIRequestLogService` 实现，避免 `middleware` 包反向依赖整个 `service` 包）：

```go
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

关键点：`c.Next()` 放在最前面，`Record` 的调用写在它之后——`Record` 依赖 `c.Writer.Status()`（要等 handler 跑完）和 `c.GetUint(ContextUserIDKey)`（要等内层 `JWTAuth` 中间件设置完 context）。这个中间件要注册在 `v1` 分组最外层、且在任何子分组的 `JWTAuth`/`RequireRole` 之前：`v1.Use(middleware.RequestLog(...))` 紧跟在 `v1 := r.Group("/api/v1")` 之后、任何子分组定义之前。Gin 中间件对同一请求是"先注册的外层包住后注册的内层"，`c.Next()` 之后的代码按注册的反序执行，所以只要 `RequestLog` 是第一个注册的，它的 `Record` 调用必然在所有内层中间件（含 `JWTAuth`）和 handler 都跑完之后才执行，能读到最终状态码和已登录用户 ID。未鉴权的路由（如 `/auth/login`）`ActorUserID` 自然是 0。

`c.FullPath()` 用路由模板（如 `/apps/:id`）而非实际请求路径，避免同一接口因为路径参数不同被记成一堆不同的行，也避免把应用 ID 等信息写进 path 字段（脱敏考虑，同时也更适合按接口聚合统计）。

### Repository / Service / Handler（与 `audit_logs` 同款结构，不赘述完整代码）

- `internal/repository/api_request_log_repository.go`：`APIRequestLogListFilter{Method, Path, Status *int, ActorUserID uint, StartTime/EndTime *time.Time, Page, PageSize}`，`Record`/`List`。
- `internal/service/api_request_log_service.go`：`APIRequestLogService`，`Record` 同样是 fire-and-forget（失败只 `log.Printf`，不阻断真实请求——中间件里调用它本来就在响应已经发出之后，但仍要保证不 panic）。
- `internal/handler/api_request_log_handler.go`：`GET /api/v1/api-logs`，鉴权同 `/audit-logs`（任意已登录角色，只挂 `JWTAuth`）。

## 前端改造（`BeetleShieldFrontend`）

1. 新增 `src/api/apiLogs.ts`：`listApiLogs(params)` 调 `GET /api/v1/api-logs`。
2. `Logs.tsx` 的"API 交互审计" tab 改成调 `listApiLogs`，直接用真实的 `method`/`path`/`status`/`latencyMs`/`clientIp`，不再从 `audit_logs` 里摘取非下载条目伪装。
3. "级别"下拉框目前对 tab 2（API 交互审计）、tab 3（交付下载记录）不生效：
   - tab 2 现在有真实 `status` 了，按状态码区间映射一个"级别"用于筛选：`2xx→SUCCESS`、`3xx/4xx→WARN`、`5xx→ERROR`。
   - tab 3（下载记录）没有自然的"级别"概念（下载只在成功时才有 `audit_logs` 记录），选中"级别"时该 tab 不受影响是符合预期的——把级别选择器在 tab 3 激活时禁用/置灰，而不是让它看起来生效却无声无效。
4. 把当前"一次性拉 100/50 条、本地过滤"的模式，改成把日期范围/搜索关键字作为真实 query 参数传给后端，并让 antd `Table` 的分页触发真正的服务端翻页请求（`page`/`pageSize` 从 UI 传给 `listAuditLogs`/`listApiLogs`/`listHardeningTasks`，而不是固定拉一批到本地再切页）。

## 测试

延续既有模式（真实本地 Postgres）：

- `internal/repository/api_request_log_repository_test.go`：`Record`+`List` 筛选组合。
- `internal/middleware/request_log_test.go`（或并入现有 `internal/handler/*_test.go` 的端到端用例）：验证一次真实 HTTP 请求后 `api_request_logs` 里出现一条记录，`Status`/`Method`/`Path` 与实际请求一致，`ActorUserID` 在鉴权路由上非零。
- 七个失败审计改造点，每个补一个"失败路径产生一条 `Success:false` 审计记录"的回归测试（复用子项目五已经建立的 `findAuditLogForTarget` 之类的辅助函数）。
- 前端：手动过一遍 4 个 tab 的搜索/日期范围/分页，确认不再有"选了条件但结果没变"的情况。
