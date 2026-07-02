# BeetleShield 后端 - 子项目五：审计日志系统

日期：2026-07-02

## 背景与范围

子项目一~四（基础设施+应用管理、用户管理+RBAC、策略中心、加固流水线）均已完成并合入 `main`，前后端联调也已跑通完整的"上传→加固→下载"链路。前端"日志审计"页面目前有两个面板：加固日志（已对接真实的 `hardening_logs` 接口）、操作日志（仍是纯 mock）。前端 Users 页面已经展示了一份 RBAC 权限矩阵，其中"审计与运行日志查询"一项对 `admin`/`developer`/`auditor` 三个角色都是勾选状态——这是本子项目要实现的后端能力。

**本子项目（子项目五）范围**：
1. 一张审计日志表，记录平台内关键写操作的操作人、操作类型、目标对象、结果、来源 IP、时间
2. 一个只读查询接口，支持按操作人/操作类型/目标类型/结果/时间范围筛选，三个角色均可访问
3. 在以下写路径里显式记录审计日志：登录（成功/失败均记）、应用上传/删除、加固任务创建、策略保存、用户增/改/启禁用

**明确不在本子项目范围内**：
- 加固任务执行过程中的逐步骤日志（`hardening_logs` 表已经覆盖，不重复记录）
- 除登录外其他操作的"失败尝试"记录（例如应用删除因存在进行中任务而 409，本子项目不记录这类失败——只记录登录失败，因为登录失败是审计场景里最需要关注的信号；其他操作的校验失败对审计意义有限，属于过度设计，不做）
- 日志保留期限/自动清理（先无限保留，后续如有存储压力再考虑）
- 变更前后字段级 diff（例如策略保存记录"策略已更新"这样的摘要，不记录具体哪些字段从什么值变成什么值）

## 数据模型

新表 `audit_logs`，不设外键（延续本项目"引用完整性在应用层而非数据库层保证"的既定原则——`ActorUserID`/`TargetID` 都是普通字段，不加 `gorm:"foreignKey"`）：

```go
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

type AuditLog struct {
    ID          uint        `gorm:"primaryKey"`
    ActorUserID uint        `gorm:"index"`   // 0 表示未认证（如登录失败且邮箱不存在）
    ActorEmail  string      `gorm:"size:255"` // 快照，登录失败时用户可能压根不存在，不能依赖 join
    Action      AuditAction `gorm:"size:60;index"`
    TargetType  string      `gorm:"size:30"` // "app" | "hardening_task" | "strategy" | "user" | ""（登录场景为空）
    TargetID    uint        // 0 表示不适用
    Detail      string      `gorm:"size:255"` // 简短人类可读摘要，如应用名/包名、用户邮箱等
    IP          string      `gorm:"size:64"`
    Success     bool
    CreatedAt   time.Time   `gorm:"index"`
}
```

`ActorEmail` 是刻意冗余的快照字段：登录失败时可能压根查不到用户（邮箱不存在），此时 `ActorUserID` 为 0，只有 `ActorEmail` 能说明"谁在尝试登录"。

## API 接口

统一前缀 `/api/v1`，鉴权方式与现有模块一致：

| Method | Path | 权限 | 说明 |
|---|---|---|---|
| GET | `/audit-logs` | 任意已登录角色（admin/developer/auditor 均可） | 分页查询，query 参数：`page`、`pageSize`、`actorUserId`、`action`、`targetType`、`success`、`startTime`、`endTime` |

响应沿用现有的 `{items, total}` 分页壳。

## 内部实现结构

### Repository（新建 `internal/repository/audit_repository.go`）

```go
type AuditListFilter struct {
    ActorUserID uint
    Action      string
    TargetType  string
    Success     *bool // nil 表示不筛选
    StartTime   *time.Time
    EndTime     *time.Time
    Page        int
    PageSize    int
}

func NewAuditRepository(db *gorm.DB) *AuditRepository
func (r *AuditRepository) Record(log *model.AuditLog) error
func (r *AuditRepository) List(filter AuditListFilter) ([]model.AuditLog, int64, error)
```

### Service（新建 `internal/service/audit_service.go`）

```go
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

func NewAuditService(auditRepo *repository.AuditRepository) *AuditService
func (s *AuditService) Record(input RecordAuditInput) // 无返回值：审计写入失败只记日志到 stdout，不向上传播错误
func (s *AuditService) List(filter repository.AuditListFilter) ([]model.AuditLog, int64, error)
```

`Record` 刻意不返回 `error`：审计是旁路能力，不应该因为审计表写入失败（比如数据库瞬时抖动）就让一次成功的应用删除/用户创建回滚或报错给用户。写入失败时用 `log.Printf` 记一条日志，行为上与 worker 包里"MinIO 清理失败只告警不阻断"的既有模式一致。

### 现有写路径的改造

审计记录采用"服务层显式调用"，需要往下列方法的入参里新增 `IP string` 字段（现有代码已经有 handler 从 `middleware.ContextUserIDKey` 取 `CreatedBy`/`UpdatedBy` 塞进 Input 结构体传给 service 的先例，`IP` 用同样的方式从 `c.ClientIP()` 取出后传入）：

| Service 方法 | 改动 | 记录时机 |
|---|---|---|
| `AuthService.Login(email, password, ip string)` | 新增 `ip` 参数 | 成功和失败都记；失败时 `ActorUserID=0`，`ActorEmail=email`（输入的邮箱，不管是否存在） |
| `AppService.Upload(ctx, input UploadInput)` | `UploadInput` 新增 `IP string` | 仅上传成功后记，`Detail` 为应用名+包名 |
| `AppService.Delete(ctx, id uint, ip string)` | 新增 `ip` 参数 | 仅删除成功后记（删除前已查出的应用名作为 `Detail`） |
| `HardeningService.Create(ctx, input CreateHardeningTaskInput)` | `CreateHardeningTaskInput` 新增 `IP string` | 仅任务创建成功后记，`Detail` 为应用名+任务编号 |
| `StrategyService.Save(input SaveStrategyInput, updatedBy uint, ip string)` | 新增 `ip` 参数 | 仅保存成功后记，`Detail` 固定为"全局加固策略已更新" |
| `UserService.Create(input CreateUserInput)` | `CreateUserInput` 新增 `IP string` | 仅创建成功后记，`Detail` 为新用户邮箱+角色 |
| `UserService.Update(id, input UpdateUserInput, ip string)` | 新增 `ip` 参数 | 仅更新成功后记，`Detail` 固定为"用户资料已更新" |
| `UserService.UpdateStatus(id, status, currentUserID, ip string)` | 新增 `ip` 参数 | 仅变更成功后记，`Detail` 为"状态变更为 启用/禁用" |

对应的 handler 都要加一行 `ip := c.ClientIP()` 并传入 service 调用。

### Handler + 路由

`internal/handler/audit_handler.go`：`List` 方法，把 query 参数解析成 `repository.AuditListFilter`（`success` 参数为空串时不筛选，`"true"`/`"false"` 分别转成 `*bool`；`startTime`/`endTime` 按 RFC3339 解析，解析失败按 400 处理）。

`internal/router/router.go` 新增 `/audit-logs` 路由组：`GET ""` 只挂 `JWTAuth`（不额外挂 `RequireRole`，三角色皆可读）。

`cmd/server/main.go` 增加 `AuditRepository`/`AuditService`/`AuditHandler` 的依赖组装，并把 `AuditLog` 加入 `db.Migrate`；同时把 `auditService` 注入 `AuthService`/`AppService`/`HardeningService`/`StrategyService`/`UserService` 的构造函数（这几个 service 各自持有一个 `*service.AuditService` 字段）。

## 测试

延续既有模式，Repository/Service/Handler 测试跑在真实本地 Postgres 上：

- Repository：`Record` + `List` 的筛选组合（按 action/targetType/success/时间范围）
- Service：`AuditService.Record` 在 repo 写入失败时不 panic、不返回错误（用一个会失败的假 repo 验证）
- 各业务 service 的回归测试：验证对应操作成功后 `audit_logs` 表里出现了预期的一条记录（`Action`/`TargetType`/`TargetID`/`Success` 字段正确），失败路径（如重复邮箱建用户）不产生审计记录
- 登录相关：验证成功登录和密码错误登录都各产生一条记录，且失败记录的 `ActorUserID=0`、`ActorEmail` 为输入邮箱
- Handler 层：`GET /audit-logs` 对三个角色都返回 200（不做 403 校验，因为设计上就是全角色可读）
