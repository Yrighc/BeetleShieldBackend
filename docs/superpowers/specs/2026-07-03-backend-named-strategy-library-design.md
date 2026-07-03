# BeetleShield 后端 - 策略中心升级：默认策略 + 命名策略库

日期：2026-07-03

## 背景与范围

现有策略中心按子项目三的设计实现为“单一全局策略”：`GET /strategies/current` 读取当前策略，`PUT /strategies/current` 保存并覆盖该策略。后续加固流水线创建任务时，如果请求没有直接传 `strategySnapshot`，会读取这份当前策略并冻结到 `HardeningTask.StrategySnapshot`。

实际使用场景需要更灵活：运维人员会提前创建多套可命名的加固策略，例如“数信学院加固策略”“金融高强度策略”“基础兼容策略”；创建加固任务时按需选择其中一套。策略不需要和 App 固定绑定，App 只是被加固对象；策略是可复用的配置库。

本次升级范围：

1. 保留默认策略能力，继续支持 `GET /strategies/current` 与 `PUT /strategies/current`。
2. 新增命名策略库 CRUD，允许创建、查询、更新、删除普通策略。
3. 创建加固任务时新增可选 `strategyId`；传入则使用指定命名策略，不传则使用默认策略。
4. 所有加固任务仍冻结策略快照，后续策略更新不影响历史任务。

明确不在本次范围内：

- 不新增独立 `projects` 表。
- 不把策略和 `apps` 绑定。
- 不修改 APK/AAB 上传流程。
- 不把三个预设模板改成可删除的数据库记录；它们仍是后端常量，用于一键创建或填充策略。
- 不回填历史任务的 `StrategySnapshot`。历史任务已经有快照，保持原样。

## 产品语义

策略中心有两类策略：

- 默认策略：系统兜底策略，最多一条。创建加固任务时如果没有传 `strategyId`，后端使用默认策略。默认策略不能删除。
- 命名策略：运维人员创建的可复用策略。创建加固任务时传 `strategyId` 使用该策略。

默认策略和命名策略使用同一张 `strategies` 表、同一个模型，靠 `IsDefault` 区分。这样加固流水线只需要面对“解析出一个具体 `Strategy` 并冻结快照”的统一行为，不需要区分策略来源。

## 数据模型

在现有 `model.Strategy` 上扩展元数据字段：

```go
type Strategy struct {
    ID            uint                `gorm:"primaryKey" json:"id"`
    Name          string              `gorm:"size:120;not null;index" json:"name"`
    Description   string              `gorm:"size:500" json:"description"`
    IsDefault     bool                `gorm:"not null;default:false;index" json:"isDefault"`
    Frida         bool                `json:"frida"`
    Xposed        bool                `json:"xposed"`
    Debugger      bool                `json:"debugger"`
    Emulator      bool                `json:"emulator"`
    DexLevel      DexObfuscationLevel `gorm:"size:20" json:"dexLevel"`
    StringEncrypt bool                `json:"stringEncrypt"`
    ResMix        bool                `json:"resMix"`
    SoShell       SoShellType         `gorm:"size:20" json:"soShell"`
    SoStrength    int                 `json:"soStrength"`
    TargetSos     []string            `gorm:"serializer:json" json:"targetSos"`
    RootDetect    bool                `json:"rootDetect"`
    Signature     bool                `json:"signature"`
    AntiHook      bool                `json:"antiHook"`
    ResEncrypt    bool                `json:"resEncrypt"`
    CreatedBy     uint                `json:"createdBy"`
    UpdatedBy     uint                `json:"updatedBy"`
    CreatedAt     time.Time           `json:"createdAt"`
    UpdatedAt     time.Time           `json:"updatedAt"`
}
```

兼容旧数据：

- 现有旧表没有 `name`、`is_default`、`created_by`。`AutoMigrate` 会新增列。
- 迁移后如果存在旧策略行但没有默认策略，服务层首次读取默认策略时将最早一条策略补齐为默认策略，名称设为“默认加固策略”。
- 如果表中没有任何策略，`GetCurrent` 继续返回金融级模板的默认值，不强制落库。

约束策略：

- 普通策略名称不能为空。
- 普通策略名称建议做唯一校验，避免运维列表里出现两个同名策略。因为当前项目不依赖数据库约束做业务完整性，唯一性在 repository/service 层查询并返回业务错误。
- 默认策略名称固定返回“默认加固策略”，`PUT /strategies/current` 可更新参数，不需要前端传名称。
- 默认策略不能通过删除接口删除。

## API 接口

统一前缀 `/api/v1`，鉴权延续现有策略中心规则。

| Method | Path | 权限 | 说明 |
|---|---|---|---|
| GET | `/strategies/templates` | 任意已登录角色 | 返回三个预设模板 |
| GET | `/strategies/current` | 任意已登录角色 | 返回默认策略；无数据时返回金融级模板默认值 |
| PUT | `/strategies/current` | 仅 `admin` | 更新默认策略参数 |
| GET | `/strategies` | 任意已登录角色 | 分页查询普通命名策略，不包含默认策略 |
| POST | `/strategies` | 仅 `admin` | 创建普通命名策略 |
| GET | `/strategies/:id` | 任意已登录角色 | 查询普通命名策略详情；默认策略仍通过 `/strategies/current` 查询 |
| PUT | `/strategies/:id` | 仅 `admin` | 更新普通命名策略 |
| DELETE | `/strategies/:id` | 仅 `admin` | 删除普通命名策略 |

`GET /strategies` 查询参数：

- `page`：默认 1。
- `pageSize`：默认 10。
- `search`：按 `name`、`description` 模糊搜索。

`POST /strategies` 与 `PUT /strategies/:id` 请求体在现有策略参数基础上新增：

```json
{
  "name": "数信学院加固策略",
  "description": "面向数信学院 App 的高强度加固配置",
  "frida": true,
  "xposed": true,
  "debugger": true,
  "emulator": true,
  "dexLevel": "high",
  "stringEncrypt": true,
  "resMix": true,
  "soShell": "vmp",
  "soStrength": 90,
  "targetSos": ["libnative-lib.so"],
  "rootDetect": true,
  "signature": true,
  "antiHook": true,
  "resEncrypt": true
}
```

响应仍使用统一 `{code, message, data}` 包装。

## 加固任务创建

`POST /hardening-tasks` 请求体新增可选字段：

```json
{
  "appId": 1,
  "strategyId": 12,
  "vmpRulesText": "com.example.**",
  "enableFileIntegrityCheck": true,
  "enableProxyDetect": true
}
```

行为规则：

- `strategyId > 0`：按 ID 查询策略，使用其完整参数作为快照，`StrategyName` 写入该策略 `Name`。
- `strategyId` 未传或为 0：读取默认策略，`StrategyName` 写入“默认加固策略”。
- `strategyId` 不存在：返回 404，错误文案为“加固策略不存在”。
- `strategyId` 指向默认策略：可以接受，结果与不传 `strategyId` 等价。
- 保留 `strategySnapshot` 入参仅作为兼容旧测试和旧调用方的过渡能力；新前端不再使用它。若同时传 `strategyId` 和 `strategySnapshot`，`strategyId` 优先。

`HardeningTask` 暂不新增 `StrategyID` 字段。原因是任务的业务依据是冻结后的 `StrategySnapshot`，不是策略表当前行；保存 `strategyName` 已足够用于列表展示和审计。后续若需要按策略统计任务，再单独增加 `StrategyID`。

## 内部实现

### Repository

`StrategyRepository` 从单行 upsert 扩展为多策略仓储：

```go
type StrategyListFilter struct {
    Search   string
    Page     int
    PageSize int
}

func (r *StrategyRepository) GetCurrent() (*model.Strategy, error)
func (r *StrategyRepository) SaveCurrent(strategy *model.Strategy) error
func (r *StrategyRepository) List(filter StrategyListFilter) ([]model.Strategy, int64, error)
func (r *StrategyRepository) FindByID(id uint) (*model.Strategy, error)
func (r *StrategyRepository) FindRegularByID(id uint) (*model.Strategy, error)
func (r *StrategyRepository) Create(strategy *model.Strategy) error
func (r *StrategyRepository) Update(strategy *model.Strategy) error
func (r *StrategyRepository) Delete(id uint) error
func (r *StrategyRepository) NameExists(name string, excludeID uint) (bool, error)
func (r *StrategyRepository) PromoteLegacyCurrent() (*model.Strategy, error)
```

`GetCurrent` 查询 `is_default = true`。无默认策略时返回 `gorm.ErrRecordNotFound`，由 service 决定是否升级旧行或返回模板默认值。`FindByID` 用于加固任务选择策略，允许查到默认策略；`FindRegularByID` 用于策略库详情、更新、删除，只返回 `is_default = false` 的普通命名策略。

### Service

新增和调整错误：

```go
var (
    ErrStrategyNotFound      = errors.New("strategy not found")
    ErrStrategyNameRequired  = errors.New("strategy name is required")
    ErrStrategyNameExists    = errors.New("strategy name already exists")
    ErrDefaultStrategyDelete = errors.New("default strategy cannot be deleted")
)
```

新增输入结构：

```go
type StrategyPayloadInput struct {
    Name        string
    Description string
    Frida       bool
    // 其余策略参数沿用 SaveStrategyInput
}
```

Service 负责：

- 统一校验策略参数枚举和值域。
- 创建/更新普通策略时校验名称。
- `GetCurrent` 处理旧数据升级：如果没有默认策略但存在旧策略行，将旧策略补齐默认元数据并保存；如果表为空，返回金融模板默认值。
- `SaveCurrent` 只更新默认策略，不影响普通命名策略。
- `ResolveForHardening(strategyID uint)` 返回创建加固任务需要的策略和策略名。

### Handler + Router

`StrategyHandler` 保留现有三个方法，并新增：

- `List`
- `Create`
- `Get`
- `Update`
- `Delete`

路由顺序必须把固定路径 `/templates`、`/current` 放在 `/:id` 之前：

```go
strategies.GET("/templates", deps.StrategyHandler.Templates)
strategies.GET("/current", deps.StrategyHandler.GetCurrent)
strategies.PUT("/current", middleware.RequireRole(model.RoleAdmin), deps.StrategyHandler.SaveCurrent)
strategies.GET("", deps.StrategyHandler.List)
strategies.POST("", middleware.RequireRole(model.RoleAdmin), deps.StrategyHandler.Create)
strategies.GET("/:id", deps.StrategyHandler.Get)
strategies.PUT("/:id", middleware.RequireRole(model.RoleAdmin), deps.StrategyHandler.Update)
strategies.DELETE("/:id", middleware.RequireRole(model.RoleAdmin), deps.StrategyHandler.Delete)
```

### 审计日志

沿用 `AuditActionStrategySave`，不新增 action 常量：

- 创建普通策略：`TargetType=strategy`，`TargetID=strategy.ID`，`Detail="创建策略：" + strategy.Name`。
- 更新普通策略：`Detail="更新策略：" + strategy.Name`。
- 删除普通策略：`Detail="删除策略：" + strategy.Name`。
- 更新默认策略：保留现有 `Detail="全局加固策略已更新"`。
- 失败路径继续记录 `Success=false`，detail 中带错误原因。

## 测试

按 TDD 拆分实现，先补失败测试再写代码：

- `internal/repository/strategy_repository_test.go`
  - `SaveCurrent` 只维护一条默认策略。
  - `List` 只返回普通命名策略，不返回默认策略。
  - `NameExists` 支持排除当前 ID。
  - `Delete` 删除普通策略后不可再查。
- `internal/service/strategy_service_test.go`
  - 无数据时 `GetCurrent` 返回金融模板默认值。
  - 旧单行策略会被升级为默认策略。
  - 创建普通策略要求名称且名称唯一。
  - 默认策略不能删除。
  - `ResolveForHardening(0)` 返回默认策略。
  - `ResolveForHardening(strategyID)` 返回指定命名策略。
- `internal/service/hardening_service_test.go`
  - 创建加固任务传 `strategyId` 时冻结指定策略快照并写入策略名称。
  - 不传 `strategyId` 时继续使用默认策略。
  - 不存在的 `strategyId` 返回策略不存在错误。
- `internal/handler/strategy_handler_test.go`
  - 普通角色可读列表和详情。
  - `developer`/`auditor` 创建、更新、删除返回 403。
  - `admin` 可创建、更新、删除普通策略。
  - 默认策略删除接口不可用，因为默认策略不走普通删除路径。
- `internal/handler/hardening_handler_test.go`
  - `POST /hardening-tasks` 支持 `strategyId`。
  - 不存在策略返回 404。

最终验证命令：

```bash
make test
```

若本地 Postgres/MinIO 未启动，先执行 `make dev-up`，再运行测试。

## 兼容性与风险

- 数据库需要 `AutoMigrate` 增加新列，无需新增物理外键。
- 旧的 `/strategies/current` 调用保持兼容。
- 旧的加固任务创建调用不传策略时仍可工作，使用默认策略。
- 删除普通策略不会影响历史任务，因为历史任务已经保存快照。
- 策略名称唯一性如果只在 service 层检查，并发创建同名策略时仍可能出现竞态；当前项目没有显式使用数据库唯一约束，本次延续既有风格。若后续对并发一致性要求提高，再加唯一索引和迁移修复。
