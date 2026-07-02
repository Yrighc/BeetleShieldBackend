# BeetleShield 后端 - 子项目三：策略中心

日期：2026-07-02

## 背景与范围

子项目一（基础设施 + 应用管理）、子项目二（用户管理 + RBAC）已完成并合入 `main`。前端 Strategy 页面（策略中心）展示一份可编辑的加固策略配置（反调试开关、DEX 混淆强度、SO 加壳类型与强度、系统级防护开关等），支持一键加载三个预设模板（金融级/游戏级/基础加固），编辑后保存。页面文案提到"上传 APK 时可为单个应用独立覆盖此配置"，但目前应用管理的上传接口还没有关联任何策略字段——那属于加固流水线子项目要做的事，不在本次范围内。

**本子项目（子项目三）范围**：
1. 单一全局生效策略的读写接口（对应前端页面当前编辑的那份配置）
2. 三个预设模板（金融级/游戏级/基础加固）的后端常量定义 + 查询接口

**明确不在本子项目范围内**：
- 按客户/项目区分的多个命名策略（讨论过，明确决定先做单一全局策略，多策略是记录下来的后续扩展方向，前端目前也没有对应的多策略选择 UI）
- 应用上传时关联/覆盖策略（留给加固流水线子项目，那时上传接口才会真正触发加固任务）
- 策略模板的用户自定义新增/删除（三个模板是后端常量，不支持通过接口增删模板本身）

## 数据模型

新表 `strategies`，设计上只会有一行数据，代表"当前生效的全局策略"：

```go
type SoShellType string
const (
    SoShellNone     SoShellType = "none"
    SoShellAES      SoShellType = "aes"
    SoShellVMP      SoShellType = "vmp"
    SoShellCustomSo SoShellType = "custom_so"
)

type DexObfuscationLevel string
const (
    DexLevelLow    DexObfuscationLevel = "low"
    DexLevelMedium DexObfuscationLevel = "medium"
    DexLevelHigh   DexObfuscationLevel = "high"
)

type Strategy struct {
    ID            uint                `gorm:"primaryKey"`
    Frida         bool
    Xposed        bool
    Debugger      bool
    Emulator      bool
    DexLevel      DexObfuscationLevel `gorm:"size:20"`
    StringEncrypt bool
    ResMix        bool
    SoShell       SoShellType         `gorm:"size:20"`
    SoStrength    int
    TargetSos     []string            `gorm:"serializer:json"`
    RootDetect    bool
    Signature     bool
    AntiHook      bool
    ResEncrypt    bool
    UpdatedBy     uint
    CreatedAt     time.Time
    UpdatedAt     time.Time
}
```

`TargetSos` 用 GORM 内置的 `serializer:json` 标签存成 JSON 数组，不引入 `github.com/lib/pq` 等新依赖（原本考虑用 Postgres 原生数组类型 `pq.StringArray`，但那需要新增依赖，按约定改用不需要新依赖的方案）。后端不对 `TargetSos` 里的字符串做白名单校验，允许任意 so 文件名，避免过度设计成跟前端下拉列表强耦合。

## API 接口

统一前缀 `/api/v1`，鉴权方式与现有模块一致（JWT Bearer Token）：

| Method | Path | 权限 | 说明 |
|---|---|---|---|
| GET | `/strategies/templates` | 任意已登录角色 | 返回三个预设模板（金融级/游戏级/基础加固）的完整参数 |
| GET | `/strategies/current` | 任意已登录角色 | 返回当前生效的全局策略；从未保存过时返回金融级模板的默认值（不落库） |
| PUT | `/strategies/current` | 仅 `admin` | 保存/更新当前生效策略，全量覆盖（不做部分字段 patch） |

## 内部实现结构

### Repository（新建 `internal/repository/strategy_repository.go`）

```go
func NewStrategyRepository(db *gorm.DB) *StrategyRepository
func (r *StrategyRepository) GetCurrent() (*model.Strategy, error)  // 查表里唯一一行；无数据返回 gorm.ErrRecordNotFound
func (r *StrategyRepository) Save(strategy *model.Strategy) error   // upsert：已有行则更新，无则创建
```

### Service（新建 `internal/service/strategy_service.go`）

```go
type SaveStrategyInput struct {
    Frida, Xposed, Debugger, Emulator                bool
    DexLevel                                          model.DexObfuscationLevel
    StringEncrypt, ResMix                             bool
    SoShell                                            model.SoShellType
    SoStrength                                         int
    TargetSos                                          []string
    RootDetect, Signature, AntiHook, ResEncrypt        bool
}

var (
    ErrInvalidDexLevel   = errors.New("invalid dex obfuscation level")
    ErrInvalidSoShell    = errors.New("invalid so shell type")
    ErrInvalidSoStrength = errors.New("so strength must be between 0 and 100")
)

func NewStrategyService(strategyRepo *repository.StrategyRepository) *StrategyService
func (s *StrategyService) Templates() map[string]model.Strategy
func (s *StrategyService) GetCurrent() (*model.Strategy, error)
func (s *StrategyService) Save(input SaveStrategyInput, updatedBy uint) (*model.Strategy, error)
```

`Templates()` 返回三个键为 `finance`/`game`/`basic` 的预设模板常量（参数取值参照前端 `templates` 对象）。`Save` 校验 `DexLevel`/`SoShell` 是否落在合法枚举值内、`SoStrength` 是否在 0-100 区间，非法则返回对应哨兵错误（映射为 400）。

### Handler + 路由

`internal/handler/strategy_handler.go`：`Templates`/`GetCurrent`/`SaveCurrent` 三个方法。

`internal/router/router.go` 新增 `/strategies` 分组：`GET /templates`、`GET /current` 只挂 `JWTAuth`（三个角色都能读）；`PUT /current` 额外挂 `RequireRole(model.RoleAdmin)`。

`cmd/server/main.go` 增加 `StrategyRepository`/`StrategyService`/`StrategyHandler` 的依赖组装，并把新 model 加入 `db.Migrate`。

## 测试

延续既有模式：

- Repository/Service/Handler 测试跑在真实本地 Postgres（`root`/`root`@`localhost:5432`/`beetleshield`）上
- Service 层覆盖：`GetCurrent` 在无数据时返回金融级默认值、`Save` 对非法 `DexLevel`/`SoShell`/`SoStrength` 的校验、`Save` 后 `GetCurrent` 能读到刚保存的值
- Handler 层做一次 RBAC 回归：`developer`/`auditor` 角色能 `GET /strategies/current`，但 `PUT /strategies/current` 返回 403；`admin` 角色能正常保存
