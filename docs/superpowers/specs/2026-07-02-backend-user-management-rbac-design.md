# BeetleShield 后端 - 子项目二：用户管理 + RBAC 权限落地

日期：2026-07-02

## 背景与范围

子项目一（基础设施 + 应用管理）已完成并合入 `main`：项目骨架、JWT 登录鉴权、`users` 表（含 `role`/`status` 枚举）、以及应用管理的完整上传/列表/详情/删除/下载闭环。子项目一里 `/api/v1/apps/*` 的所有写操作目前只要求"已登录"，没有做角色区分；`users` 表也只有登录闭环需要的最小能力（`Create`/`FindByEmail`/`FindByID`/`UpdateLastLogin`/`DeleteByEmail`），前端 Users 页面展示的用户管理 CRUD 和 RBAC 权限矩阵表都还没有对应的后端接口。

**本子项目（子项目二）范围**：
1. RBAC 中间件：`middleware.RequireRole(roles ...model.UserRole)`，并把它接到子项目一已合并的应用管理写操作路由上
2. 用户管理模块：用户列表（搜索+角色筛选+分页）、创建用户、编辑用户、启用/禁用用户

**明确不在本子项目范围内**：
- 删除用户接口（前端没有对应的删除操作）
- 修改邮箱、修改密码/重置密码接口（涉及登录身份变更，风险更高，留给以后需要时再单独设计）
- 策略中心、加固流水线、加固报告、日志审计、Dashboard 聚合接口（仍是后续子项目）

## RBAC 角色 → 接口映射

依据前端 Users 页面的静态权限矩阵表，并把子项目一里尚未做角色区分的应用管理接口一并纳入：

| 接口 | 允许角色 |
|---|---|
| `GET /apps`、`GET /apps/:id` | `admin` / `developer` / `auditor`（只读，任意已登录角色） |
| `POST /apps/upload`、`DELETE /apps/:id`、`GET /apps/:id/download-url` | `admin` / `developer` |
| `GET /users`、`POST /users`、`PATCH /users/:id`、`PATCH /users/:id/status` | 仅 `admin` |
| `GET /auth/me` | 任意已登录角色（不变） |

### RBAC 中间件

`internal/middleware/rbac.go`：

```go
func RequireRole(roles ...model.UserRole) gin.HandlerFunc
```

接在 `JWTAuth` 之后使用，从 `c.GetString(ContextRoleKey)`（`JWTAuth` 已经写入的角色）判断是否在允许列表里，不在则返回 403（`response.Error`，业务错误码区分于 401）。

这会修改子项目一里已合并的 `internal/router/router.go`，给现有 `apps` 分组的三个写操作路由加上 `RequireRole(model.RoleAdmin, model.RoleDeveloper)`。

## 用户管理 API

统一前缀 `/api/v1`，统一响应结构与鉴权方式与子项目一一致（JWT Bearer Token，`{code, message, data}` 响应体）。以下接口均需 `JWTAuth` + `RequireRole(model.RoleAdmin)`：

| Method | Path | 说明 |
|---|---|---|
| GET | `/users` | 列表，支持 `search`（姓名/邮箱模糊搜索）、`role` 筛选 + 分页（`page`/`pageSize`） |
| POST | `/users` | 创建：`{name, email, password, role, department}`。管理员直接设定初始密码，服务端用已有的 `hash.HashPassword` 哈希后入库；`status` 默认 `active` |
| PATCH | `/users/:id` | 编辑：`{name?, department?, role?}`（不支持改邮箱） |
| PATCH | `/users/:id/status` | 启用/禁用：`{status: "active"\|"disabled"}` |

### 设计决策

- **不提供 DELETE 接口**：前端表格只有编辑/启用/禁用操作，做删除是没有消费方的多余接口，遵循 YAGNI。
- **编辑接口不允许改邮箱**：邮箱是登录账号，修改邮箱涉及唯一性冲突处理和"登录身份变更"这类更复杂的场景，本次不做，需要时再单独设计。
- **禁止管理员禁用自己的账号**：`PATCH /users/:id/status` 里加保护——如果 `:id` 对应当前登录用户自己且目标状态是 `disabled`，返回 403（`ErrCannotDisableSelf`），防止管理员误操作把自己锁死，导致没有其他管理员账号时系统无法再管理。
- **创建用户时邮箱唯一性校验**：`POST /users` 若邮箱已存在，返回 409（`ErrEmailAlreadyExists`）。

## 内部实现结构

### Repository（`internal/repository/user_repository.go`，在子项目一已有方法基础上追加）

```go
type UserListFilter struct {
    Search   string
    Role     string
    Page     int
    PageSize int
}

func (r *UserRepository) List(filter UserListFilter) ([]model.User, int64, error)
func (r *UserRepository) Update(id uint, updates map[string]interface{}) error
func (r *UserRepository) UpdateStatus(id uint, status model.UserStatus) error
```

`List` 的筛选/分页写法与子项目一 `AppRepository.List` 保持一致（`ILIKE` 模糊搜索、`page < 1 → 1`、`pageSize < 1 → 10` 默认值）。

### Service（新建 `internal/service/user_service.go`）

```go
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

type UserService struct { ... }

func NewUserService(userRepo *repository.UserRepository) *UserService
func (s *UserService) List(filter repository.UserListFilter) ([]model.User, int64, error)
func (s *UserService) Create(input CreateUserInput) (*model.User, error)
func (s *UserService) Update(id uint, input UpdateUserInput) (*model.User, error)
func (s *UserService) UpdateStatus(id uint, status model.UserStatus, currentUserID uint) error
```

### Handler + 路由

`internal/handler/user_handler.go`：`List`/`Create`/`Update`/`UpdateStatus`，错误映射沿用子项目一的模式（sentinel error → HTTP 状态码 + 业务错误码）。

`internal/router/router.go` 新增 `/users` 分组，挂 `JWTAuth` + `RequireRole(model.RoleAdmin)`；同时给已有 `apps` 分组的 `POST /upload`、`DELETE /:id`、`GET /:id/download-url` 三个路由追加 `RequireRole(model.RoleAdmin, model.RoleDeveloper)`。

`cmd/server/main.go` 相应增加 `UserRepository`（已存在，复用）、`UserService`、`UserHandler` 的依赖组装。

## 测试

延续子项目一的模式：

- Repository/Service/Handler 测试都是跑在真实本地 Postgres（`root`/`root`@`localhost:5432`/`beetleshield`）上的集成测试，覆盖列表筛选分页、创建（含邮箱唯一性冲突）、编辑、启用/禁用（含"不能禁用自己"场景）
- RBAC 中间件（`RequireRole`）用 `httptest` 做纯单元测试，覆盖：允许角色通过、不允许角色返回 403、未带 token 返回 401 三种场景
- 应用管理路由追加角色限制后，需要补一个测试确认：`auditor` 角色调用 `POST /apps/upload`/`DELETE /apps/:id`/`GET /apps/:id/download-url` 会被拒绝（403），而 `GET /apps`/`GET /apps/:id` 仍然放行
