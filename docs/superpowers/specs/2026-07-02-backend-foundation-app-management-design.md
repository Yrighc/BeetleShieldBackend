# BeetleShield 后端 - 子项目一：基础设施 + 应用管理

日期：2026-07-02

## 背景与范围

BeetleShield 是一个 Android 应用加固管理平台。加固引擎已具备，前端管理页面已在 `BeetleShieldFrontend` 完成（Dashboard / 应用管理 / 加固流水线 / 策略中心 / 加固报告 / 日志审计 / 用户管理 共 7 个页面，均为 mock 数据）。

后端需要用 Go + Gin 从零搭建，覆盖上述 7 个页面的服务端能力。由于这些模块之间存在依赖顺序（流水线依赖应用管理和策略、报告依赖流水线、Dashboard 依赖全部模块聚合数据），决定分批设计与实现，避免一次性定义过多尚不存在的功能。

**本子项目（子项目一）范围**：
1. 项目骨架（Go + Gin + PostgreSQL + MinIO 本地开发环境）
2. 登录鉴权（JWT），支撑后续所有模块的接口保护
3. 应用管理模块：APK/AAB 上传（含自动解析包名/版本、计算 MD5/SHA256、存储到 MinIO）、列表筛选、详情、删除、下载

**明确不在本子项目范围内**（留给后续子项目）：
- 用户管理页面的完整 CRUD（创建用户、禁用/启用、RBAC 权限矩阵接口）——本子项目只建 `users` 表并 seed 一个默认管理员，支撑登录闭环
- 策略中心、加固流水线（含加固引擎对接）、加固报告、日志审计、Dashboard 聚合接口
- 应用的"加固历史"记录（`app_hardening_history` 之类的表）——这是流水线模块的任务记录，届时再设计

## 技术栈

- Go 1.22+，Gin web 框架
- GORM + PostgreSQL（AutoMigrate 管理表结构，阶段一数据量小暂不引入独立 migration 工具）
- MinIO（`minio-go` SDK）存储 APK/AAB 原始文件
- JWT（`golang-jwt/jwt`）无状态鉴权，密码用 bcrypt 加密
- 配置：`.env` + viper，环境变量可覆盖
- 本地开发：`docker-compose.yml` 一键起 PostgreSQL + MinIO

## 项目结构

```
BeetleShieldBackend/
├── cmd/server/main.go
├── internal/
│   ├── config/          # viper 配置加载
│   ├── router/          # gin 路由注册
│   ├── middleware/      # jwt鉴权、cors、日志、recover
│   ├── handler/         # http handler（auth, app）
│   ├── service/         # 业务逻辑
│   ├── repository/      # gorm 数据访问
│   ├── model/           # gorm model 定义
│   └── pkg/
│       ├── jwtutil/
│       ├── storage/     # minio 封装
│       └── response/    # 统一响应结构
├── docker-compose.yml   # postgres + minio
├── .env.example
├── go.mod
└── Makefile
```

## 数据模型

### users 表

| 字段 | 类型 | 说明 |
|---|---|---|
| id | uint (PK) | |
| name | string | 真实姓名 |
| email | string, unique | 登录账号 |
| password_hash | string | bcrypt |
| role | string enum | `admin` / `developer` / `auditor` |
| department | string | 所属部门 |
| status | string enum | `active` / `disabled` |
| last_login_at | *time.Time | |
| created_at / updated_at | time.Time | |

启动时 seed 一个默认管理员账号（邮箱通过 `.env` 配置，如 `admin@beetleshield.com`，初始密码启动日志打印一次，方便首次登录）。

### apps 表

| 字段 | 类型 | 说明 |
|---|---|---|
| id | uint (PK) | |
| name | string | 应用名称 |
| package_name | string, indexed | 包名（自动解析或手动兜底） |
| version | string | 版本号（自动解析或手动兜底） |
| tag | string enum | `finance`/`game`/`tool`/`ecommerce` |
| status | string enum | `unprotected`/`processing`/`completed`/`failed`。本子项目上传后恒为 `unprotected`，其余状态由后续加固流水线模块驱动流转 |
| risk_level | *string enum | `low`/`medium`/`high`/`critical`，本子项目为空，后续风险评估模块填充 |
| file_size | int64 | 字节数 |
| object_key | string | MinIO 对象路径 |
| md5 / sha256 | string | 上传时流式计算 |
| uploaded_by | uint (FK users.id) | |
| created_at / updated_at | time.Time | |

## API 接口

统一前缀 `/api/v1`，统一响应结构：

```go
type Response struct {
    Code    int         `json:"code"`    // 0=成功，其他=业务错误码
    Message string      `json:"message"`
    Data    interface{} `json:"data,omitempty"`
}
```

### 鉴权

| Method | Path | 说明 |
|---|---|---|
| POST | `/auth/login` | `{email, password}` → `{token, user}` |
| GET | `/auth/me` | 需 Bearer Token，返回当前用户信息 |

### 应用管理（均需 JWT；细粒度按角色的写权限限制留给用户管理子项目一起做）

| Method | Path | 说明 |
|---|---|---|
| POST | `/apps/upload` | multipart：`file` + `tag`（+ 可选 `packageName`/`version` 手动兜底）。服务端解析扩展名、算 MD5/SHA256、解析 AndroidManifest 提取包名/版本、上传 MinIO、建应用记录 |
| GET | `/apps` | 列表，支持 `search`（应用名/包名）、`status`、`tag` 过滤 + 分页 |
| GET | `/apps/:id` | 详情 |
| DELETE | `/apps/:id` | 删除记录 + 删除 MinIO 对象 |
| GET | `/apps/:id/download-url` | 返回原始文件的 MinIO 预签名下载 URL（15 分钟有效期） |

## 上传与存储流程

```
客户端 POST /apps/upload (multipart file + tag)
  → 校验扩展名(.apk/.aab)和大小上限（配置项，默认 4GB）
  → 边读边算 MD5/SHA256（流式，不全量加载到内存）
  → 解析 AndroidManifest 提取 packageName/versionName
     - APK：解析 AndroidManifest.xml 二进制 XML
     - AAB：解析 protobuf 格式 manifest
     - 解析失败且请求未提供手动 packageName/version → 返回 422，附清晰错误信息，前端可重新提交并手动填写
  → 上传原始文件到 MinIO（bucket: beetleshield-apps，object key: {packageName}/{sha256前12位}/{原始文件名}）
  → 写 apps 表记录（status=unprotected, uploaded_by=当前用户）
  → 返回应用详情
```

失败处理：MinIO 上传失败 → 不写数据库记录，直接返回错误。

## 鉴权与错误处理

- JWT payload：`{user_id, role, exp}`，有效期 24h，`Authorization: Bearer <token>` 头传递
- Gin 中间件解析校验 token，失败返回 401；校验通过后把 `user_id`/`role` 存入 `gin.Context`
- 统一 recover 中间件捕获 panic 转 500
- 参数校验用 gin binding tag + validator，校验失败统一返回 400 及具体字段错误

## 本地开发与测试

- `docker-compose.yml`：postgres:16 + minio（含自动建 bucket 的初始化）
- `.env.example`：数据库连接串、MinIO endpoint/ak/sk、JWT secret、上传大小上限等
- `Makefile`：`make run`、`make dev-up`（起 docker-compose）、`make test`
- 测试：
  - 纯逻辑单元测试（JWT 生成校验、密码哈希、MD5/SHA256 计算）
  - Handler/Service 层测试跑在 docker-compose 起的真实 Postgres + MinIO 上，覆盖登录、上传、列表筛选、删除主链路
  - 提供 curl/Postman 示例脚本方便手动联调前端

## 后续子项目（不在本次实现范围，仅记录顺序供参考）

1. 用户管理（Users 页面完整 CRUD + RBAC 权限矩阵接口）
2. 策略中心（加固策略模板 CRUD）
3. 加固流水线（对接已有加固引擎、任务队列、步骤状态流转、加固历史记录）
4. 加固报告（加固前后风险评分对比）
5. 日志审计（加固运行日志 + API 调用审计日志）
6. Dashboard 聚合接口
