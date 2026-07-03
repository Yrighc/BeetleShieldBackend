# BeetleShield Backend 部署文档

本文档覆盖两种部署方式的完整流程：本地开发（Go 原生进程 + Docker 依赖）和
全容器化部署（应用本身也打包进 Docker）。`README.md` 只保留快速上手指引，
详细配置、故障排查、生产注意事项都在本文档里。

## 目录

- [架构与依赖概览](#架构与依赖概览)
- [环境变量参考](#环境变量参考)
- [方式一：本地开发部署](#方式一本地开发部署)
- [方式二：全容器化部署](#方式二全容器化部署)
- [验证部署是否成功](#验证部署是否成功)
- [生产环境注意事项](#生产环境注意事项)
- [数据持久化与备份](#数据持久化与备份)
- [更新部署](#更新部署)
- [常见问题排查](#常见问题排查)

## 架构与依赖概览

进程组成（`cmd/server/main.go` 里在同一个进程内启动）：

- HTTP API server（Gin），监听 `SERVER_PORT`（默认 `8080`）
- 加固 worker（`internal/worker.HardeningWorker`），每 3 秒轮询一次 `hardening_tasks`
  队列，串行执行加固任务

外部依赖（必须都能连通）：

- **PostgreSQL**：业务数据存储，`db.Migrate` 在进程启动时自动建表/加列，
  `db.SeedAdmin` 首次启动会 seed 一个默认管理员账号
- **MinIO**（或兼容 S3 协议的对象存储）：APK/AAB 原始包与加固产物存储，进程启动时
  `EnsureBucket` 会自动建桶（如果不存在）
- **`dpt.jar`**：加固引擎，需要一个 Java 21 运行时（JRE 即可，不需要 JDK，见下文），
  以及它自身的 `shell-files/`、`bin/` 两个配套目录（见 [dpt.jar 打包说明](#dptjar-打包说明)）

## 环境变量参考

以 `.env.example` 为模板，`cp .env.example .env` 后按需修改。`JWT_SECRET`
没有默认值，缺失会导致进程直接退出（`config.Load` 显式校验）。

| 变量 | 默认值 | 说明 |
|---|---|---|
| `SERVER_PORT` | `8080` | HTTP 监听端口 |
| `DB_HOST` / `DB_PORT` | — / `5432` | PostgreSQL 地址；容器化部署里由 compose 覆盖为 `postgres` |
| `DB_USER` / `DB_PASSWORD` / `DB_NAME` | — | PostgreSQL 凭据与库名 |
| `DB_SSLMODE` | — | 通常本地 `disable`，托管数据库按需改 `require`/`verify-full` |
| `JWT_SECRET` | **无默认值，必填** | 登录态签名密钥，生产环境务必换成长随机字符串 |
| `JWT_EXPIRE_HOURS` | `24` | JWT 过期时间（小时） |
| `MINIO_ENDPOINT` | — | `host:port` 形式，不带协议前缀；容器化部署里由 compose 覆盖为 `minio:9000` |
| `MINIO_ACCESS_KEY` / `MINIO_SECRET_KEY` | — | 对象存储凭据 |
| `MINIO_USE_SSL` | `false` | MinIO 是否走 HTTPS |
| `MINIO_BUCKET` | — | 存储桶名，不存在会自动创建 |
| `MAX_UPLOAD_SIZE_MB` | `4096` | 单个 APK/AAB 上传大小上限 |
| `DPT_JAR_PATH` | 本机开发路径 | `dpt.jar` 绝对路径；容器化部署里由 compose 覆盖为 `/opt/dpt/dpt.jar` |
| `DPT_WORK_DIR` | `/tmp/beetleshield-hardening` | 每个加固任务的工作目录根路径，需要可写 |
| `DPT_DEFAULT_VMP_RULES` | 内置两行默认规则 | 策略里 `vmpRulesText` 留空时使用的默认 VMP 白名单规则 |
| `DPT_TASK_TIMEOUT_MINUTES` | `60` | 单个加固任务超时时间 |
| `HARDENING_ENGINE_VERSION` | `BeetleShield Engine v2.4.1` | 写入加固报告的引擎版本号，纯展示用途 |
| `ADMIN_EMAIL` / `ADMIN_PASSWORD` | `admin@beetleshield.com` / `ChangeMe123!` | 首次启动 seed 的默认管理员账号，**登录后应立即改密码** |

## 方式一：本地开发部署

日常开发用这种方式，`go run` 支持热改代码，比每次改动都重新 build 镜像快得多。

```bash
cp .env.example .env
# 编辑 .env，把 DB_*/MINIO_* 指向真实可连通的实例

make dev-up      # 启动 postgres:16 + minio（如果本机已有可用实例，跳过这步）
make run         # go run ./cmd/server，监听 :8080
```

首次启动会在日志里看到 seed 管理员账号的确认行。如果本机 5432/9000/9001
端口已经被其他项目占用（比如已经有别的 Postgres/MinIO 容器在跑），
`make dev-up` 会因为端口冲突启动失败——这种情况跳过 `make dev-up`，直接把
`.env` 指向那些已有实例即可，不需要修改 `docker-compose.yml`。

真实跑一遍加固引擎（默认测试套件不会执行 `dpt.jar`）：把 `.env` 里
`DPT_JAR_PATH` 指向本机真实的 `dpt.jar`，按 README「Manual hardening smoke
test」一节操作，或直接跑 `scripts/smoke_test.sh`。

## 方式二：全容器化部署

应用本身（server + worker）连同 `dpt.jar` 引擎一起打包进一个 Docker 镜像，
`docker-compose.yml` 里的 `app` 服务放在 `full` compose profile 下——**默认
不会随 `docker compose up`/`make dev-up` 启动**，不会打断上面「方式一」的本
地开发流程。

### dpt.jar 打包说明

`dpt.jar` 是不随本仓库分发的专有二进制。构建镜像前必须先把它和两个配套目录
一起放到 `./dpt/`（已加入 `.gitignore`，不会被提交）：

```bash
mkdir -p dpt
cp -R /path/to/dpt-shell/executable/dpt.jar dpt/
cp -R /path/to/dpt-shell/executable/shell-files dpt/
cp -R /path/to/dpt-shell/executable/bin dpt/
```

**三者缺一不可**：`dpt.jar` 在运行时按自身所在目录（不是当前工作目录）去找
`shell-files/`、`bin/` 这两个配套资源，只拷贝 `dpt.jar` 单个文件，在真实执行
加固时会报 `Cannot find directory: shell-files` 直接失败——这个坑已经在真实
APK 上验证过并踩过一次，`Dockerfile` 现在是 `COPY dpt/ /opt/dpt/` 整个目录
拷贝，不是只拷贝 `dpt.jar`。

不需要额外准备 JDK 或 `jarsigner`：已用真实 APK 验证过完整链路（VMP 转换、
DEX 保护、生成加固后测试签名包，产物里含 `.idsig`），JRE 21
（`eclipse-temurin:21-jre-jammy`）镜像跑得通，`dpt.jar` 自带纯 Java 的签名
库自己完成签名。

### 构建与启动

```bash
cp .env.example .env   # 如果还没有 .env，本地开发已经做过这步可以跳过

make docker-build      # 只构建 app 镜像，不启动
make docker-up          # 构建并启动 postgres + minio + app
make docker-down        # 停止并移除这三个服务的容器（不删数据卷）
```

`app` 容器里以下三个变量由 `docker-compose.yml` 的 `environment:` 强制覆盖为
容器网络内的地址，会覆盖 `.env` 文件里对应的值：

- `DB_HOST=postgres`
- `MINIO_ENDPOINT=minio:9000`
- `DPT_JAR_PATH=/opt/dpt/dpt.jar`

其余配置（`JWT_SECRET`、`ADMIN_EMAIL`、`DPT_TASK_TIMEOUT_MINUTES` 等）仍从
挂载进容器的本地 `.env` 文件读取——`cmd/server/main.go` 读的是字面量 `./.env`
文件而不是单纯的进程环境变量，所以这个文件必须真实挂载进容器
（`docker-compose.yml` 已经配好 `./.env:/app/.env:ro` 的 bind mount，改本地
`.env` 后重启 `app` 容器即可生效，不需要重新 build）。

`postgres`/`minio` 都配了 healthcheck，`app` 通过
`depends_on: condition: service_healthy` 等它们健康后再启动，避免首次冷启动
时因为数据库还没就绪而连接失败。

## 验证部署是否成功

```bash
curl http://localhost:8080/health
# {"status":"ok"}

docker compose --profile full logs app --tail 50
# 应该能看到：
#   seeded default admin account: ...
#   [GIN-debug] GET /health ...
```

用 seed 出来的管理员账号登录确认整条链路：

```bash
curl -s -X POST http://localhost:8080/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"<ADMIN_EMAIL>","password":"<ADMIN_PASSWORD>"}'
```

要验证加固引擎本身是否可用，参考 README「Manual hardening smoke test」，
用返回的 token 走一遍上传 APK → 创建加固任务 → 轮询任务状态的完整流程。

## 生产环境注意事项

- **`GIN_MODE`**：不设置时 Gin 跑在 debug 模式（日志会打印全部路由和调试信息）。
  生产环境在 `docker-compose.yml` 的 `app.environment` 里加一行
  `GIN_MODE: release`，或者部署平台层面设置这个环境变量。
- **`JWT_SECRET`**：`.env.example` 里的占位值不能直接用于生产，换成足够长的
  随机字符串，且不要提交到仓库（`.env` 已在 `.gitignore` 里）。
- **默认管理员密码**：`ADMIN_EMAIL`/`ADMIN_PASSWORD` 只在 `users` 表为空时
  seed 一次，登录后应立即改密码；不要在生产 `.env` 里保留
  `.env.example` 的默认值。
- **反向代理 / HTTPS**：`app` 容器本身只监听 HTTP `:8080`，生产环境建议在前面
  加一层 Nginx/Caddy/云厂商负载均衡终结 TLS，不要直接把 8080 暴露给公网。
- **`DB_SSLMODE`**：连接托管数据库（非本机 Docker 里的 `postgres:16`）时按需
  改成 `require` 或更严格的模式。
- **上传大小限制**：`MAX_UPLOAD_SIZE_MB` 默认 4096（4GB），如果前面有反向代理，
  记得同步调大代理层的请求体大小限制，否则会先被代理拦截。

## 数据持久化与备份

`docker-compose.yml` 定义了三个具名 volume：

| Volume | 挂载路径 | 内容 |
|---|---|---|
| `beetleshield_postgres_data` | postgres 容器内 `/var/lib/postgresql/data` | 全部业务数据 |
| `beetleshield_minio_data` | minio 容器内 `/data` | 上传的 APK/AAB 与加固产物 |
| `beetleshield_dpt_work_data` | app 容器内 `/tmp/beetleshield-hardening` | 加固任务的临时工作目录，仅为保留正在进行中的任务数据，可随时清空 |

`make docker-down`/`docker compose down` 默认不会删除 volume。真的要清空重来：

```bash
docker compose --profile full down -v   # 加 -v 才会删 volume，谨慎使用
```

生产环境的备份策略应该针对 `beetleshield_postgres_data`（业务数据）和 MinIO
里的对象数据做定期快照，`beetleshield_dpt_work_data` 是纯临时数据，不需要备份。

## 更新部署

代码或依赖变更后，镜像不会自动更新，需要重新 build：

```bash
git pull
make docker-build
make docker-up   # docker-up 自带 --build，等价于 build + up -d
```

只改了 `.env` 里的配置（不涉及代码或 `dpt.jar`）：

```bash
docker compose --profile full restart app
```

## 常见问题排查

**`make dev-up`/`make docker-up` 报端口冲突（5432/9000/9001 already in
use）**：本机已经有其他 Postgres/MinIO 容器占用这些端口（团队机器上常见，比如
`pg12-dev`/`minio-dev` 之类别的项目在用）。要么修改 `docker-compose.yml` 里冲
突服务的端口映射，要么直接把 `.env`（本地开发）或 compose 里 `app.environment`
（全容器化部署）指向已有实例，跳过本仓库自带的 `postgres`/`minio` 服务。

**加固任务一直失败，日志里有 `Cannot find directory: shell-files`**：
`./dpt/` 目录下只有 `dpt.jar`，缺了 `shell-files/`、`bin/` 这两个配套目录，
按上面「dpt.jar 打包说明」重新拷全，然后 `make docker-build` 重新构建镜像。

**`app` 容器日志里报 `password authentication failed`**：挂载进容器的
`.env` 里 `DB_USER`/`DB_PASSWORD` 跟 `docker-compose.yml` 里 `postgres`
服务的 `POSTGRES_USER`/`POSTGRES_PASSWORD` 不一致——这两处要么保持一致，要么
在 `app.environment` 里也覆盖 `DB_USER`/`DB_PASSWORD`。

**`app` 容器起不来，一直重启，日志里是 `JWT_SECRET is required`**：挂载进
容器的 `.env` 里没有设置 `JWT_SECRET` 或者是空字符串，编辑本地 `.env` 补上后
`docker compose --profile full restart app`。

**改了 `.env` 但容器里没生效**：确认改的是 compose 里 `volumes:` 挂载的那份
`.env`（仓库根目录的 `.env`，不是 `.env.example`），改完需要
`docker compose --profile full restart app`（不需要重新 build，因为是 bind
mount 不是打进镜像里的）。
