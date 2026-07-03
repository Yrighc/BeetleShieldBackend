# BeetleShield Backend

Go + Gin backend for the BeetleShield Android hardening management platform.
This is sub-project one: project foundation + login + app management +
hardening pipeline orchestration.
See `docs/superpowers/specs/2026-07-02-backend-foundation-app-management-design.md`
for the full design.

## Prerequisites

- Go 1.22+
- A reachable PostgreSQL instance and a reachable MinIO instance (see "Local setup" below)

## Local setup

```bash
cp .env.example .env
```

Edit `.env` so `DB_*` and `MINIO_*` point at a PostgreSQL instance and a MinIO
instance that are actually running and reachable. This project ships a
`docker-compose.yml` that starts `postgres:16` and `minio` on the standard
ports (5432, 9000/9001) — use it if you don't already have Postgres/MinIO
running locally:

```bash
make dev-up      # starts postgres:16 and minio via docker-compose
```

If you already run Postgres and/or MinIO locally for other projects (as is
the case on this machine, where a long-lived `pg12-dev` and `minio-dev`
container pair from other work already occupy ports 5432 and 9000-9001),
`make dev-up` will conflict on those ports. In that situation, skip
`docker-compose.yml` entirely and instead point `.env` at your existing
instances (matching credentials/database/bucket name to whatever those
containers are configured with), or adjust the port mappings in
`docker-compose.yml` before running it. `docker-compose.yml` is kept in the
repo for environments that want to spin up their own isolated instances —
e.g. CI or production orchestration — not as the only supported way to get a
local Postgres/MinIO.

Once `.env` points at a working Postgres + MinIO:

```bash
make run         # starts the API server on :8080
```

On first run, the server seeds a default admin account (email/password from
`.env`, default `admin@beetleshield.com` / `ChangeMe123!`) and prints a log
line confirming it. Change the password after first login once the
user-management module exists.

## Running tests

Integration tests (`internal/db`, `internal/pkg/storage`, `internal/repository`,
`internal/service`, `internal/handler`) require a reachable PostgreSQL and
MinIO instance, configured the same way as for local setup above.

```bash
make test
```

## API overview

All endpoints are under `/api/v1`, return `{code, message, data}`, and (except
`/api/v1/auth/login`) require `Authorization: Bearer <token>`.

- `POST /api/v1/auth/login` — `{email, password}` → `{token, user}`
- `GET /api/v1/auth/me` — current user
- `POST /api/v1/apps/upload` — multipart `file` + `tag` (`finance`/`game`/`tool`/`ecommerce`)
  + optional `packageName`/`version` (required for `.aab`, auto-parsed for `.apk`)
- `GET /api/v1/apps?search=&status=&tag=&page=&pageSize=` — list
- `GET /api/v1/apps/:id` — detail
- `DELETE /api/v1/apps/:id` — delete
- `GET /api/v1/apps/:id/download-url` — presigned MinIO download URL (15 min expiry)
- `POST /api/v1/hardening-tasks` — create a queued hardening task for an existing app (`admin`/`developer`)
- `GET /api/v1/hardening-tasks?status=&appId=&search=&page=&pageSize=` — list hardening tasks
- `GET /api/v1/hardening-tasks/:id` — task detail with steps and recent logs
- `GET /api/v1/hardening-tasks/:id/logs?stepKey=&afterId=&limit=` — task logs
- `GET /api/v1/hardening-tasks/:id/download-url?artifact=unsigned|signed_test` — presigned artifact download URL
- `GET /api/v1/apps/:id/hardening-history` — recent hardening history for an app

See `scripts/smoke_test.sh` for a runnable example of the full flow.

## Manual hardening smoke test

The default test suite does not run `dpt.jar`. To test the real engine locally:

1. Ensure `.env` points `DPT_JAR_PATH` at `/Users/yrighc/work/hzyz/project/test/dpt-shell/executable/dpt.jar`.
2. Upload an APK through `POST /api/v1/apps/upload`.
3. Create a hardening task with `POST /api/v1/hardening-tasks`.
4. Poll `GET /api/v1/hardening-tasks/:id` until the task is `completed` or `failed`.
5. Download the unsigned artifact with `GET /api/v1/hardening-tasks/:id/download-url?artifact=unsigned`.
6. Optionally download the test signed artifact with `artifact=signed_test` if present.

## Docker 化部署

`docker-compose.yml` 里 `postgres`/`minio` 是默认就会启动的依赖服务（`make dev-up`
一直如此，行为不变）。应用本身（API server + 加固 worker + `dpt.jar` + JRE）打包成一个
`app` 服务，放在 `full` compose profile 下，默认不随 `docker compose up`/`make dev-up`
启动，避免打断现有的本地 `make run` 开发流程。

`dpt.jar` 是不随仓库分发的专有二进制（见 `.gitignore` 里的 `/dpt/`），构建镜像前必须先手动放好：

```bash
mkdir -p dpt
cp /path/to/your/dpt.jar dpt/dpt.jar   # 例如本机的 dpt-shell/executable/dpt.jar
cp .env.example .env                    # 如果还没有 .env
```

然后：

```bash
make docker-build   # 只构建 app 镜像
make docker-up       # 构建并启动 postgres + minio + app（含健康检查依赖顺序）
make docker-down     # 停止并移除这三个服务的容器
```

`app` 容器里 `DB_HOST`/`MINIO_ENDPOINT`/`DPT_JAR_PATH` 由 `docker-compose.yml` 的
`environment:` 覆盖为容器网络内的服务名（`postgres`/`minio:9000`）和镜像内固定的
`/opt/dpt/dpt.jar` 路径，其余配置（`JWT_SECRET`、`ADMIN_EMAIL` 等）仍从挂载进容器的
本地 `.env` 文件读取——`cmd/server/main.go` 读的是字面量 `./.env` 文件而不是单纯的进程
环境变量，所以这个文件必须真实挂载进容器（compose 里已经配好了 bind mount）。

如果本机 5432/9000/9001 端口已经被其他项目占用（README "Local setup" 一节提到的场景），
`full` profile 同样会冲突——修改 `docker-compose.yml` 里对应的端口映射，或者把
`DB_HOST`/`MINIO_ENDPOINT` 指向已有实例并跳过 compose 里的 `postgres`/`minio` 服务。

## What's not in this sub-project

Full user-management CRUD, hardening strategy templates, reports, audit log
viewing, and the dashboard aggregation endpoints are separate, later
sub-projects — see the design doc's "后续子项目" section.
