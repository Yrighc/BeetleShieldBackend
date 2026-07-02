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

## What's not in this sub-project

Full user-management CRUD, hardening strategy templates, reports, audit log
viewing, and the dashboard aggregation endpoints are separate, later
sub-projects — see the design doc's "后续子项目" section.
