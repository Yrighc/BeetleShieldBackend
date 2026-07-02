# BeetleShield Backend

Go + Gin backend for the BeetleShield Android hardening management platform.
This is sub-project one: project foundation + login + app management.
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
`/auth/login`) require `Authorization: Bearer <token>`.

- `POST /auth/login` — `{email, password}` → `{token, user}`
- `GET /auth/me` — current user
- `POST /apps/upload` — multipart `file` + `tag` (`finance`/`game`/`tool`/`ecommerce`)
  + optional `packageName`/`version` (required for `.aab`, auto-parsed for `.apk`)
- `GET /apps?search=&status=&tag=&page=&pageSize=` — list
- `GET /apps/:id` — detail
- `DELETE /apps/:id` — delete
- `GET /apps/:id/download-url` — presigned MinIO download URL (15 min expiry)

See `scripts/smoke_test.sh` for a runnable example of the full flow.

## What's not in this sub-project

Full user-management CRUD, hardening strategy templates, the hardening
pipeline (engine integration), reports, audit log viewing, and the dashboard
aggregation endpoints are separate, later sub-projects — see the design doc's
"后续子项目" section.
