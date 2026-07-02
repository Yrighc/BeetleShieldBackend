# BeetleShield Backend — Foundation + App Management Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up the BeetleShield Go backend from scratch (Gin + PostgreSQL + MinIO), with JWT-based login and a fully working "应用管理" (App Management) module: APK/AAB upload with auto-parsed package metadata, list/filter, detail, delete, and presigned download.

**Architecture:** Layered Go service (`handler` → `service` → `repository` → GORM/PostgreSQL), with small `pkg/` utility packages (JWT, password hashing, unified response, MinIO client, APK manifest parsing) that are unit-testable in isolation. `docker-compose.yml` provides local PostgreSQL + MinIO for integration tests and local dev.

**Tech Stack:** Go 1.22+, Gin, GORM (`gorm.io/driver/postgres`, AutoMigrate — no separate migration tool for this phase), `github.com/minio/minio-go/v7`, `github.com/golang-jwt/jwt/v5`, `golang.org/x/crypto/bcrypt`, `github.com/spf13/viper` (reading `.env`), `github.com/shogo82148/androidbinary/apk` (APK manifest parsing).

Reference spec: [`docs/superpowers/specs/2026-07-02-backend-foundation-app-management-design.md`](../specs/2026-07-02-backend-foundation-app-management-design.md)

## Global Constraints

- Go module name: `beetleshield-backend` (all internal imports use this prefix).
- API prefix `/api/v1`; every response uses the envelope `{code int, message string, data any}` (code `0` = success).
- JWT expiry default 24h, configurable via `JWT_EXPIRE_HOURS`; secret via `JWT_SECRET` (required, no default).
- Upload size limit default 4096MB, configurable via `MAX_UPLOAD_SIZE_MB`. Only `.apk` and `.aab` extensions are accepted.
- `.apk` package name/version are auto-parsed from `AndroidManifest.xml` via `github.com/shogo82148/androidbinary/apk`. `.aab` requires the client to supply `packageName`/`version` form fields — if missing, the API returns HTTP 422.
- MinIO bucket name comes from `MINIO_BUCKET` config; object key pattern is `{packageName}/{sha256 first 12 chars}/{original filename}`.
- Enums: `users.role` ∈ {`admin`, `developer`, `auditor`}; `users.status` ∈ {`active`, `disabled`}; `apps.status` ∈ {`unprotected`, `processing`, `completed`, `failed`}; `apps.tag` ∈ {`finance`, `game`, `tool`, `ecommerce`}; `apps.risk_level` ∈ {`low`, `medium`, `high`, `critical`} (nullable, unset in this phase).
- All `/api/v1/apps/*` routes require a valid JWT (`Authorization: Bearer <token>`). Fine-grained per-role write restrictions are deferred to the future user-management sub-project.
- Integration tests (anything touching Postgres or MinIO) assume a local Postgres and MinIO are already running, and print a hint in the failure message if the connection fails.
- **Local dev DB/MinIO amendment (added after Task 1 landed):** this machine already runs its own long-lived `pg12-dev` (Postgres, user `root` / password `root`, database `beetleshield` already created) and `minio-dev` (root user `admin` / password `yuan801200`, endpoint `localhost:9000`) containers used across the developer's other local projects, occupying ports 5432 and 9000-9001. Rather than fighting that port conflict, local dev and all integration tests in this plan connect directly to those existing containers instead of the project's own `docker-compose.yml`. Every test helper's hardcoded Postgres credentials in this plan use `DBUser: "root", DBPassword: "root"` (DBName stays `"beetleshield"`), and every hardcoded `NewMinioStorage(...)` call uses `"admin", "yuan801200"` — this has already been applied throughout the plan text below. `docker-compose.yml` (from Task 1) is kept as-is for production orchestration (per explicit instruction) and is not used for local dev/test right now. The real local `.env` (gitignored, not committed) is updated to match these credentials; `.env.example` stays generic/unchanged as a template for environments that do use the bundled `docker-compose.yml`.

---

## File Structure

```
BeetleShieldBackend/
├── cmd/server/main.go
├── internal/
│   ├── config/config.go
│   ├── db/db.go
│   ├── model/user.go
│   ├── model/app.go
│   ├── router/router.go
│   ├── middleware/cors.go
│   ├── middleware/auth.go
│   ├── handler/auth_handler.go
│   ├── handler/app_handler.go
│   ├── service/auth_service.go
│   ├── service/app_service.go
│   ├── repository/user_repository.go
│   ├── repository/app_repository.go
│   └── pkg/
│       ├── response/response.go
│       ├── jwtutil/jwt.go
│       ├── hash/password.go
│       ├── storage/minio.go
│       └── manifest/parser.go
├── scripts/smoke_test.sh
├── docker-compose.yml
├── .env.example
├── go.mod / go.sum
├── Makefile
└── README.md
```

---

### Task 1: Project scaffold, config loading, health-check server

**Files:**
- Create: `go.mod`
- Create: `docker-compose.yml`
- Create: `.env.example`
- Create: `Makefile`
- Create: `internal/config/config.go`
- Create: `internal/config/config_test.go`
- Create: `cmd/server/main.go`

**Interfaces:**
- Produces: `config.Config` struct and `config.Load(path string) (*config.Config, error)` — every later task that needs configuration loads it through this function.

- [ ] **Step 1: Initialize the Go module**

```bash
cd /Users/yrighc/work/hzyz/project/BeetleShieldBackend
go mod init beetleshield-backend
```

Expected: creates `go.mod` with `module beetleshield-backend` and a `go 1.22` (or newer) directive.

- [ ] **Step 2: Write `docker-compose.yml`**

```yaml
services:
  postgres:
    image: postgres:16
    container_name: beetleshield-postgres
    restart: unless-stopped
    environment:
      POSTGRES_USER: beetleshield
      POSTGRES_PASSWORD: beetleshield
      POSTGRES_DB: beetleshield
    ports:
      - "5432:5432"
    volumes:
      - beetleshield_postgres_data:/var/lib/postgresql/data

  minio:
    image: minio/minio:latest
    container_name: beetleshield-minio
    restart: unless-stopped
    command: server /data --console-address ":9001"
    environment:
      MINIO_ROOT_USER: beetleshield
      MINIO_ROOT_PASSWORD: beetleshield123
    ports:
      - "9000:9000"
      - "9001:9001"
    volumes:
      - beetleshield_minio_data:/data

volumes:
  beetleshield_postgres_data:
  beetleshield_minio_data:
```

- [ ] **Step 3: Write `.env.example`**

```
SERVER_PORT=8080

DB_HOST=localhost
DB_PORT=5432
DB_USER=beetleshield
DB_PASSWORD=beetleshield
DB_NAME=beetleshield
DB_SSLMODE=disable

JWT_SECRET=change-me-to-a-long-random-string
JWT_EXPIRE_HOURS=24

MINIO_ENDPOINT=localhost:9000
MINIO_ACCESS_KEY=beetleshield
MINIO_SECRET_KEY=beetleshield123
MINIO_USE_SSL=false
MINIO_BUCKET=beetleshield-apps

MAX_UPLOAD_SIZE_MB=4096

ADMIN_EMAIL=admin@beetleshield.com
ADMIN_PASSWORD=ChangeMe123!
```

- [ ] **Step 4: Write `Makefile`**

```makefile
.PHONY: run dev-up dev-down test

run:
	go run ./cmd/server

dev-up:
	docker compose up -d

dev-down:
	docker compose down

test:
	go test ./... -v
```

- [ ] **Step 5: Write the failing config test**

Create `internal/config/config_test.go`:

```go
package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	content := `SERVER_PORT=9090
DB_HOST=localhost
DB_PORT=5432
DB_USER=testuser
DB_PASSWORD=testpass
DB_NAME=testdb
DB_SSLMODE=disable
JWT_SECRET=test-secret
JWT_EXPIRE_HOURS=12
MINIO_ENDPOINT=localhost:9000
MINIO_ACCESS_KEY=testkey
MINIO_SECRET_KEY=testsecret
MINIO_USE_SSL=false
MINIO_BUCKET=test-bucket
MAX_UPLOAD_SIZE_MB=1024
ADMIN_EMAIL=admin@test.com
ADMIN_PASSWORD=testpass123
`
	if err := os.WriteFile(envPath, []byte(content), 0644); err != nil {
		t.Fatalf("write env file: %v", err)
	}

	cfg, err := Load(envPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}

	if cfg.ServerPort != "9090" {
		t.Errorf("ServerPort = %q, want %q", cfg.ServerPort, "9090")
	}
	if cfg.JWTSecret != "test-secret" {
		t.Errorf("JWTSecret = %q, want %q", cfg.JWTSecret, "test-secret")
	}
	if cfg.JWTExpireHours != 12 {
		t.Errorf("JWTExpireHours = %d, want %d", cfg.JWTExpireHours, 12)
	}
	if cfg.MinioUseSSL != false {
		t.Errorf("MinioUseSSL = %v, want false", cfg.MinioUseSSL)
	}
	if cfg.MaxUploadSizeMB != 1024 {
		t.Errorf("MaxUploadSizeMB = %d, want %d", cfg.MaxUploadSizeMB, 1024)
	}
}

func TestLoad_MissingJWTSecret(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	content := "SERVER_PORT=9090\n"
	if err := os.WriteFile(envPath, []byte(content), 0644); err != nil {
		t.Fatalf("write env file: %v", err)
	}

	_, err := Load(envPath)
	if err == nil {
		t.Fatal("Load() expected error for missing JWT_SECRET, got nil")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/config/... -v`
Expected: FAIL — `config.Load` undefined (package doesn't compile yet).

- [ ] **Step 3: Add viper dependency and implement `config.Load`**

```bash
go get github.com/spf13/viper
```

Create `internal/config/config.go`:

```go
package config

import (
	"fmt"

	"github.com/spf13/viper"
)

type Config struct {
	ServerPort string

	DBHost     string
	DBPort     string
	DBUser     string
	DBPassword string
	DBName     string
	DBSSLMode  string

	JWTSecret      string
	JWTExpireHours int

	MinioEndpoint  string
	MinioAccessKey string
	MinioSecretKey string
	MinioUseSSL    bool
	MinioBucket    string

	MaxUploadSizeMB int64

	AdminEmail    string
	AdminPassword string
}

func Load(path string) (*Config, error) {
	v := viper.New()
	v.SetConfigFile(path)
	v.SetConfigType("env")
	v.AutomaticEnv()

	v.SetDefault("SERVER_PORT", "8080")
	v.SetDefault("JWT_EXPIRE_HOURS", 24)
	v.SetDefault("MAX_UPLOAD_SIZE_MB", 4096)
	v.SetDefault("MINIO_USE_SSL", false)

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	cfg := &Config{
		ServerPort:      v.GetString("SERVER_PORT"),
		DBHost:          v.GetString("DB_HOST"),
		DBPort:          v.GetString("DB_PORT"),
		DBUser:          v.GetString("DB_USER"),
		DBPassword:      v.GetString("DB_PASSWORD"),
		DBName:          v.GetString("DB_NAME"),
		DBSSLMode:       v.GetString("DB_SSLMODE"),
		JWTSecret:       v.GetString("JWT_SECRET"),
		JWTExpireHours:  v.GetInt("JWT_EXPIRE_HOURS"),
		MinioEndpoint:   v.GetString("MINIO_ENDPOINT"),
		MinioAccessKey:  v.GetString("MINIO_ACCESS_KEY"),
		MinioSecretKey:  v.GetString("MINIO_SECRET_KEY"),
		MinioUseSSL:     v.GetBool("MINIO_USE_SSL"),
		MinioBucket:     v.GetString("MINIO_BUCKET"),
		MaxUploadSizeMB: v.GetInt64("MAX_UPLOAD_SIZE_MB"),
		AdminEmail:      v.GetString("ADMIN_EMAIL"),
		AdminPassword:   v.GetString("ADMIN_PASSWORD"),
	}

	if cfg.JWTSecret == "" {
		return nil, fmt.Errorf("JWT_SECRET is required")
	}

	return cfg, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/config/... -v`
Expected: PASS (`TestLoad`, `TestLoad_MissingJWTSecret`)

- [ ] **Step 5: Add Gin and write `cmd/server/main.go` with a health check**

```bash
go get github.com/gin-gonic/gin
```

Create `cmd/server/main.go`:

```go
package main

import (
	"log"

	"github.com/gin-gonic/gin"

	"beetleshield-backend/internal/config"
)

func main() {
	cfg, err := config.Load(".env")
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	r := gin.Default()
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	if err := r.Run(":" + cfg.ServerPort); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}
```

- [ ] **Step 6: Manually verify the server boots**

```bash
cp .env.example .env
go run ./cmd/server &
sleep 1
curl -s http://localhost:8080/health
kill %1
```

Expected output: `{"status":"ok"}`

- [ ] **Step 7: Commit**

```bash
git add go.mod go.sum docker-compose.yml .env.example Makefile internal/config cmd/server
git commit -m "feat: project scaffold with config loading and health check"
```

---

### Task 2: Unified response helper

**Files:**
- Create: `internal/pkg/response/response.go`
- Test: `internal/pkg/response/response_test.go`

**Interfaces:**
- Produces: `response.Response{Code, Message, Data}`, `response.Success(c *gin.Context, httpStatus int, data interface{})`, `response.Error(c *gin.Context, httpStatus int, code int, message string)` — used by every handler in later tasks.

- [ ] **Step 1: Write the failing test**

Create `internal/pkg/response/response_test.go`:

```go
package response

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
)

func TestSuccess(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	Success(c, http.StatusOK, gin.H{"foo": "bar"})

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusOK)
	}

	var body Response
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body.Code != 0 {
		t.Errorf("Code = %d, want 0", body.Code)
	}
	if body.Message != "success" {
		t.Errorf("Message = %q, want %q", body.Message, "success")
	}
}

func TestError(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	Error(c, http.StatusBadRequest, 40001, "invalid input")

	if w.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", w.Code, http.StatusBadRequest)
	}

	var body Response
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if body.Code != 40001 {
		t.Errorf("Code = %d, want 40001", body.Code)
	}
	if body.Message != "invalid input" {
		t.Errorf("Message = %q, want %q", body.Message, "invalid input")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/pkg/response/... -v`
Expected: FAIL — `Success`/`Error`/`Response` undefined.

- [ ] **Step 3: Implement**

Create `internal/pkg/response/response.go`:

```go
package response

import "github.com/gin-gonic/gin"

type Response struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

func Success(c *gin.Context, httpStatus int, data interface{}) {
	c.JSON(httpStatus, Response{Code: 0, Message: "success", Data: data})
}

func Error(c *gin.Context, httpStatus int, code int, message string) {
	c.JSON(httpStatus, Response{Code: code, Message: message})
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/pkg/response/... -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/pkg/response
git commit -m "feat: add unified API response helper"
```

---

### Task 3: JWT utility package

**Files:**
- Create: `internal/pkg/jwtutil/jwt.go`
- Test: `internal/pkg/jwtutil/jwt_test.go`

**Interfaces:**
- Produces: `jwtutil.Claims{UserID uint, Role string, jwt.RegisteredClaims}`, `jwtutil.GenerateToken(secret string, userID uint, role string, expireHours int) (string, error)`, `jwtutil.ParseToken(secret, tokenString string) (*jwtutil.Claims, error)`, `jwtutil.ErrInvalidToken` — consumed by `internal/middleware/auth.go` (Task 6) and `internal/service/auth_service.go` (Task 7).

- [ ] **Step 1: Write the failing test**

Create `internal/pkg/jwtutil/jwt_test.go`:

```go
package jwtutil

import (
	"testing"
	"time"
)

func TestGenerateAndParseToken(t *testing.T) {
	secret := "test-secret"
	tokenString, err := GenerateToken(secret, 42, "admin", 1)
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}

	claims, err := ParseToken(secret, tokenString)
	if err != nil {
		t.Fatalf("ParseToken() error = %v", err)
	}
	if claims.UserID != 42 {
		t.Errorf("UserID = %d, want 42", claims.UserID)
	}
	if claims.Role != "admin" {
		t.Errorf("Role = %q, want %q", claims.Role, "admin")
	}
}

func TestParseToken_WrongSecret(t *testing.T) {
	tokenString, err := GenerateToken("secret-a", 1, "admin", 1)
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}

	_, err = ParseToken("secret-b", tokenString)
	if err == nil {
		t.Fatal("ParseToken() expected error for wrong secret, got nil")
	}
}

func TestParseToken_Expired(t *testing.T) {
	secret := "test-secret"
	tokenString, err := GenerateToken(secret, 1, "admin", 0)
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}
	time.Sleep(1 * time.Second)

	_, err = ParseToken(secret, tokenString)
	if err == nil {
		t.Fatal("ParseToken() expected error for expired token, got nil")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/pkg/jwtutil/... -v`
Expected: FAIL — package doesn't compile (`GenerateToken`/`ParseToken` undefined).

- [ ] **Step 3: Implement**

```bash
go get github.com/golang-jwt/jwt/v5
```

Create `internal/pkg/jwtutil/jwt.go`:

```go
package jwtutil

import (
	"errors"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

var ErrInvalidToken = errors.New("invalid token")

type Claims struct {
	UserID uint   `json:"user_id"`
	Role   string `json:"role"`
	jwt.RegisteredClaims
}

func GenerateToken(secret string, userID uint, role string, expireHours int) (string, error) {
	claims := Claims{
		UserID: userID,
		Role:   role,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Duration(expireHours) * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(secret))
}

func ParseToken(secret string, tokenString string) (*Claims, error) {
	claims := &Claims{}
	token, err := jwt.ParseWithClaims(tokenString, claims, func(t *jwt.Token) (interface{}, error) {
		return []byte(secret), nil
	})
	if err != nil {
		return nil, err
	}
	if !token.Valid {
		return nil, ErrInvalidToken
	}
	return claims, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/pkg/jwtutil/... -v`
Expected: PASS (3 tests, `TestParseToken_Expired` takes ~1s)

- [ ] **Step 5: Commit**

```bash
git add go.mod go.sum internal/pkg/jwtutil
git commit -m "feat: add JWT generate/parse utility"
```

---

### Task 4: Password hashing utility

**Files:**
- Create: `internal/pkg/hash/password.go`
- Test: `internal/pkg/hash/password_test.go`

**Interfaces:**
- Produces: `hash.HashPassword(password string) (string, error)`, `hash.CheckPassword(hashedPassword, password string) bool` — consumed by `internal/db/db.go` (Task 5) and `internal/service/auth_service.go` (Task 7).

- [ ] **Step 1: Write the failing test**

Create `internal/pkg/hash/password_test.go`:

```go
package hash

import "testing"

func TestHashAndCheckPassword(t *testing.T) {
	hashed, err := HashPassword("MySecret123!")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	if hashed == "MySecret123!" {
		t.Error("hashed password must not equal plaintext")
	}

	if !CheckPassword(hashed, "MySecret123!") {
		t.Error("CheckPassword() = false, want true for correct password")
	}
	if CheckPassword(hashed, "WrongPassword") {
		t.Error("CheckPassword() = true, want false for wrong password")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/pkg/hash/... -v`
Expected: FAIL — `HashPassword`/`CheckPassword` undefined.

- [ ] **Step 3: Implement**

```bash
go get golang.org/x/crypto
```

Create `internal/pkg/hash/password.go`:

```go
package hash

import "golang.org/x/crypto/bcrypt"

func HashPassword(password string) (string, error) {
	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashed), nil
}

func CheckPassword(hashedPassword, password string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hashedPassword), []byte(password))
	return err == nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/pkg/hash/... -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add go.mod go.sum internal/pkg/hash
git commit -m "feat: add bcrypt password hashing utility"
```

---

### Task 5: User model, DB connection, migration, admin seed

**Files:**
- Create: `internal/model/user.go`
- Create: `internal/db/db.go`
- Test: `internal/db/db_test.go`
- Modify: `cmd/server/main.go`

**Interfaces:**
- Consumes: `config.Config` (Task 1), `hash.HashPassword` (Task 4).
- Produces: `model.User`, `model.UserRole` (`RoleAdmin`, `RoleDeveloper`, `RoleAuditor`), `model.UserStatus` (`UserStatusActive`, `UserStatusDisabled`); `db.Connect(cfg *config.Config) (*gorm.DB, error)`, `db.Migrate(database *gorm.DB) error`, `db.SeedAdmin(database *gorm.DB, email, password string) error` — consumed by `internal/repository/user_repository.go` (Task 7) and `main.go`.

- [ ] **Step 1: Write the model**

Create `internal/model/user.go`:

```go
package model

import "time"

type UserRole string

const (
	RoleAdmin     UserRole = "admin"
	RoleDeveloper UserRole = "developer"
	RoleAuditor   UserRole = "auditor"
)

type UserStatus string

const (
	UserStatusActive   UserStatus = "active"
	UserStatusDisabled UserStatus = "disabled"
)

type User struct {
	ID           uint       `gorm:"primaryKey" json:"id"`
	Name         string     `gorm:"size:100;not null" json:"name"`
	Email        string     `gorm:"size:255;uniqueIndex;not null" json:"email"`
	PasswordHash string     `gorm:"size:255;not null" json:"-"`
	Role         UserRole   `gorm:"size:20;not null" json:"role"`
	Department   string     `gorm:"size:100" json:"department"`
	Status       UserStatus `gorm:"size:20;not null;default:active" json:"status"`
	LastLoginAt  *time.Time `json:"lastLoginAt"`
	CreatedAt    time.Time  `json:"createdAt"`
	UpdatedAt    time.Time  `json:"updatedAt"`
}

func (User) TableName() string {
	return "users"
}
```

- [ ] **Step 2: Write the failing integration test**

Create `internal/db/db_test.go`:

```go
package db

import (
	"testing"

	"beetleshield-backend/internal/config"
	"beetleshield-backend/internal/model"
)

func testConfig() *config.Config {
	return &config.Config{
		DBHost:     "localhost",
		DBPort:     "5432",
		DBUser:     "root",
		DBPassword: "root",
		DBName:     "beetleshield",
		DBSSLMode:  "disable",
	}
}

func TestMigrateAndSeedAdmin(t *testing.T) {
	cfg := testConfig()
	database, err := Connect(cfg)
	if err != nil {
		t.Fatalf("Connect() error = %v (is `make dev-up` running?)", err)
	}

	if err := Migrate(database); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}

	database.Unscoped().Where("email = ?", "seed-test-admin@beetleshield.com").Delete(&model.User{})

	if err := SeedAdmin(database, "seed-test-admin@beetleshield.com", "TestPassword123!"); err != nil {
		t.Fatalf("SeedAdmin() error = %v", err)
	}

	var user model.User
	if err := database.Where("email = ?", "seed-test-admin@beetleshield.com").First(&user).Error; err != nil {
		t.Fatalf("expected seeded admin to exist: %v", err)
	}
	if user.Role != model.RoleAdmin {
		t.Errorf("Role = %q, want %q", user.Role, model.RoleAdmin)
	}

	if err := SeedAdmin(database, "seed-test-admin@beetleshield.com", "TestPassword123!"); err != nil {
		t.Fatalf("second SeedAdmin() error = %v", err)
	}
	var count int64
	database.Model(&model.User{}).Where("email = ?", "seed-test-admin@beetleshield.com").Count(&count)
	if count != 1 {
		t.Errorf("expected exactly 1 user after duplicate seed, got %d", count)
	}

	database.Unscoped().Where("email = ?", "seed-test-admin@beetleshield.com").Delete(&model.User{})
}
```

- [ ] **Step 3: Start the local database and run test to verify it fails**

```bash
make dev-up
go test ./internal/db/... -v
```

Expected: FAIL — `Connect`/`Migrate`/`SeedAdmin` undefined.

- [ ] **Step 4: Implement**

```bash
go get gorm.io/gorm gorm.io/driver/postgres
```

Note: on this project's configured Go module proxy, a plain `go get gorm.io/driver/postgres` may resolve to a stale `v1.2.3` that doesn't compile against a current `gorm.io/gorm`. If `go build ./...` fails with a `ColumnType`/`AutoIncrement` compile error after this step, run `go get gorm.io/driver/postgres@v1.6.0` (the newest version available on this proxy) followed by `go mod tidy`, then continue.

Create `internal/db/db.go`:

```go
package db

import (
	"fmt"
	"log"

	"gorm.io/driver/postgres"
	"gorm.io/gorm"

	"beetleshield-backend/internal/config"
	"beetleshield-backend/internal/model"
	"beetleshield-backend/internal/pkg/hash"
)

func Connect(cfg *config.Config) (*gorm.DB, error) {
	dsn := fmt.Sprintf(
		"host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		cfg.DBHost, cfg.DBPort, cfg.DBUser, cfg.DBPassword, cfg.DBName, cfg.DBSSLMode,
	)
	database, err := gorm.Open(postgres.Open(dsn), &gorm.Config{})
	if err != nil {
		return nil, fmt.Errorf("connect database: %w", err)
	}
	return database, nil
}

func Migrate(database *gorm.DB) error {
	return database.AutoMigrate(&model.User{})
}

func SeedAdmin(database *gorm.DB, email, password string) error {
	var count int64
	if err := database.Model(&model.User{}).Where("email = ?", email).Count(&count).Error; err != nil {
		return err
	}
	if count > 0 {
		return nil
	}

	hashed, err := hash.HashPassword(password)
	if err != nil {
		return err
	}

	admin := model.User{
		Name:         "系统管理员",
		Email:        email,
		PasswordHash: hashed,
		Role:         model.RoleAdmin,
		Department:   "系统",
		Status:       model.UserStatusActive,
	}
	if err := database.Create(&admin).Error; err != nil {
		return err
	}
	log.Printf("seeded default admin account: %s / %s (please change the password after first login)", email, password)
	return nil
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/db/... -v`
Expected: PASS

- [ ] **Step 6: Wire DB connect/migrate/seed into `main.go`**

Modify `cmd/server/main.go`:

```go
package main

import (
	"log"

	"github.com/gin-gonic/gin"

	"beetleshield-backend/internal/config"
	"beetleshield-backend/internal/db"
)

func main() {
	cfg, err := config.Load(".env")
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	database, err := db.Connect(cfg)
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}

	if err := db.Migrate(database); err != nil {
		log.Fatalf("failed to migrate database: %v", err)
	}

	if err := db.SeedAdmin(database, cfg.AdminEmail, cfg.AdminPassword); err != nil {
		log.Fatalf("failed to seed admin account: %v", err)
	}

	r := gin.Default()
	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	if err := r.Run(":" + cfg.ServerPort); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}
```

- [ ] **Step 7: Manually verify startup seeds the admin**

```bash
go run ./cmd/server &
sleep 1
kill %1
```

Expected: log line `seeded default admin account: admin@beetleshield.com / ChangeMe123! ...` on first run (won't repeat on subsequent runs).

- [ ] **Step 8: Commit**

```bash
git add go.mod go.sum internal/model/user.go internal/db cmd/server/main.go
git commit -m "feat: add User model, DB connection, migration, and admin seed"
```

---

### Task 6: CORS and JWT auth middleware

**Files:**
- Create: `internal/middleware/cors.go`
- Create: `internal/middleware/auth.go`
- Test: `internal/middleware/auth_test.go`

**Interfaces:**
- Consumes: `jwtutil.GenerateToken`/`ParseToken` (Task 3).
- Produces: `middleware.CORS() gin.HandlerFunc`, `middleware.JWTAuth(secret string) gin.HandlerFunc`, `middleware.ContextUserIDKey`, `middleware.ContextRoleKey` (string constants) — consumed by `internal/router/router.go` (Task 8) and every protected handler.

- [ ] **Step 1: Write the failing test**

Create `internal/middleware/auth_test.go`:

```go
package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"

	"beetleshield-backend/internal/pkg/jwtutil"
)

func setupRouter(secret string) *gin.Engine {
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.Use(JWTAuth(secret))
	r.GET("/protected", func(c *gin.Context) {
		userID, _ := c.Get(ContextUserIDKey)
		c.JSON(http.StatusOK, gin.H{"userID": userID})
	})
	return r
}

func TestJWTAuth_MissingHeader(t *testing.T) {
	r := setupRouter("test-secret")
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}

func TestJWTAuth_ValidToken(t *testing.T) {
	secret := "test-secret"
	r := setupRouter(secret)
	token, err := jwtutil.GenerateToken(secret, 7, "admin", 1)
	if err != nil {
		t.Fatalf("GenerateToken() error = %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer "+token)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("status = %d, want %d, body=%s", w.Code, http.StatusOK, w.Body.String())
	}
}

func TestJWTAuth_InvalidToken(t *testing.T) {
	r := setupRouter("test-secret")
	req := httptest.NewRequest(http.MethodGet, "/protected", nil)
	req.Header.Set("Authorization", "Bearer not-a-real-token")
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("status = %d, want %d", w.Code, http.StatusUnauthorized)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/middleware/... -v`
Expected: FAIL — `JWTAuth`/`ContextUserIDKey` undefined.

- [ ] **Step 3: Implement**

Create `internal/middleware/cors.go`:

```go
package middleware

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func CORS() gin.HandlerFunc {
	return func(c *gin.Context) {
		c.Header("Access-Control-Allow-Origin", "*")
		c.Header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		c.Header("Access-Control-Allow-Headers", "Authorization, Content-Type")

		if c.Request.Method == http.MethodOptions {
			c.AbortWithStatus(http.StatusNoContent)
			return
		}
		c.Next()
	}
}
```

Create `internal/middleware/auth.go`:

```go
package middleware

import (
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"

	"beetleshield-backend/internal/pkg/jwtutil"
	"beetleshield-backend/internal/pkg/response"
)

const (
	ContextUserIDKey = "userID"
	ContextRoleKey   = "role"
)

func JWTAuth(secret string) gin.HandlerFunc {
	return func(c *gin.Context) {
		header := c.GetHeader("Authorization")
		if header == "" || !strings.HasPrefix(header, "Bearer ") {
			response.Error(c, http.StatusUnauthorized, 40100, "missing or invalid authorization header")
			c.Abort()
			return
		}

		tokenString := strings.TrimPrefix(header, "Bearer ")
		claims, err := jwtutil.ParseToken(secret, tokenString)
		if err != nil {
			response.Error(c, http.StatusUnauthorized, 40101, "invalid or expired token")
			c.Abort()
			return
		}

		c.Set(ContextUserIDKey, claims.UserID)
		c.Set(ContextRoleKey, claims.Role)
		c.Next()
	}
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/middleware/... -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add internal/middleware
git commit -m "feat: add CORS and JWT auth middleware"
```

---

### Task 7: User repository and auth service

**Files:**
- Create: `internal/repository/user_repository.go`
- Create: `internal/service/auth_service.go`
- Test: `internal/service/auth_service_test.go`

**Interfaces:**
- Consumes: `model.User` (Task 5), `hash.HashPassword`/`CheckPassword` (Task 4), `jwtutil.GenerateToken` (Task 3).
- Produces: `repository.UserRepository` with `NewUserRepository(db *gorm.DB) *UserRepository`, `FindByEmail(email string) (*model.User, error)`, `FindByID(id uint) (*model.User, error)`, `UpdateLastLogin(id uint) error`, `Create(user *model.User) error`, `DeleteByEmail(email string) error`; `service.AuthService` with `NewAuthService(userRepo *repository.UserRepository, jwtSecret string, jwtExpireHours int) *AuthService`, `Login(email, password string) (string, *model.User, error)`, `GetUserByID(id uint) (*model.User, error)`, and sentinel errors `service.ErrInvalidCredentials`, `service.ErrUserDisabled` — consumed by `internal/handler/auth_handler.go` (Task 8) and `main.go`.

- [ ] **Step 1: Implement the repository**

Create `internal/repository/user_repository.go`:

```go
package repository

import (
	"time"

	"gorm.io/gorm"

	"beetleshield-backend/internal/model"
)

type UserRepository struct {
	db *gorm.DB
}

func NewUserRepository(db *gorm.DB) *UserRepository {
	return &UserRepository{db: db}
}

func (r *UserRepository) FindByEmail(email string) (*model.User, error) {
	var user model.User
	if err := r.db.Where("email = ?", email).First(&user).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *UserRepository) FindByID(id uint) (*model.User, error) {
	var user model.User
	if err := r.db.First(&user, id).Error; err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *UserRepository) UpdateLastLogin(id uint) error {
	now := time.Now()
	return r.db.Model(&model.User{}).Where("id = ?", id).Update("last_login_at", now).Error
}

func (r *UserRepository) Create(user *model.User) error {
	return r.db.Create(user).Error
}

func (r *UserRepository) DeleteByEmail(email string) error {
	return r.db.Unscoped().Where("email = ?", email).Delete(&model.User{}).Error
}
```

- [ ] **Step 2: Write the failing integration test for the auth service**

Create `internal/service/auth_service_test.go`:

```go
package service_test

import (
	"testing"

	"beetleshield-backend/internal/config"
	"beetleshield-backend/internal/db"
	"beetleshield-backend/internal/model"
	"beetleshield-backend/internal/pkg/hash"
	"beetleshield-backend/internal/repository"
	"beetleshield-backend/internal/service"
)

func setupTestUserRepo(t *testing.T) *repository.UserRepository {
	t.Helper()
	cfg := &config.Config{
		DBHost: "localhost", DBPort: "5432",
		DBUser: "root", DBPassword: "root",
		DBName: "beetleshield", DBSSLMode: "disable",
	}
	database, err := db.Connect(cfg)
	if err != nil {
		t.Fatalf("Connect() error = %v (is `make dev-up` running?)", err)
	}
	if err := db.Migrate(database); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}
	return repository.NewUserRepository(database)
}

func TestAuthService_Login(t *testing.T) {
	repo := setupTestUserRepo(t)

	hashed, err := hash.HashPassword("Password123!")
	if err != nil {
		t.Fatalf("HashPassword() error = %v", err)
	}
	testUser := model.User{
		Name: "测试用户", Email: "auth-test@beetleshield.com",
		PasswordHash: hashed, Role: model.RoleDeveloper,
		Status: model.UserStatusActive,
	}
	repo.DeleteByEmail(testUser.Email)
	if err := repo.Create(&testUser); err != nil {
		t.Fatalf("create test user: %v", err)
	}
	defer repo.DeleteByEmail(testUser.Email)

	authService := service.NewAuthService(repo, "test-secret", 1)

	t.Run("valid credentials", func(t *testing.T) {
		token, user, err := authService.Login(testUser.Email, "Password123!")
		if err != nil {
			t.Fatalf("Login() error = %v", err)
		}
		if token == "" {
			t.Error("expected non-empty token")
		}
		if user.Email != testUser.Email {
			t.Errorf("Email = %q, want %q", user.Email, testUser.Email)
		}
	})

	t.Run("wrong password", func(t *testing.T) {
		_, _, err := authService.Login(testUser.Email, "wrong-password")
		if err != service.ErrInvalidCredentials {
			t.Errorf("err = %v, want %v", err, service.ErrInvalidCredentials)
		}
	})

	t.Run("unknown email", func(t *testing.T) {
		_, _, err := authService.Login("nobody@beetleshield.com", "whatever")
		if err != service.ErrInvalidCredentials {
			t.Errorf("err = %v, want %v", err, service.ErrInvalidCredentials)
		}
	})
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/service/... -v`
Expected: FAIL — `service.NewAuthService` undefined.

- [ ] **Step 4: Implement the auth service**

Create `internal/service/auth_service.go`:

```go
package service

import (
	"errors"

	"beetleshield-backend/internal/model"
	"beetleshield-backend/internal/pkg/hash"
	"beetleshield-backend/internal/pkg/jwtutil"
	"beetleshield-backend/internal/repository"
)

var (
	ErrInvalidCredentials = errors.New("invalid email or password")
	ErrUserDisabled       = errors.New("user account is disabled")
)

type AuthService struct {
	userRepo       *repository.UserRepository
	jwtSecret      string
	jwtExpireHours int
}

func NewAuthService(userRepo *repository.UserRepository, jwtSecret string, jwtExpireHours int) *AuthService {
	return &AuthService{userRepo: userRepo, jwtSecret: jwtSecret, jwtExpireHours: jwtExpireHours}
}

func (s *AuthService) Login(email, password string) (string, *model.User, error) {
	user, err := s.userRepo.FindByEmail(email)
	if err != nil {
		return "", nil, ErrInvalidCredentials
	}

	if !hash.CheckPassword(user.PasswordHash, password) {
		return "", nil, ErrInvalidCredentials
	}

	if user.Status == model.UserStatusDisabled {
		return "", nil, ErrUserDisabled
	}

	token, err := jwtutil.GenerateToken(s.jwtSecret, user.ID, string(user.Role), s.jwtExpireHours)
	if err != nil {
		return "", nil, err
	}

	_ = s.userRepo.UpdateLastLogin(user.ID)

	return token, user, nil
}

func (s *AuthService) GetUserByID(id uint) (*model.User, error) {
	return s.userRepo.FindByID(id)
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/service/... -v`
Expected: PASS (3 subtests under `TestAuthService_Login`)

- [ ] **Step 6: Commit**

```bash
git add internal/repository/user_repository.go internal/service/auth_service.go internal/service/auth_service_test.go
git commit -m "feat: add user repository and auth service (login)"
```

---

### Task 8: Auth handler, router, and full login wiring

**Files:**
- Create: `internal/handler/auth_handler.go`
- Create: `internal/router/router.go`
- Test: `internal/handler/auth_handler_test.go`
- Modify: `cmd/server/main.go`

**Interfaces:**
- Consumes: `service.AuthService` (Task 7), `middleware.CORS`/`JWTAuth`/`ContextUserIDKey` (Task 6), `response.Success`/`Error` (Task 2).
- Produces: `handler.AuthHandler` with `NewAuthHandler(authService *service.AuthService) *AuthHandler`, `Login(c *gin.Context)`, `Me(c *gin.Context)`; `router.Deps{JWTSecret string, AuthHandler *handler.AuthHandler}` and `router.New(deps Deps) *gin.Engine` — `router.Deps` gains an `AppHandler` field in Task 14.

- [ ] **Step 1: Write the failing end-to-end test**

Create `internal/handler/auth_handler_test.go`:

```go
package handler_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"beetleshield-backend/internal/config"
	"beetleshield-backend/internal/db"
	"beetleshield-backend/internal/handler"
	"beetleshield-backend/internal/model"
	"beetleshield-backend/internal/pkg/hash"
	"beetleshield-backend/internal/repository"
	"beetleshield-backend/internal/router"
	"beetleshield-backend/internal/service"
)

func setupAuthRouter(t *testing.T) (*httptest.Server, func()) {
	t.Helper()
	cfg := &config.Config{
		DBHost: "localhost", DBPort: "5432",
		DBUser: "root", DBPassword: "root",
		DBName: "beetleshield", DBSSLMode: "disable",
		JWTSecret: "test-secret", JWTExpireHours: 1,
	}
	database, err := db.Connect(cfg)
	if err != nil {
		t.Fatalf("Connect() error = %v (is `make dev-up` running?)", err)
	}
	if err := db.Migrate(database); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}

	userRepo := repository.NewUserRepository(database)
	hashed, _ := hash.HashPassword("Password123!")
	testUser := model.User{
		Name: "接口测试用户", Email: "handler-test@beetleshield.com",
		PasswordHash: hashed, Role: model.RoleAdmin, Status: model.UserStatusActive,
	}
	userRepo.DeleteByEmail(testUser.Email)
	if err := userRepo.Create(&testUser); err != nil {
		t.Fatalf("create test user: %v", err)
	}

	authService := service.NewAuthService(userRepo, cfg.JWTSecret, cfg.JWTExpireHours)
	authHandler := handler.NewAuthHandler(authService)
	r := router.New(router.Deps{JWTSecret: cfg.JWTSecret, AuthHandler: authHandler})

	srv := httptest.NewServer(r)
	cleanup := func() {
		userRepo.DeleteByEmail(testUser.Email)
		srv.Close()
	}
	return srv, cleanup
}

func TestLoginAndMe(t *testing.T) {
	srv, cleanup := setupAuthRouter(t)
	defer cleanup()

	body, _ := json.Marshal(map[string]string{
		"email":    "handler-test@beetleshield.com",
		"password": "Password123!",
	})
	resp, err := http.Post(srv.URL+"/api/v1/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /auth/login error = %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var loginResp struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&loginResp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if loginResp.Data.Token == "" {
		t.Fatal("expected non-empty token")
	}

	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/auth/me", nil)
	req.Header.Set("Authorization", "Bearer "+loginResp.Data.Token)
	meResp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /auth/me error = %v", err)
	}
	defer meResp.Body.Close()
	if meResp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want %d", meResp.StatusCode, http.StatusOK)
	}
}

func TestLogin_WrongPassword(t *testing.T) {
	srv, cleanup := setupAuthRouter(t)
	defer cleanup()

	body, _ := json.Marshal(map[string]string{
		"email":    "handler-test@beetleshield.com",
		"password": "wrong-password",
	})
	resp, err := http.Post(srv.URL+"/api/v1/auth/login", "application/json", bytes.NewReader(body))
	if err != nil {
		t.Fatalf("POST /auth/login error = %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/handler/... -v`
Expected: FAIL — package doesn't compile (`handler.NewAuthHandler`, `router.New`, `router.Deps` undefined).

- [ ] **Step 3: Implement the auth handler**

Create `internal/handler/auth_handler.go`:

```go
package handler

import (
	"errors"
	"net/http"

	"github.com/gin-gonic/gin"

	"beetleshield-backend/internal/middleware"
	"beetleshield-backend/internal/pkg/response"
	"beetleshield-backend/internal/service"
)

type AuthHandler struct {
	authService *service.AuthService
}

func NewAuthHandler(authService *service.AuthService) *AuthHandler {
	return &AuthHandler{authService: authService}
}

type loginRequest struct {
	Email    string `json:"email" binding:"required,email"`
	Password string `json:"password" binding:"required"`
}

func (h *AuthHandler) Login(c *gin.Context) {
	var req loginRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Error(c, http.StatusBadRequest, 40001, err.Error())
		return
	}

	token, user, err := h.authService.Login(req.Email, req.Password)
	if err != nil {
		if errors.Is(err, service.ErrInvalidCredentials) {
			response.Error(c, http.StatusUnauthorized, 40102, "邮箱或密码错误")
			return
		}
		if errors.Is(err, service.ErrUserDisabled) {
			response.Error(c, http.StatusForbidden, 40301, "账号已被禁用")
			return
		}
		response.Error(c, http.StatusInternalServerError, 50000, "登录失败，请稍后重试")
		return
	}

	response.Success(c, http.StatusOK, gin.H{
		"token": token,
		"user":  user,
	})
}

func (h *AuthHandler) Me(c *gin.Context) {
	userID := c.GetUint(middleware.ContextUserIDKey)
	user, err := h.authService.GetUserByID(userID)
	if err != nil {
		response.Error(c, http.StatusNotFound, 40401, "用户不存在")
		return
	}
	response.Success(c, http.StatusOK, user)
}
```

- [ ] **Step 4: Implement the router**

Create `internal/router/router.go`:

```go
package router

import (
	"github.com/gin-gonic/gin"

	"beetleshield-backend/internal/handler"
	"beetleshield-backend/internal/middleware"
)

type Deps struct {
	JWTSecret   string
	AuthHandler *handler.AuthHandler
}

func New(deps Deps) *gin.Engine {
	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery(), middleware.CORS())

	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	v1 := r.Group("/api/v1")
	{
		auth := v1.Group("/auth")
		{
			auth.POST("/login", deps.AuthHandler.Login)
			auth.GET("/me", middleware.JWTAuth(deps.JWTSecret), deps.AuthHandler.Me)
		}
	}

	return r
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/handler/... -v`
Expected: PASS (`TestLoginAndMe`, `TestLogin_WrongPassword`)

- [ ] **Step 6: Wire the router into `main.go`**

Modify `cmd/server/main.go`:

```go
package main

import (
	"log"

	"beetleshield-backend/internal/config"
	"beetleshield-backend/internal/db"
	"beetleshield-backend/internal/handler"
	"beetleshield-backend/internal/repository"
	"beetleshield-backend/internal/router"
	"beetleshield-backend/internal/service"
)

func main() {
	cfg, err := config.Load(".env")
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	database, err := db.Connect(cfg)
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}

	if err := db.Migrate(database); err != nil {
		log.Fatalf("failed to migrate database: %v", err)
	}

	if err := db.SeedAdmin(database, cfg.AdminEmail, cfg.AdminPassword); err != nil {
		log.Fatalf("failed to seed admin account: %v", err)
	}

	userRepo := repository.NewUserRepository(database)
	authService := service.NewAuthService(userRepo, cfg.JWTSecret, cfg.JWTExpireHours)
	authHandler := handler.NewAuthHandler(authService)

	r := router.New(router.Deps{
		JWTSecret:   cfg.JWTSecret,
		AuthHandler: authHandler,
	})

	if err := r.Run(":" + cfg.ServerPort); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}
```

- [ ] **Step 7: Manually verify with curl**

```bash
go run ./cmd/server &
sleep 1
curl -s -X POST http://localhost:8080/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@beetleshield.com","password":"ChangeMe123!"}'
kill %1
```

Expected: JSON with `"code":0` and a non-empty `data.token`.

- [ ] **Step 8: Commit**

```bash
git add internal/handler/auth_handler.go internal/handler/auth_handler_test.go internal/router cmd/server/main.go
git commit -m "feat: wire login/me endpoints through router and main"
```

---

### Task 9: App model and migration

**Files:**
- Create: `internal/model/app.go`
- Modify: `internal/db/db.go`
- Modify: `internal/db/db_test.go`

**Interfaces:**
- Produces: `model.App`, `model.AppTag` (`AppTagFinance`, `AppTagGame`, `AppTagTool`, `AppTagEcommerce`), `model.AppStatus` (`AppStatusUnprotected`, `AppStatusProcessing`, `AppStatusCompleted`, `AppStatusFailed`), `model.RiskLevel` (`RiskLevelLow`, `RiskLevelMedium`, `RiskLevelHigh`, `RiskLevelCritical`) — consumed by `internal/repository/app_repository.go` (Task 12).

- [ ] **Step 1: Write the model**

Create `internal/model/app.go`:

```go
package model

import "time"

type AppTag string

const (
	AppTagFinance   AppTag = "finance"
	AppTagGame      AppTag = "game"
	AppTagTool      AppTag = "tool"
	AppTagEcommerce AppTag = "ecommerce"
)

type AppStatus string

const (
	AppStatusUnprotected AppStatus = "unprotected"
	AppStatusProcessing  AppStatus = "processing"
	AppStatusCompleted   AppStatus = "completed"
	AppStatusFailed      AppStatus = "failed"
)

type RiskLevel string

const (
	RiskLevelLow      RiskLevel = "low"
	RiskLevelMedium   RiskLevel = "medium"
	RiskLevelHigh     RiskLevel = "high"
	RiskLevelCritical RiskLevel = "critical"
)

type App struct {
	ID          uint       `gorm:"primaryKey" json:"id"`
	Name        string     `gorm:"size:200;not null" json:"name"`
	PackageName string     `gorm:"size:255;index;not null" json:"packageName"`
	Version     string     `gorm:"size:50" json:"version"`
	Tag         AppTag     `gorm:"size:20;not null" json:"tag"`
	Status      AppStatus  `gorm:"size:20;not null;default:unprotected" json:"status"`
	RiskLevel   *RiskLevel `gorm:"size:20" json:"riskLevel"`
	FileSize    int64      `json:"fileSize"`
	ObjectKey   string     `gorm:"size:500;not null" json:"-"`
	MD5         string     `gorm:"size:32;not null" json:"md5"`
	SHA256      string     `gorm:"size:64;not null" json:"sha256"`
	UploadedBy  uint       `gorm:"not null" json:"uploadedBy"`
	CreatedAt   time.Time  `json:"createdAt"`
	UpdatedAt   time.Time  `json:"updatedAt"`
}

func (App) TableName() string {
	return "apps"
}
```

- [ ] **Step 2: Add a failing test asserting the apps table exists**

Append to `internal/db/db_test.go`:

```go
func TestMigrate_AppsTable(t *testing.T) {
	cfg := testConfig()
	database, err := Connect(cfg)
	if err != nil {
		t.Fatalf("Connect() error = %v (is `make dev-up` running?)", err)
	}
	if err := Migrate(database); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}

	testApp := model.App{
		Name: "迁移测试应用", PackageName: "com.migrationtest.app", Version: "0.0.1",
		Tag: model.AppTagTool, Status: model.AppStatusUnprotected,
		ObjectKey: "com.migrationtest.app/abc/app.apk",
		MD5:       "d41d8cd98f00b204e9800998ecf8427e",
		SHA256:    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85",
		UploadedBy: 1,
	}
	database.Unscoped().Where("package_name = ?", testApp.PackageName).Delete(&model.App{})

	if err := database.Create(&testApp).Error; err != nil {
		t.Fatalf("failed to insert into apps table: %v", err)
	}

	database.Unscoped().Where("package_name = ?", testApp.PackageName).Delete(&model.App{})
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/db/... -v -run TestMigrate_AppsTable`
Expected: FAIL — `relation "apps" does not exist` (Migrate doesn't create it yet).

- [ ] **Step 4: Add App to AutoMigrate**

Modify `internal/db/db.go`, change the `Migrate` function:

```go
func Migrate(database *gorm.DB) error {
	return database.AutoMigrate(&model.User{}, &model.App{})
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/db/... -v`
Expected: PASS (all tests in the package, including `TestMigrateAndSeedAdmin` and `TestMigrate_AppsTable`)

- [ ] **Step 6: Commit**

```bash
git add internal/model/app.go internal/db/db.go internal/db/db_test.go
git commit -m "feat: add App model and migration"
```

---

### Task 10: MinIO storage wrapper

**Files:**
- Create: `internal/pkg/storage/minio.go`
- Test: `internal/pkg/storage/minio_test.go`

**Interfaces:**
- Produces: `storage.MinioStorage` with `NewMinioStorage(endpoint, accessKey, secretKey, bucket string, useSSL bool) (*MinioStorage, error)`, `EnsureBucket(ctx context.Context) error`, `PutObject(ctx context.Context, objectKey string, reader io.Reader, size int64, contentType string) error`, `PresignedDownloadURL(ctx context.Context, objectKey string, expiry time.Duration) (string, error)`, `DeleteObject(ctx context.Context, objectKey string) error` — consumed by `internal/service/app_service.go` (Task 13) and `main.go`.

- [ ] **Step 1: Write the failing integration test**

Create `internal/pkg/storage/minio_test.go`:

```go
package storage

import (
	"bytes"
	"context"
	"testing"
	"time"
)

func newTestStorage(t *testing.T) *MinioStorage {
	t.Helper()
	s, err := NewMinioStorage("localhost:9000", "admin", "yuan801200", "test-bucket", false)
	if err != nil {
		t.Fatalf("NewMinioStorage() error = %v", err)
	}
	if err := s.EnsureBucket(context.Background()); err != nil {
		t.Fatalf("EnsureBucket() error = %v (is `make dev-up` running?)", err)
	}
	return s
}

func TestPutAndDeleteObject(t *testing.T) {
	s := newTestStorage(t)
	ctx := context.Background()
	objectKey := "unit-test/hello.txt"
	content := []byte("hello beetleshield")

	if err := s.PutObject(ctx, objectKey, bytes.NewReader(content), int64(len(content)), "text/plain"); err != nil {
		t.Fatalf("PutObject() error = %v", err)
	}

	downloadURL, err := s.PresignedDownloadURL(ctx, objectKey, 5*time.Minute)
	if err != nil {
		t.Fatalf("PresignedDownloadURL() error = %v", err)
	}
	if downloadURL == "" {
		t.Error("expected non-empty presigned URL")
	}

	if err := s.DeleteObject(ctx, objectKey); err != nil {
		t.Fatalf("DeleteObject() error = %v", err)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/pkg/storage/... -v`
Expected: FAIL — `NewMinioStorage` undefined.

- [ ] **Step 3: Implement**

```bash
go get github.com/minio/minio-go/v7
```

Create `internal/pkg/storage/minio.go`:

```go
package storage

import (
	"context"
	"io"
	"net/url"
	"time"

	"github.com/minio/minio-go/v7"
	"github.com/minio/minio-go/v7/pkg/credentials"
)

type MinioStorage struct {
	client *minio.Client
	bucket string
}

func NewMinioStorage(endpoint, accessKey, secretKey, bucket string, useSSL bool) (*MinioStorage, error) {
	client, err := minio.New(endpoint, &minio.Options{
		Creds:  credentials.NewStaticV4(accessKey, secretKey, ""),
		Secure: useSSL,
	})
	if err != nil {
		return nil, err
	}
	return &MinioStorage{client: client, bucket: bucket}, nil
}

func (s *MinioStorage) EnsureBucket(ctx context.Context) error {
	exists, err := s.client.BucketExists(ctx, s.bucket)
	if err != nil {
		return err
	}
	if exists {
		return nil
	}
	return s.client.MakeBucket(ctx, s.bucket, minio.MakeBucketOptions{})
}

func (s *MinioStorage) PutObject(ctx context.Context, objectKey string, reader io.Reader, size int64, contentType string) error {
	_, err := s.client.PutObject(ctx, s.bucket, objectKey, reader, size, minio.PutObjectOptions{
		ContentType: contentType,
	})
	return err
}

func (s *MinioStorage) PresignedDownloadURL(ctx context.Context, objectKey string, expiry time.Duration) (string, error) {
	u, err := s.client.PresignedGetObject(ctx, s.bucket, objectKey, expiry, url.Values{})
	if err != nil {
		return "", err
	}
	return u.String(), nil
}

func (s *MinioStorage) DeleteObject(ctx context.Context, objectKey string) error {
	return s.client.RemoveObject(ctx, s.bucket, objectKey, minio.RemoveObjectOptions{})
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/pkg/storage/... -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add go.mod go.sum internal/pkg/storage
git commit -m "feat: add MinIO storage wrapper"
```

---

### Task 11: APK manifest parser

**Files:**
- Create: `internal/pkg/manifest/parser.go`
- Create: `internal/pkg/manifest/testdata/helloworld.apk` (binary fixture, downloaded)
- Create: `internal/pkg/manifest/testdata/NOTICE.md`
- Create: `internal/pkg/manifest/testdata/not-an-apk.txt`
- Test: `internal/pkg/manifest/parser_test.go`

**Interfaces:**
- Produces: `manifest.PackageInfo{PackageName, VersionName string}`, `manifest.ParseAPK(path string) (*PackageInfo, error)`, `manifest.ErrParsePackageInfo` — consumed by `internal/service/app_service.go` (Task 13).

- [ ] **Step 1: Fetch the test fixture**

This uses the public "HelloWorld" sample APK from the `shogo82148/androidbinary` library's own test suite (MIT licensed), which is exactly what that library uses to test `apk.OpenFile`. It has `PackageName() == "com.example.helloworld"`.

```bash
mkdir -p internal/pkg/manifest/testdata
curl -sL -o internal/pkg/manifest/testdata/helloworld.apk \
  https://raw.githubusercontent.com/shogo82148/androidbinary/main/apk/testdata/helloworld.apk
```

Create `internal/pkg/manifest/testdata/NOTICE.md`:

```markdown
# Test fixture provenance

`helloworld.apk` is copied from the `shogo82148/androidbinary` project's own
test suite (`apk/testdata/helloworld.apk`), used here under the MIT License
solely to unit-test our `ParseAPK` wrapper against a real binary
AndroidManifest.xml.

Source: https://github.com/shogo82148/androidbinary/blob/main/apk/testdata/helloworld.apk
```

Create `internal/pkg/manifest/testdata/not-an-apk.txt`:

```
this is not a valid apk file, used to test parser error handling
```

- [ ] **Step 2: Write the failing test**

Create `internal/pkg/manifest/parser_test.go`:

```go
package manifest

import "testing"

func TestParseAPK_HelloWorld(t *testing.T) {
	info, err := ParseAPK("testdata/helloworld.apk")
	if err != nil {
		t.Fatalf("ParseAPK() error = %v", err)
	}
	if info.PackageName != "com.example.helloworld" {
		t.Errorf("PackageName = %q, want %q", info.PackageName, "com.example.helloworld")
	}
}

func TestParseAPK_NotAnAPK(t *testing.T) {
	_, err := ParseAPK("testdata/not-an-apk.txt")
	if err == nil {
		t.Fatal("expected error for invalid apk file, got nil")
	}
}
```

- [ ] **Step 3: Run test to verify it fails**

Run: `go test ./internal/pkg/manifest/... -v`
Expected: FAIL — `ParseAPK` undefined.

- [ ] **Step 4: Implement**

```bash
go get github.com/shogo82148/androidbinary/apk
```

Create `internal/pkg/manifest/parser.go`:

```go
package manifest

import (
	"errors"

	"github.com/shogo82148/androidbinary/apk"
)

var ErrParsePackageInfo = errors.New("failed to parse package info from manifest")

type PackageInfo struct {
	PackageName string
	VersionName string
}

func ParseAPK(path string) (*PackageInfo, error) {
	a, err := apk.OpenFile(path)
	if err != nil {
		return nil, err
	}
	defer a.Close()

	packageName := a.PackageName()
	if packageName == "" {
		return nil, ErrParsePackageInfo
	}

	versionName, err := a.Manifest().VersionName.String()
	if err != nil {
		versionName = ""
	}

	return &PackageInfo{
		PackageName: packageName,
		VersionName: versionName,
	}, nil
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/pkg/manifest/... -v`
Expected: PASS

- [ ] **Step 6: Commit**

```bash
git add go.mod go.sum internal/pkg/manifest
git commit -m "feat: add APK AndroidManifest package/version parser"
```

---

### Task 12: App repository

**Files:**
- Create: `internal/repository/app_repository.go`
- Test: `internal/repository/app_repository_test.go`

**Interfaces:**
- Consumes: `model.App` (Task 9).
- Produces: `repository.AppListFilter{Search, Status, Tag string, Page, PageSize int}`, `repository.AppRepository` with `NewAppRepository(db *gorm.DB) *AppRepository`, `Create(app *model.App) error`, `FindByID(id uint) (*model.App, error)`, `Delete(id uint) error`, `List(filter AppListFilter) ([]model.App, int64, error)` — consumed by `internal/service/app_service.go` (Task 13).

- [ ] **Step 1: Write the failing test**

Create `internal/repository/app_repository_test.go`:

```go
package repository

import (
	"testing"

	"beetleshield-backend/internal/config"
	"beetleshield-backend/internal/db"
	"beetleshield-backend/internal/model"
)

func setupAppRepo(t *testing.T) *AppRepository {
	t.Helper()
	cfg := &config.Config{
		DBHost: "localhost", DBPort: "5432",
		DBUser: "root", DBPassword: "root",
		DBName: "beetleshield", DBSSLMode: "disable",
	}
	database, err := db.Connect(cfg)
	if err != nil {
		t.Fatalf("Connect() error = %v (is `make dev-up` running?)", err)
	}
	if err := db.Migrate(database); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}
	database.Unscoped().Where("package_name LIKE ?", "com.repotest.%").Delete(&model.App{})
	t.Cleanup(func() {
		database.Unscoped().Where("package_name LIKE ?", "com.repotest.%").Delete(&model.App{})
	})
	return NewAppRepository(database)
}

func TestAppRepository_CreateFindDelete(t *testing.T) {
	repo := setupAppRepo(t)

	app := model.App{
		Name: "测试应用", PackageName: "com.repotest.one", Version: "1.0.0",
		Tag: model.AppTagTool, Status: model.AppStatusUnprotected,
		FileSize: 1024, ObjectKey: "com.repotest.one/abc/app.apk",
		MD5:        "d41d8cd98f00b204e9800998ecf8427e",
		SHA256:     "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b85",
		UploadedBy: 1,
	}
	if err := repo.Create(&app); err != nil {
		t.Fatalf("Create() error = %v", err)
	}
	if app.ID == 0 {
		t.Fatal("expected ID to be set after Create()")
	}

	found, err := repo.FindByID(app.ID)
	if err != nil {
		t.Fatalf("FindByID() error = %v", err)
	}
	if found.PackageName != app.PackageName {
		t.Errorf("PackageName = %q, want %q", found.PackageName, app.PackageName)
	}

	if err := repo.Delete(app.ID); err != nil {
		t.Fatalf("Delete() error = %v", err)
	}
	if _, err := repo.FindByID(app.ID); err == nil {
		t.Fatal("expected error finding deleted app, got nil")
	}
}

func TestAppRepository_ListFilters(t *testing.T) {
	repo := setupAppRepo(t)

	apps := []model.App{
		{Name: "金融应用", PackageName: "com.repotest.finance", Version: "1.0",
			Tag: model.AppTagFinance, Status: model.AppStatusCompleted,
			ObjectKey: "k1", MD5: "m1", SHA256: "s1", UploadedBy: 1},
		{Name: "游戏应用", PackageName: "com.repotest.game", Version: "1.0",
			Tag: model.AppTagGame, Status: model.AppStatusUnprotected,
			ObjectKey: "k2", MD5: "m2", SHA256: "s2", UploadedBy: 1},
	}
	for i := range apps {
		if err := repo.Create(&apps[i]); err != nil {
			t.Fatalf("Create() error = %v", err)
		}
	}

	result, total, err := repo.List(AppListFilter{Tag: "finance", Page: 1, PageSize: 10})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if total != 1 {
		t.Errorf("total = %d, want 1", total)
	}
	if len(result) != 1 || result[0].PackageName != "com.repotest.finance" {
		t.Errorf("unexpected result: %+v", result)
	}

	result, total, err = repo.List(AppListFilter{Search: "游戏", Page: 1, PageSize: 10})
	if err != nil {
		t.Fatalf("List() error = %v", err)
	}
	if total != 1 || result[0].PackageName != "com.repotest.game" {
		t.Errorf("unexpected search result: %+v total=%d", result, total)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/repository/... -v -run TestAppRepository`
Expected: FAIL — `AppRepository` undefined.

- [ ] **Step 3: Implement**

Create `internal/repository/app_repository.go`:

```go
package repository

import (
	"gorm.io/gorm"

	"beetleshield-backend/internal/model"
)

type AppListFilter struct {
	Search   string
	Status   string
	Tag      string
	Page     int
	PageSize int
}

type AppRepository struct {
	db *gorm.DB
}

func NewAppRepository(db *gorm.DB) *AppRepository {
	return &AppRepository{db: db}
}

func (r *AppRepository) Create(app *model.App) error {
	return r.db.Create(app).Error
}

func (r *AppRepository) FindByID(id uint) (*model.App, error) {
	var app model.App
	if err := r.db.First(&app, id).Error; err != nil {
		return nil, err
	}
	return &app, nil
}

func (r *AppRepository) Delete(id uint) error {
	return r.db.Delete(&model.App{}, id).Error
}

func (r *AppRepository) List(filter AppListFilter) ([]model.App, int64, error) {
	query := r.db.Model(&model.App{})

	if filter.Search != "" {
		like := "%" + filter.Search + "%"
		query = query.Where("name ILIKE ? OR package_name ILIKE ?", like, like)
	}
	if filter.Status != "" {
		query = query.Where("status = ?", filter.Status)
	}
	if filter.Tag != "" {
		query = query.Where("tag = ?", filter.Tag)
	}

	var total int64
	if err := query.Count(&total).Error; err != nil {
		return nil, 0, err
	}

	page := filter.Page
	if page < 1 {
		page = 1
	}
	pageSize := filter.PageSize
	if pageSize < 1 {
		pageSize = 10
	}

	var apps []model.App
	if err := query.Order("created_at DESC").
		Offset((page - 1) * pageSize).
		Limit(pageSize).
		Find(&apps).Error; err != nil {
		return nil, 0, err
	}

	return apps, total, nil
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/repository/... -v`
Expected: PASS (all repository tests, including `TestAppRepository_CreateFindDelete`, `TestAppRepository_ListFilters`)

- [ ] **Step 5: Commit**

```bash
git add internal/repository/app_repository.go internal/repository/app_repository_test.go
git commit -m "feat: add app repository with filtering and pagination"
```

---

### Task 13: App service (upload pipeline, list/get/delete/download)

**Files:**
- Create: `internal/service/app_service.go`
- Test: `internal/service/app_service_test.go`

**Interfaces:**
- Consumes: `repository.AppRepository`/`AppListFilter` (Task 12), `storage.MinioStorage` (Task 10), `manifest.ParseAPK` (Task 11), `model.App`/`AppTag`/`AppStatus` (Task 9).
- Produces: `service.UploadInput{FileHeader *multipart.FileHeader, Tag model.AppTag, ManualPackageName, ManualVersion string, UploadedBy uint}`, `service.AppService` with `NewAppService(appRepo *repository.AppRepository, storage *storage.MinioStorage, maxUploadSizeMB int64) *AppService`, `Upload(ctx context.Context, input UploadInput) (*model.App, error)`, `List(filter repository.AppListFilter) ([]model.App, int64, error)`, `Get(id uint) (*model.App, error)`, `Delete(ctx context.Context, id uint) error`, `DownloadURL(ctx context.Context, id uint) (string, error)`, and sentinel errors `ErrUnsupportedFileType`, `ErrFileTooLarge`, `ErrMissingPackageInfo`, `ErrAppNotFound` — consumed by `internal/handler/app_handler.go` (Task 14).

- [ ] **Step 1: Write the failing integration test**

Create `internal/service/app_service_test.go`:

```go
package service_test

import (
	"bytes"
	"context"
	"mime/multipart"
	"os"
	"testing"

	"beetleshield-backend/internal/config"
	"beetleshield-backend/internal/db"
	"beetleshield-backend/internal/model"
	"beetleshield-backend/internal/pkg/storage"
	"beetleshield-backend/internal/repository"
	"beetleshield-backend/internal/service"
)

func buildFileHeader(t *testing.T, fieldName, fileName string, content []byte) *multipart.FileHeader {
	t.Helper()
	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	part, err := w.CreateFormFile(fieldName, fileName)
	if err != nil {
		t.Fatalf("CreateFormFile() error = %v", err)
	}
	if _, err := part.Write(content); err != nil {
		t.Fatalf("write part: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}

	r := multipart.NewReader(&buf, w.Boundary())
	form, err := r.ReadForm(int64(len(content)) + 1024)
	if err != nil {
		t.Fatalf("ReadForm() error = %v", err)
	}
	t.Cleanup(func() { form.RemoveAll() })

	return form.File[fieldName][0]
}

func setupAppService(t *testing.T) *service.AppService {
	t.Helper()
	cfg := &config.Config{
		DBHost: "localhost", DBPort: "5432",
		DBUser: "root", DBPassword: "root",
		DBName: "beetleshield", DBSSLMode: "disable",
	}
	database, err := db.Connect(cfg)
	if err != nil {
		t.Fatalf("Connect() error = %v (is `make dev-up` running?)", err)
	}
	if err := db.Migrate(database); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}
	appRepo := repository.NewAppRepository(database)

	st, err := storage.NewMinioStorage("localhost:9000", "admin", "yuan801200", "test-bucket", false)
	if err != nil {
		t.Fatalf("NewMinioStorage() error = %v", err)
	}
	if err := st.EnsureBucket(context.Background()); err != nil {
		t.Fatalf("EnsureBucket() error = %v (is `make dev-up` running?)", err)
	}

	return service.NewAppService(appRepo, st, 10)
}

func TestAppService_Upload_ManualPackageInfo(t *testing.T) {
	svc := setupAppService(t)
	ctx := context.Background()

	fh := buildFileHeader(t, "file", "notreal.aab", []byte("not a real aab, just bytes for testing"))

	app, err := svc.Upload(ctx, service.UploadInput{
		FileHeader:        fh,
		Tag:               model.AppTagTool,
		ManualPackageName: "com.svctest.aabapp",
		ManualVersion:     "2.0.0",
		UploadedBy:        1,
	})
	if err != nil {
		t.Fatalf("Upload() error = %v", err)
	}
	t.Cleanup(func() { _ = svc.Delete(ctx, app.ID) })

	if app.PackageName != "com.svctest.aabapp" {
		t.Errorf("PackageName = %q, want %q", app.PackageName, "com.svctest.aabapp")
	}
	if app.Status != model.AppStatusUnprotected {
		t.Errorf("Status = %q, want %q", app.Status, model.AppStatusUnprotected)
	}
	if app.MD5 == "" || app.SHA256 == "" {
		t.Error("expected non-empty MD5/SHA256")
	}

	fetched, err := svc.Get(app.ID)
	if err != nil {
		t.Fatalf("Get() error = %v", err)
	}
	if fetched.ID != app.ID {
		t.Errorf("Get() returned different app")
	}

	downloadURL, err := svc.DownloadURL(ctx, app.ID)
	if err != nil {
		t.Fatalf("DownloadURL() error = %v", err)
	}
	if downloadURL == "" {
		t.Error("expected non-empty download URL")
	}
}

func TestAppService_Upload_AutoParsesAPKPackageInfo(t *testing.T) {
	svc := setupAppService(t)
	ctx := context.Background()

	content, err := os.ReadFile("../pkg/manifest/testdata/helloworld.apk")
	if err != nil {
		t.Fatalf("read fixture apk: %v", err)
	}
	fh := buildFileHeader(t, "file", "helloworld.apk", content)

	app, err := svc.Upload(ctx, service.UploadInput{
		FileHeader: fh,
		Tag:        model.AppTagTool,
		UploadedBy: 1,
	})
	if err != nil {
		t.Fatalf("Upload() error = %v", err)
	}
	t.Cleanup(func() { _ = svc.Delete(ctx, app.ID) })

	if app.PackageName != "com.example.helloworld" {
		t.Errorf("PackageName = %q, want %q (auto-parsed)", app.PackageName, "com.example.helloworld")
	}
}

func TestAppService_Upload_MissingPackageInfoForAAB(t *testing.T) {
	svc := setupAppService(t)
	ctx := context.Background()

	fh := buildFileHeader(t, "file", "noinfo.aab", []byte("bytes without package info"))

	_, err := svc.Upload(ctx, service.UploadInput{
		FileHeader: fh,
		Tag:        model.AppTagTool,
		UploadedBy: 1,
	})
	if err != service.ErrMissingPackageInfo {
		t.Errorf("err = %v, want %v", err, service.ErrMissingPackageInfo)
	}
}

func TestAppService_Upload_RejectsUnsupportedExtension(t *testing.T) {
	svc := setupAppService(t)
	ctx := context.Background()

	fh := buildFileHeader(t, "file", "app.exe", []byte("nope"))

	_, err := svc.Upload(ctx, service.UploadInput{
		FileHeader: fh,
		Tag:        model.AppTagTool,
		UploadedBy: 1,
	})
	if err != service.ErrUnsupportedFileType {
		t.Errorf("err = %v, want %v", err, service.ErrUnsupportedFileType)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/service/... -v -run TestAppService`
Expected: FAIL — `service.NewAppService`/`UploadInput` undefined.

- [ ] **Step 3: Implement**

Create `internal/service/app_service.go`:

```go
package service

import (
	"context"
	"crypto/md5"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"os"
	"path/filepath"
	"strings"
	"time"

	"beetleshield-backend/internal/model"
	"beetleshield-backend/internal/pkg/manifest"
	"beetleshield-backend/internal/pkg/storage"
	"beetleshield-backend/internal/repository"
)

var (
	ErrUnsupportedFileType = errors.New("unsupported file type, only .apk and .aab are allowed")
	ErrFileTooLarge        = errors.New("file exceeds the maximum allowed size")
	ErrMissingPackageInfo  = errors.New("could not determine package name/version, please provide them manually")
	ErrAppNotFound         = errors.New("app not found")
)

type UploadInput struct {
	FileHeader        *multipart.FileHeader
	Tag               model.AppTag
	ManualPackageName string
	ManualVersion     string
	UploadedBy        uint
}

type AppService struct {
	appRepo         *repository.AppRepository
	storage         *storage.MinioStorage
	maxUploadSizeMB int64
}

func NewAppService(appRepo *repository.AppRepository, storage *storage.MinioStorage, maxUploadSizeMB int64) *AppService {
	return &AppService{appRepo: appRepo, storage: storage, maxUploadSizeMB: maxUploadSizeMB}
}

func (s *AppService) Upload(ctx context.Context, input UploadInput) (*model.App, error) {
	ext := strings.ToLower(filepath.Ext(input.FileHeader.Filename))
	if ext != ".apk" && ext != ".aab" {
		return nil, ErrUnsupportedFileType
	}

	maxBytes := s.maxUploadSizeMB * 1024 * 1024
	if input.FileHeader.Size > maxBytes {
		return nil, ErrFileTooLarge
	}

	src, err := input.FileHeader.Open()
	if err != nil {
		return nil, fmt.Errorf("open uploaded file: %w", err)
	}
	defer src.Close()

	tmpFile, err := os.CreateTemp("", "beetleshield-upload-*"+ext)
	if err != nil {
		return nil, fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer os.Remove(tmpPath)
	defer tmpFile.Close()

	md5Hash := md5.New()
	sha256Hash := sha256.New()
	multiWriter := io.MultiWriter(tmpFile, md5Hash, sha256Hash)

	if _, err := io.Copy(multiWriter, src); err != nil {
		return nil, fmt.Errorf("write temp file: %w", err)
	}

	packageName := input.ManualPackageName
	version := input.ManualVersion

	if ext == ".apk" {
		info, parseErr := manifest.ParseAPK(tmpPath)
		if parseErr == nil {
			if packageName == "" {
				packageName = info.PackageName
			}
			if version == "" {
				version = info.VersionName
			}
		}
	}

	if packageName == "" || version == "" {
		return nil, ErrMissingPackageInfo
	}

	md5Sum := hex.EncodeToString(md5Hash.Sum(nil))
	sha256Sum := hex.EncodeToString(sha256Hash.Sum(nil))

	objectKey := fmt.Sprintf("%s/%s/%s", packageName, sha256Sum[:12], input.FileHeader.Filename)

	if _, err := tmpFile.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("seek temp file: %w", err)
	}

	contentType := "application/vnd.android.package-archive"
	if err := s.storage.PutObject(ctx, objectKey, tmpFile, input.FileHeader.Size, contentType); err != nil {
		return nil, fmt.Errorf("upload to storage: %w", err)
	}

	app := &model.App{
		Name:        strings.TrimSuffix(input.FileHeader.Filename, ext),
		PackageName: packageName,
		Version:     version,
		Tag:         input.Tag,
		Status:      model.AppStatusUnprotected,
		FileSize:    input.FileHeader.Size,
		ObjectKey:   objectKey,
		MD5:         md5Sum,
		SHA256:      sha256Sum,
		UploadedBy:  input.UploadedBy,
	}

	if err := s.appRepo.Create(app); err != nil {
		_ = s.storage.DeleteObject(ctx, objectKey)
		return nil, fmt.Errorf("save app record: %w", err)
	}

	return app, nil
}

func (s *AppService) List(filter repository.AppListFilter) ([]model.App, int64, error) {
	return s.appRepo.List(filter)
}

func (s *AppService) Get(id uint) (*model.App, error) {
	app, err := s.appRepo.FindByID(id)
	if err != nil {
		return nil, ErrAppNotFound
	}
	return app, nil
}

func (s *AppService) Delete(ctx context.Context, id uint) error {
	app, err := s.appRepo.FindByID(id)
	if err != nil {
		return ErrAppNotFound
	}
	if err := s.storage.DeleteObject(ctx, app.ObjectKey); err != nil {
		return fmt.Errorf("delete storage object: %w", err)
	}
	return s.appRepo.Delete(id)
}

func (s *AppService) DownloadURL(ctx context.Context, id uint) (string, error) {
	app, err := s.appRepo.FindByID(id)
	if err != nil {
		return "", ErrAppNotFound
	}
	return s.storage.PresignedDownloadURL(ctx, app.ObjectKey, 15*time.Minute)
}
```

- [ ] **Step 4: Run test to verify it passes**

Run: `go test ./internal/service/... -v -run TestAppService`
Expected: PASS (all 4 `TestAppService_*` tests)

- [ ] **Step 5: Commit**

```bash
git add internal/service/app_service.go internal/service/app_service_test.go
git commit -m "feat: add app service with upload pipeline, list, get, delete, download-url"
```

---

### Task 14: App handler and router wiring

**Files:**
- Create: `internal/handler/app_handler.go`
- Test: `internal/handler/app_handler_test.go`
- Modify: `internal/router/router.go`
- Modify: `cmd/server/main.go`

**Interfaces:**
- Consumes: `service.AppService`/`UploadInput` (Task 13), `repository.AppListFilter` (Task 12), `middleware.ContextUserIDKey`/`JWTAuth` (Task 6), `response.Success`/`Error` (Task 2).
- Produces: `handler.AppHandler` with `NewAppHandler(appService *service.AppService) *AppHandler`, `Upload`, `List`, `Get`, `Delete`, `DownloadURL` (all `func(c *gin.Context)`) — wired into `router.Deps.AppHandler`.

- [ ] **Step 1: Write the failing end-to-end test**

Create `internal/handler/app_handler_test.go`:

```go
package handler_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"beetleshield-backend/internal/config"
	"beetleshield-backend/internal/db"
	"beetleshield-backend/internal/handler"
	"beetleshield-backend/internal/model"
	"beetleshield-backend/internal/pkg/hash"
	"beetleshield-backend/internal/pkg/storage"
	"beetleshield-backend/internal/repository"
	"beetleshield-backend/internal/router"
	"beetleshield-backend/internal/service"
)

func setupFullRouter(t *testing.T) (*httptest.Server, string, func()) {
	t.Helper()
	cfg := &config.Config{
		DBHost: "localhost", DBPort: "5432",
		DBUser: "root", DBPassword: "root",
		DBName: "beetleshield", DBSSLMode: "disable",
		JWTSecret: "test-secret", JWTExpireHours: 1,
		MaxUploadSizeMB: 10,
	}
	database, err := db.Connect(cfg)
	if err != nil {
		t.Fatalf("Connect() error = %v (is `make dev-up` running?)", err)
	}
	if err := db.Migrate(database); err != nil {
		t.Fatalf("Migrate() error = %v", err)
	}

	userRepo := repository.NewUserRepository(database)
	hashed, _ := hash.HashPassword("Password123!")
	testUser := model.User{
		Name: "应用接口测试用户", Email: "apphandler-test@beetleshield.com",
		PasswordHash: hashed, Role: model.RoleDeveloper, Status: model.UserStatusActive,
	}
	userRepo.DeleteByEmail(testUser.Email)
	if err := userRepo.Create(&testUser); err != nil {
		t.Fatalf("create test user: %v", err)
	}

	authService := service.NewAuthService(userRepo, cfg.JWTSecret, cfg.JWTExpireHours)
	token, _, err := authService.Login(testUser.Email, "Password123!")
	if err != nil {
		t.Fatalf("Login() error = %v", err)
	}
	authHandler := handler.NewAuthHandler(authService)

	st, err := storage.NewMinioStorage("localhost:9000", "admin", "yuan801200", "test-bucket", false)
	if err != nil {
		t.Fatalf("NewMinioStorage() error = %v", err)
	}
	if err := st.EnsureBucket(context.Background()); err != nil {
		t.Fatalf("EnsureBucket() error = %v", err)
	}
	appRepo := repository.NewAppRepository(database)
	appService := service.NewAppService(appRepo, st, cfg.MaxUploadSizeMB)
	appHandler := handler.NewAppHandler(appService)

	r := router.New(router.Deps{
		JWTSecret:   cfg.JWTSecret,
		AuthHandler: authHandler,
		AppHandler:  appHandler,
	})
	srv := httptest.NewServer(r)

	cleanup := func() {
		userRepo.DeleteByEmail(testUser.Email)
		database.Unscoped().Where("package_name LIKE ?", "com.handlertest.%").Delete(&model.App{})
		srv.Close()
	}
	return srv, token, cleanup
}

func TestAppUploadListGetDownloadDelete(t *testing.T) {
	srv, token, cleanup := setupFullRouter(t)
	defer cleanup()

	var buf bytes.Buffer
	w := multipart.NewWriter(&buf)
	if err := w.WriteField("tag", "tool"); err != nil {
		t.Fatalf("WriteField(tag): %v", err)
	}
	if err := w.WriteField("packageName", "com.handlertest.demo"); err != nil {
		t.Fatalf("WriteField(packageName): %v", err)
	}
	if err := w.WriteField("version", "1.0.0"); err != nil {
		t.Fatalf("WriteField(version): %v", err)
	}
	part, err := w.CreateFormFile("file", "demo.aab")
	if err != nil {
		t.Fatalf("CreateFormFile: %v", err)
	}
	if _, err := part.Write([]byte("fake aab content for handler test")); err != nil {
		t.Fatalf("write part: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("close writer: %v", err)
	}

	req, _ := http.NewRequest(http.MethodPost, srv.URL+"/api/v1/apps/upload", &buf)
	req.Header.Set("Content-Type", w.FormDataContentType())
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("upload request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("upload status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	var uploadResp struct {
		Data model.App `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&uploadResp); err != nil {
		t.Fatalf("decode upload response: %v", err)
	}
	appID := uploadResp.Data.ID
	if appID == 0 {
		t.Fatal("expected non-zero app ID")
	}

	listReq, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/apps?tag=tool", nil)
	listReq.Header.Set("Authorization", "Bearer "+token)
	listResp, err := http.DefaultClient.Do(listReq)
	if err != nil {
		t.Fatalf("list request: %v", err)
	}
	defer listResp.Body.Close()
	if listResp.StatusCode != http.StatusOK {
		t.Fatalf("list status = %d, want %d", listResp.StatusCode, http.StatusOK)
	}

	getReq, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/api/v1/apps/%d", srv.URL, appID), nil)
	getReq.Header.Set("Authorization", "Bearer "+token)
	getResp, err := http.DefaultClient.Do(getReq)
	if err != nil {
		t.Fatalf("get request: %v", err)
	}
	defer getResp.Body.Close()
	if getResp.StatusCode != http.StatusOK {
		t.Fatalf("get status = %d, want %d", getResp.StatusCode, http.StatusOK)
	}

	dlReq, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/api/v1/apps/%d/download-url", srv.URL, appID), nil)
	dlReq.Header.Set("Authorization", "Bearer "+token)
	dlResp, err := http.DefaultClient.Do(dlReq)
	if err != nil {
		t.Fatalf("download-url request: %v", err)
	}
	defer dlResp.Body.Close()
	if dlResp.StatusCode != http.StatusOK {
		t.Fatalf("download-url status = %d, want %d", dlResp.StatusCode, http.StatusOK)
	}

	delReq, _ := http.NewRequest(http.MethodDelete, fmt.Sprintf("%s/api/v1/apps/%d", srv.URL, appID), nil)
	delReq.Header.Set("Authorization", "Bearer "+token)
	delResp, err := http.DefaultClient.Do(delReq)
	if err != nil {
		t.Fatalf("delete request: %v", err)
	}
	defer delResp.Body.Close()
	if delResp.StatusCode != http.StatusOK {
		t.Fatalf("delete status = %d, want %d", delResp.StatusCode, http.StatusOK)
	}

	getReq2, _ := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/api/v1/apps/%d", srv.URL, appID), nil)
	getReq2.Header.Set("Authorization", "Bearer "+token)
	getResp2, err := http.DefaultClient.Do(getReq2)
	if err != nil {
		t.Fatalf("get-after-delete request: %v", err)
	}
	defer getResp2.Body.Close()
	if getResp2.StatusCode != http.StatusNotFound {
		t.Fatalf("get-after-delete status = %d, want %d", getResp2.StatusCode, http.StatusNotFound)
	}
}

func TestAppList_RequiresAuth(t *testing.T) {
	srv, _, cleanup := setupFullRouter(t)
	defer cleanup()

	resp, err := http.Get(srv.URL + "/api/v1/apps")
	if err != nil {
		t.Fatalf("request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusUnauthorized)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/handler/... -v -run TestAppUpload`
Expected: FAIL — package doesn't compile (`handler.NewAppHandler`, `router.Deps.AppHandler` undefined).

- [ ] **Step 3: Implement the app handler**

Create `internal/handler/app_handler.go`:

```go
package handler

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"

	"beetleshield-backend/internal/middleware"
	"beetleshield-backend/internal/model"
	"beetleshield-backend/internal/pkg/response"
	"beetleshield-backend/internal/repository"
	"beetleshield-backend/internal/service"
)

type AppHandler struct {
	appService *service.AppService
}

func NewAppHandler(appService *service.AppService) *AppHandler {
	return &AppHandler{appService: appService}
}

var validAppTags = map[model.AppTag]bool{
	model.AppTagFinance:   true,
	model.AppTagGame:      true,
	model.AppTagTool:      true,
	model.AppTagEcommerce: true,
}

func (h *AppHandler) Upload(c *gin.Context) {
	fileHeader, err := c.FormFile("file")
	if err != nil {
		response.Error(c, http.StatusBadRequest, 40002, "缺少上传文件")
		return
	}

	tag := model.AppTag(c.PostForm("tag"))
	if !validAppTags[tag] {
		response.Error(c, http.StatusBadRequest, 40006, "无效的应用标签")
		return
	}

	userID := c.GetUint(middleware.ContextUserIDKey)

	input := service.UploadInput{
		FileHeader:        fileHeader,
		Tag:               tag,
		ManualPackageName: c.PostForm("packageName"),
		ManualVersion:     c.PostForm("version"),
		UploadedBy:        userID,
	}

	app, err := h.appService.Upload(c.Request.Context(), input)
	if err != nil {
		switch {
		case errors.Is(err, service.ErrUnsupportedFileType):
			response.Error(c, http.StatusBadRequest, 40003, err.Error())
		case errors.Is(err, service.ErrFileTooLarge):
			response.Error(c, http.StatusBadRequest, 40004, err.Error())
		case errors.Is(err, service.ErrMissingPackageInfo):
			response.Error(c, http.StatusUnprocessableEntity, 42201, err.Error())
		default:
			response.Error(c, http.StatusInternalServerError, 50001, "上传失败，请稍后重试")
		}
		return
	}

	response.Success(c, http.StatusOK, app)
}

func (h *AppHandler) List(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	pageSize, _ := strconv.Atoi(c.DefaultQuery("pageSize", "10"))

	filter := repository.AppListFilter{
		Search:   c.Query("search"),
		Status:   c.Query("status"),
		Tag:      c.Query("tag"),
		Page:     page,
		PageSize: pageSize,
	}

	apps, total, err := h.appService.List(filter)
	if err != nil {
		response.Error(c, http.StatusInternalServerError, 50002, "查询应用列表失败")
		return
	}

	response.Success(c, http.StatusOK, gin.H{
		"items": apps,
		"total": total,
	})
}

func (h *AppHandler) Get(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		response.Error(c, http.StatusBadRequest, 40005, "非法的应用 ID")
		return
	}

	app, err := h.appService.Get(uint(id))
	if err != nil {
		response.Error(c, http.StatusNotFound, 40402, "应用不存在")
		return
	}

	response.Success(c, http.StatusOK, app)
}

func (h *AppHandler) Delete(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		response.Error(c, http.StatusBadRequest, 40005, "非法的应用 ID")
		return
	}

	if err := h.appService.Delete(c.Request.Context(), uint(id)); err != nil {
		if errors.Is(err, service.ErrAppNotFound) {
			response.Error(c, http.StatusNotFound, 40402, "应用不存在")
			return
		}
		response.Error(c, http.StatusInternalServerError, 50003, "删除应用失败")
		return
	}

	response.Success(c, http.StatusOK, nil)
}

func (h *AppHandler) DownloadURL(c *gin.Context) {
	id, err := strconv.ParseUint(c.Param("id"), 10, 64)
	if err != nil {
		response.Error(c, http.StatusBadRequest, 40005, "非法的应用 ID")
		return
	}

	downloadURL, err := h.appService.DownloadURL(c.Request.Context(), uint(id))
	if err != nil {
		if errors.Is(err, service.ErrAppNotFound) {
			response.Error(c, http.StatusNotFound, 40402, "应用不存在")
			return
		}
		response.Error(c, http.StatusInternalServerError, 50004, "生成下载链接失败")
		return
	}

	response.Success(c, http.StatusOK, gin.H{"url": downloadURL})
}
```

- [ ] **Step 4: Wire the app routes into the router**

Modify `internal/router/router.go`:

```go
package router

import (
	"github.com/gin-gonic/gin"

	"beetleshield-backend/internal/handler"
	"beetleshield-backend/internal/middleware"
)

type Deps struct {
	JWTSecret   string
	AuthHandler *handler.AuthHandler
	AppHandler  *handler.AppHandler
}

func New(deps Deps) *gin.Engine {
	r := gin.New()
	r.Use(gin.Logger(), gin.Recovery(), middleware.CORS())

	r.GET("/health", func(c *gin.Context) {
		c.JSON(200, gin.H{"status": "ok"})
	})

	v1 := r.Group("/api/v1")
	{
		auth := v1.Group("/auth")
		{
			auth.POST("/login", deps.AuthHandler.Login)
			auth.GET("/me", middleware.JWTAuth(deps.JWTSecret), deps.AuthHandler.Me)
		}

		apps := v1.Group("/apps")
		apps.Use(middleware.JWTAuth(deps.JWTSecret))
		{
			apps.POST("/upload", deps.AppHandler.Upload)
			apps.GET("", deps.AppHandler.List)
			apps.GET("/:id", deps.AppHandler.Get)
			apps.DELETE("/:id", deps.AppHandler.Delete)
			apps.GET("/:id/download-url", deps.AppHandler.DownloadURL)
		}
	}

	return r
}
```

- [ ] **Step 5: Run test to verify it passes**

Run: `go test ./internal/handler/... -v`
Expected: PASS (`TestLoginAndMe`, `TestLogin_WrongPassword`, `TestAppUploadListGetDownloadDelete`, `TestAppList_RequiresAuth`)

- [ ] **Step 6: Wire the app service/handler into `main.go`**

Modify `cmd/server/main.go`:

```go
package main

import (
	"context"
	"log"

	"beetleshield-backend/internal/config"
	"beetleshield-backend/internal/db"
	"beetleshield-backend/internal/handler"
	"beetleshield-backend/internal/pkg/storage"
	"beetleshield-backend/internal/repository"
	"beetleshield-backend/internal/router"
	"beetleshield-backend/internal/service"
)

func main() {
	cfg, err := config.Load(".env")
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	database, err := db.Connect(cfg)
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}

	if err := db.Migrate(database); err != nil {
		log.Fatalf("failed to migrate database: %v", err)
	}

	if err := db.SeedAdmin(database, cfg.AdminEmail, cfg.AdminPassword); err != nil {
		log.Fatalf("failed to seed admin account: %v", err)
	}

	storageClient, err := storage.NewMinioStorage(cfg.MinioEndpoint, cfg.MinioAccessKey, cfg.MinioSecretKey, cfg.MinioBucket, cfg.MinioUseSSL)
	if err != nil {
		log.Fatalf("failed to init storage client: %v", err)
	}
	if err := storageClient.EnsureBucket(context.Background()); err != nil {
		log.Fatalf("failed to ensure minio bucket: %v", err)
	}

	userRepo := repository.NewUserRepository(database)
	authService := service.NewAuthService(userRepo, cfg.JWTSecret, cfg.JWTExpireHours)
	authHandler := handler.NewAuthHandler(authService)

	appRepo := repository.NewAppRepository(database)
	appService := service.NewAppService(appRepo, storageClient, cfg.MaxUploadSizeMB)
	appHandler := handler.NewAppHandler(appService)

	r := router.New(router.Deps{
		JWTSecret:   cfg.JWTSecret,
		AuthHandler: authHandler,
		AppHandler:  appHandler,
	})

	if err := r.Run(":" + cfg.ServerPort); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}
```

- [ ] **Step 7: Commit**

```bash
git add internal/handler/app_handler.go internal/handler/app_handler_test.go internal/router/router.go cmd/server/main.go
git commit -m "feat: wire app management endpoints through router and main"
```

---

### Task 15: README, smoke test script, final verification

**Files:**
- Create: `README.md`
- Create: `scripts/smoke_test.sh`

**Interfaces:**
- Consumes: nothing new (this task only documents and exercises the completed system from Tasks 1–14).

- [ ] **Step 1: Write `README.md`**

Create `README.md`:

````markdown
# BeetleShield Backend

Go + Gin backend for the BeetleShield Android hardening management platform.
This is sub-project one: project foundation + login + app management.
See `docs/superpowers/specs/2026-07-02-backend-foundation-app-management-design.md`
for the full design.

## Prerequisites

- Go 1.22+
- Docker (for local PostgreSQL + MinIO)

## Local setup

```bash
cp .env.example .env
make dev-up      # starts postgres:16 and minio via docker-compose
make run         # starts the API server on :8080
```

On first run, the server seeds a default admin account (email/password from
`.env`, default `admin@beetleshield.com` / `ChangeMe123!`) and prints a log
line confirming it. Change the password after first login once the
user-management module exists.

## Running tests

Integration tests (`internal/db`, `internal/pkg/storage`, `internal/repository`,
`internal/service`, `internal/handler`) require `make dev-up` to be running.

```bash
make dev-up
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
````

- [ ] **Step 2: Write `scripts/smoke_test.sh`**

Create `scripts/smoke_test.sh`:

```bash
#!/usr/bin/env bash
set -euo pipefail

BASE_URL="${BASE_URL:-http://localhost:8080}"
EMAIL="${ADMIN_EMAIL:-admin@beetleshield.com}"
PASSWORD="${ADMIN_PASSWORD:?set ADMIN_PASSWORD to the value from your .env}"

echo "== Login =="
TOKEN=$(curl -s -X POST "$BASE_URL/api/v1/auth/login" \
  -H "Content-Type: application/json" \
  -d "{\"email\":\"$EMAIL\",\"password\":\"$PASSWORD\"}" | jq -r '.data.token')

if [ "$TOKEN" == "null" ] || [ -z "$TOKEN" ]; then
  echo "Login failed"
  exit 1
fi
echo "Got token: ${TOKEN:0:20}..."

echo "== Me =="
curl -s "$BASE_URL/api/v1/auth/me" -H "Authorization: Bearer $TOKEN" | jq .

echo "== Upload (manual package info) =="
echo "dummy content" > /tmp/beetleshield-smoke.aab
UPLOAD_RESP=$(curl -s -X POST "$BASE_URL/api/v1/apps/upload" \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@/tmp/beetleshield-smoke.aab" \
  -F "tag=tool" \
  -F "packageName=com.smoketest.demo" \
  -F "version=1.0.0")
echo "$UPLOAD_RESP" | jq .
APP_ID=$(echo "$UPLOAD_RESP" | jq -r '.data.id')

echo "== List =="
curl -s "$BASE_URL/api/v1/apps?tag=tool" -H "Authorization: Bearer $TOKEN" | jq .

echo "== Get =="
curl -s "$BASE_URL/api/v1/apps/$APP_ID" -H "Authorization: Bearer $TOKEN" | jq .

echo "== Download URL =="
curl -s "$BASE_URL/api/v1/apps/$APP_ID/download-url" -H "Authorization: Bearer $TOKEN" | jq .

echo "== Delete =="
curl -s -X DELETE "$BASE_URL/api/v1/apps/$APP_ID" -H "Authorization: Bearer $TOKEN" | jq .

rm -f /tmp/beetleshield-smoke.aab
echo "Smoke test passed."
```

```bash
chmod +x scripts/smoke_test.sh
```

- [ ] **Step 3: Run the full test suite**

```bash
make dev-up
make test
```

Expected: all packages report `ok` (config, pkg/response, pkg/jwtutil, pkg/hash, db, pkg/storage, pkg/manifest, repository, service, handler).

- [ ] **Step 4: Run the smoke test against a live server**

```bash
make run &
sleep 1
ADMIN_PASSWORD=ChangeMe123! ./scripts/smoke_test.sh
kill %1
```

Expected: `Smoke test passed.` printed at the end, with every intermediate `jq` block showing `"code": 0`.

- [ ] **Step 5: Commit**

```bash
git add README.md scripts/smoke_test.sh
git commit -m "docs: add README and end-to-end smoke test script"
```

---

## Post-plan note

This completes sub-project one. The next sub-projects (in the order recorded
in the design spec) are: user management CRUD + RBAC matrix, strategy center,
hardening pipeline (engine integration), reports, log audit, and the
dashboard aggregation endpoints — each should go through its own
brainstorming → spec → plan cycle rather than being bolted onto this one.
