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

func TestLoad_MissingFileFallsBackToEnvVars(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env") // deliberately never written

	t.Setenv("JWT_SECRET", "from-real-env-var")
	t.Setenv("DB_HOST", "postgres")

	cfg, err := Load(envPath)
	if err != nil {
		t.Fatalf("Load() error = %v, want nil — a missing .env file should fall back to process env vars, matching `docker run -e ...` without a mounted .env", err)
	}
	if cfg.JWTSecret != "from-real-env-var" {
		t.Errorf("JWTSecret = %q, want %q", cfg.JWTSecret, "from-real-env-var")
	}
	if cfg.DBHost != "postgres" {
		t.Errorf("DBHost = %q, want %q", cfg.DBHost, "postgres")
	}
	if cfg.ServerPort != "8080" {
		t.Errorf("ServerPort = %q, want default %q", cfg.ServerPort, "8080")
	}
}

func TestLoad_MissingFileAndMissingJWTSecretStillErrors(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env") // deliberately never written

	if _, err := Load(envPath); err == nil {
		t.Fatal("Load() expected error for missing JWT_SECRET, got nil")
	}
}

func TestLoad_DPTDefaults(t *testing.T) {
	dir := t.TempDir()
	envPath := filepath.Join(dir, ".env")
	content := []byte("JWT_SECRET=test-secret\nDB_HOST=localhost\n")
	if err := os.WriteFile(envPath, content, 0600); err != nil {
		t.Fatalf("write env: %v", err)
	}

	cfg, err := Load(envPath)
	if err != nil {
		t.Fatalf("Load() error = %v", err)
	}
	if cfg.DPTJarPath != "/Users/yrighc/work/hzyz/project/test/dpt-shell/executable/dpt.jar" {
		t.Fatalf("DPTJarPath = %q", cfg.DPTJarPath)
	}
	if cfg.DPTWorkDir != "/tmp/beetleshield-hardening" {
		t.Fatalf("DPTWorkDir = %q", cfg.DPTWorkDir)
	}
	if cfg.DPTDefaultVMPRules != "# 全量探测保护 (依赖内置规则引擎进行智能避让)\n**" {
		t.Fatalf("DPTDefaultVMPRules = %q", cfg.DPTDefaultVMPRules)
	}
	if cfg.DPTTaskTimeoutMinutes != 60 {
		t.Fatalf("DPTTaskTimeoutMinutes = %d", cfg.DPTTaskTimeoutMinutes)
	}
}
