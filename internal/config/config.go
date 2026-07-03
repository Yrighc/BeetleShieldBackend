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

	DPTJarPath            string
	DPTWorkDir            string
	DPTDefaultVMPRules    string
	DPTTaskTimeoutMinutes int

	HardeningEngineVersion string

	AdminEmail    string
	AdminPassword string

	// StaticDir, when non-empty, makes the server also host the frontend
	// SPA (see internal/router.spaFallback) instead of API-only. Left
	// unset (default "") for local `go run` dev, where the frontend runs
	// separately via `npm run dev`.
	StaticDir string
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
	v.SetDefault("DPT_JAR_PATH", "/Users/yrighc/work/hzyz/project/test/dpt-shell/executable/dpt.jar")
	v.SetDefault("DPT_WORK_DIR", "/tmp/beetleshield-hardening")
	v.SetDefault("DPT_DEFAULT_VMP_RULES", "# 全量探测保护 (依赖内置规则引擎进行智能避让)\n**")
	v.SetDefault("DPT_TASK_TIMEOUT_MINUTES", 60)
	v.SetDefault("HARDENING_ENGINE_VERSION", "BeetleShield Engine v2.4.1")

	if err := v.ReadInConfig(); err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	cfg := &Config{
		ServerPort:             v.GetString("SERVER_PORT"),
		DBHost:                 v.GetString("DB_HOST"),
		DBPort:                 v.GetString("DB_PORT"),
		DBUser:                 v.GetString("DB_USER"),
		DBPassword:             v.GetString("DB_PASSWORD"),
		DBName:                 v.GetString("DB_NAME"),
		DBSSLMode:              v.GetString("DB_SSLMODE"),
		JWTSecret:              v.GetString("JWT_SECRET"),
		JWTExpireHours:         v.GetInt("JWT_EXPIRE_HOURS"),
		MinioEndpoint:          v.GetString("MINIO_ENDPOINT"),
		MinioAccessKey:         v.GetString("MINIO_ACCESS_KEY"),
		MinioSecretKey:         v.GetString("MINIO_SECRET_KEY"),
		MinioUseSSL:            v.GetBool("MINIO_USE_SSL"),
		MinioBucket:            v.GetString("MINIO_BUCKET"),
		MaxUploadSizeMB:        v.GetInt64("MAX_UPLOAD_SIZE_MB"),
		DPTJarPath:             v.GetString("DPT_JAR_PATH"),
		DPTWorkDir:             v.GetString("DPT_WORK_DIR"),
		DPTDefaultVMPRules:     v.GetString("DPT_DEFAULT_VMP_RULES"),
		DPTTaskTimeoutMinutes:  v.GetInt("DPT_TASK_TIMEOUT_MINUTES"),
		HardeningEngineVersion: v.GetString("HARDENING_ENGINE_VERSION"),
		AdminEmail:             v.GetString("ADMIN_EMAIL"),
		AdminPassword:          v.GetString("ADMIN_PASSWORD"),
		StaticDir:              v.GetString("STATIC_DIR"),
	}

	if cfg.JWTSecret == "" {
		return nil, fmt.Errorf("JWT_SECRET is required")
	}

	return cfg, nil
}
