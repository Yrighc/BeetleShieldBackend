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
