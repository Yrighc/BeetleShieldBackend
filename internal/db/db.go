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
