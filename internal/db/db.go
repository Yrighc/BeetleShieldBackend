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
	// Foreign key constraints are intentionally not created at the database level.
	// Referential integrity between models (e.g. "an app with an active hardening
	// task cannot be deleted") is enforced in the service layer, not via DB
	// features, so the schema stays free of physical FK constraints.
	database, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		DisableForeignKeyConstraintWhenMigrating: true,
	})
	if err != nil {
		return nil, fmt.Errorf("connect database: %w", err)
	}
	return database, nil
}

func Migrate(database *gorm.DB) error {
	// Drop any foreign key constraint left over from before FK constraints were
	// disabled at migration time, so re-running Migrate on an existing database
	// converges to the same FK-free schema as a fresh one.
	if database.Migrator().HasConstraint(&model.HardeningTask{}, "App") {
		if err := database.Migrator().DropConstraint(&model.HardeningTask{}, "App"); err != nil {
			return fmt.Errorf("drop hardening_tasks app foreign key: %w", err)
		}
	}

	return database.AutoMigrate(
		&model.User{},
		&model.App{},
		&model.Strategy{},
		&model.HardeningTask{},
		&model.HardeningStep{},
		&model.HardeningLog{},
		&model.AuditLog{},
	)
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
