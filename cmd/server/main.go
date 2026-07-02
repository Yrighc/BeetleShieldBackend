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

	userService := service.NewUserService(userRepo)
	userHandler := handler.NewUserHandler(userService)

	appRepo := repository.NewAppRepository(database)
	appService := service.NewAppService(appRepo, storageClient, cfg.MaxUploadSizeMB)
	appHandler := handler.NewAppHandler(appService)

	strategyRepo := repository.NewStrategyRepository(database)
	strategyService := service.NewStrategyService(strategyRepo)
	strategyHandler := handler.NewStrategyHandler(strategyService)

	hardeningRepo := repository.NewHardeningRepository(database)
	hardeningService := service.NewHardeningService(
		hardeningRepo,
		appRepo,
		strategyService,
		storageClient,
		cfg.DPTDefaultVMPRules,
	)
	hardeningHandler := handler.NewHardeningHandler(hardeningService)

	r := router.New(router.Deps{
		JWTSecret:        cfg.JWTSecret,
		AuthHandler:      authHandler,
		AppHandler:       appHandler,
		UserHandler:      userHandler,
		StrategyHandler:  strategyHandler,
		HardeningHandler: hardeningHandler,
	})

	if err := r.Run(":" + cfg.ServerPort); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}
