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

// 主函数，程序的入口点
func main() {
	// 从.env文件加载配置
	cfg, err := config.Load(".env")
	if err != nil {
		log.Fatalf("failed to load config: %v", err)
	}

	// 连接数据库
	database, err := db.Connect(cfg)
	if err != nil {
		log.Fatalf("failed to connect to database: %v", err)
	}

	// 执行数据库迁移
	if err := db.Migrate(database); err != nil {
		log.Fatalf("failed to migrate database: %v", err)
	}

	// 初始化管理员账户
	if err := db.SeedAdmin(database, cfg.AdminEmail, cfg.AdminPassword); err != nil {
		log.Fatalf("failed to seed admin account: %v", err)
	}

	// 初始化对象存储客户端
	storageClient, err := storage.NewMinioStorage(cfg.MinioEndpoint, cfg.MinioAccessKey, cfg.MinioSecretKey, cfg.MinioBucket, cfg.MinioUseSSL)
	if err != nil {
		log.Fatalf("failed to init storage client: %v", err)
	}
	// 确保存储桶存在
	if err := storageClient.EnsureBucket(context.Background()); err != nil {
		log.Fatalf("failed to ensure minio bucket: %v", err)
	}

	// 初始化用户仓库
	userRepo := repository.NewUserRepository(database)
	// 初始化认证服务
	authService := service.NewAuthService(userRepo, cfg.JWTSecret, cfg.JWTExpireHours)
	// 初始化认证处理器
	authHandler := handler.NewAuthHandler(authService)

	// 初始化应用仓库
	appRepo := repository.NewAppRepository(database)
	// 初始化应用服务
	appService := service.NewAppService(appRepo, storageClient, cfg.MaxUploadSizeMB)
	// 初始化应用处理器
	appHandler := handler.NewAppHandler(appService)

	// 设置路由依赖
	r := router.New(router.Deps{
		JWTSecret:   cfg.JWTSecret,
		AuthHandler: authHandler,
		AppHandler:  appHandler,
	})

	// 启动服务器，监听配置的端口
	if err := r.Run(":" + cfg.ServerPort); err != nil {
		log.Fatalf("server failed: %v", err)
	}
}
