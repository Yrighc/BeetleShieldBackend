package main

import (
	"context"
	"errors"
	"log"
	"net/http"
	"os/signal"
	"syscall"
	"time"

	"beetleshield-backend/internal/config"
	"beetleshield-backend/internal/db"
	"beetleshield-backend/internal/handler"
	"beetleshield-backend/internal/middleware"
	"beetleshield-backend/internal/pkg/storage"
	"beetleshield-backend/internal/repository"
	"beetleshield-backend/internal/router"
	"beetleshield-backend/internal/service"
	"beetleshield-backend/internal/worker"
)

// shutdownTimeout bounds how long graceful shutdown waits for the HTTP
// server to drain in-flight requests and for the hardening worker to finish
// its current task before the process exits anyway.
const shutdownTimeout = 15 * time.Second

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
	auditRepo := repository.NewAuditRepository(database)
	auditService := service.NewAuditService(auditRepo)
	auditHandler := handler.NewAuditHandler(auditService)

	apiRequestLogRepo := repository.NewAPIRequestLogRepository(database)
	apiRequestLogService := service.NewAPIRequestLogService(apiRequestLogRepo)
	apiRequestLogHandler := handler.NewAPIRequestLogHandler(apiRequestLogService)
	requestLogRecorder := middleware.RequestLogRecorderFunc(func(entry middleware.RequestLogEntry) {
		apiRequestLogService.Record(service.RecordAPIRequestInput{
			Method: entry.Method, Path: entry.Path, Status: entry.Status,
			LatencyMS: entry.LatencyMS, ClientIP: entry.ClientIP, ActorUserID: entry.ActorUserID,
		})
	})

	authService := service.NewAuthService(userRepo, cfg.JWTSecret, cfg.JWTExpireHours, auditService)
	authHandler := handler.NewAuthHandler(authService)

	userService := service.NewUserService(userRepo, auditService)
	userHandler := handler.NewUserHandler(userService)

	appRepo := repository.NewAppRepository(database)
	hardeningRepo := repository.NewHardeningRepository(database)
	appService := service.NewAppService(appRepo, hardeningRepo, storageClient, cfg.MaxUploadSizeMB, auditService)
	appHandler := handler.NewAppHandler(appService)

	strategyRepo := repository.NewStrategyRepository(database)
	strategyService := service.NewStrategyService(strategyRepo, auditService)
	strategyHandler := handler.NewStrategyHandler(strategyService)

	hardeningService := service.NewHardeningService(
		hardeningRepo,
		appRepo,
		strategyService,
		storageClient,
		cfg.DPTDefaultVMPRules,
		auditService,
	)
	hardeningHandler := handler.NewHardeningHandler(hardeningService)
	hardeningWorker := worker.NewHardeningWorker(
		hardeningRepo,
		storageClient,
		worker.DPTRunner{},
		worker.HardeningWorkerConfig{
			JarPath:         cfg.DPTJarPath,
			WorkDir:         cfg.DPTWorkDir,
			DefaultVMPRules: cfg.DPTDefaultVMPRules,
			Timeout:         time.Duration(cfg.DPTTaskTimeoutMinutes) * time.Minute,
		},
	)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	workerDone := hardeningWorker.Start(ctx, 3*time.Second)

	r := router.New(router.Deps{
		JWTSecret:            cfg.JWTSecret,
		AuthHandler:          authHandler,
		AppHandler:           appHandler,
		UserHandler:          userHandler,
		StrategyHandler:      strategyHandler,
		HardeningHandler:     hardeningHandler,
		AuditHandler:         auditHandler,
		APIRequestLogHandler: apiRequestLogHandler,
		RequestLogRecorder:   requestLogRecorder,
	})

	srv := &http.Server{Addr: ":" + cfg.ServerPort, Handler: r}
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Fatalf("server failed: %v", err)
		}
	}()

	<-ctx.Done()
	log.Println("shutdown signal received, draining...")

	shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("http server shutdown error: %v", err)
	}

	select {
	case <-workerDone:
	case <-shutdownCtx.Done():
		log.Println("hardening worker did not stop before shutdown timeout")
	}
}
