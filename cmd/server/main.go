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
