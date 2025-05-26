package main

import (
	"context"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/asakuno/huma-sample/app/config"
	"github.com/asakuno/huma-sample/cmd/migration"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"gorm.io/gorm"

	_ "github.com/danielgtaylor/huma/v2/formats/cbor"
)

// GreetingOutput represents the greeting operation response.
type GreetingOutput struct {
	Body struct {
		Message string `json:"message" example:"Hello, world!" doc:"Greeting message"`
	}
}

// HealthOutput represents the health check response.
type HealthOutput struct {
	Body struct {
		Status   string `json:"status" example:"ok" doc:"Health status"`
		Database string `json:"database" example:"connected" doc:"Database status"`
		Time     string `json:"time" example:"2023-01-01T00:00:00Z" doc:"Current time"`
	}
}

func main() {
	// Load configuration
	cfg := config.LoadConfig()
	log.Printf("Starting %s server on port %s", cfg.AppName, cfg.Port)

	// Setup database connection
	db := config.SetupDatabaseConnection()
	defer config.CloseDatabaseConnection(db)

	// Handle command line arguments
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "--migrate":
			if err := migration.Migrate(db); err != nil {
				log.Fatalf("Migration failed: %v", err)
			}
			log.Println("Migration completed successfully")
			return
		case "--seed":
			if err := migration.Seed(db); err != nil {
				log.Fatalf("Seeding failed: %v", err)
			}
			log.Println("Seeding completed successfully")
			return
		case "--migrate-seed":
			if err := migration.Migrate(db); err != nil {
				log.Fatalf("Migration failed: %v", err)
			}
			log.Println("Migration completed successfully")
			if err := migration.Seed(db); err != nil {
				log.Fatalf("Seeding failed: %v", err)
			}
			log.Println("Seeding completed successfully")
			return
		case "--rollback":
			if err := migration.Rollback(db); err != nil {
				log.Fatalf("Rollback failed: %v", err)
			}
			log.Println("Rollback completed successfully")
			return
		}
	}

	// Create router with middleware
	router := chi.NewMux()
	
	// Add middleware
	router.Use(middleware.Logger)
	router.Use(middleware.Recoverer)
	router.Use(middleware.RequestID)
	router.Use(middleware.RealIP)
	router.Use(middleware.Timeout(60 * time.Second))

	// Create Huma API
	api := humachi.New(router, huma.DefaultConfig(cfg.AppName+" API", "1.0.0"))

	// Register routes
	registerRoutes(api, db)

	// Create HTTP server
	server := &http.Server{
		Addr:         ":" + cfg.Port,
		Handler:      router,
		ReadTimeout:  30 * time.Second,
		WriteTimeout: 30 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	// Start server in a goroutine
	go func() {
		log.Printf("Server starting on http://0.0.0.0:%s", cfg.Port)
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("Server failed to start: %v", err)
		}
	}()

	// Wait for interrupt signal to gracefully shutdown the server
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("Shutting down server...")

	// Create a deadline to wait for
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Attempt graceful shutdown
	if err := server.Shutdown(ctx); err != nil {
		log.Printf("Server forced to shutdown: %v", err)
	} else {
		log.Println("Server exited gracefully")
	}
}

// registerRoutes registers all API routes
func registerRoutes(api huma.API, db *gorm.DB) {
	// Health check endpoint
	huma.Get(api, "/health", func(ctx context.Context, input *struct{}) (*HealthOutput, error) {
		resp := &HealthOutput{}
		resp.Body.Status = "ok"
		resp.Body.Time = time.Now().Format(time.RFC3339)
		
		// Check database connection
		if sqlDB, err := db.DB(); err != nil {
			resp.Body.Database = "error"
		} else if err := sqlDB.Ping(); err != nil {
			resp.Body.Database = "disconnected"
		} else {
			resp.Body.Database = "connected"
		}
		
		return resp, nil
	})

	// Greeting endpoint
	huma.Get(api, "/greeting/{name}", func(ctx context.Context, input *struct {
		Name string `path:"name" maxLength:"30" example:"world" doc:"Name to greet"`
	}) (*GreetingOutput, error) {
		resp := &GreetingOutput{}
		resp.Body.Message = fmt.Sprintf("Hello, %s!", input.Name)
		return resp, nil
	})
}
