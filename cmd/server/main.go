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
	"github.com/asakuno/huma-sample/app/middleware"
	"github.com/asakuno/huma-sample/app/modules/auth"
	"github.com/asakuno/huma-sample/cmd/migration"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
	chMiddleware "github.com/go-chi/chi/v5/middleware"
	"gorm.io/gorm"

	_ "github.com/danielgtaylor/huma/v2/formats/cbor"
)

// GreetingInput represents the greeting operation input.
type GreetingInput struct {
	Name string `path:"name" maxLength:"30" example:"world" doc:"Name to greet"`
}

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
		Version  string `json:"version" example:"1.0.0" doc:"API version"`
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

	// Add Chi middleware
	router.Use(chMiddleware.Logger)
	router.Use(chMiddleware.Recoverer)
	router.Use(chMiddleware.RequestID)
	router.Use(chMiddleware.RealIP)
	router.Use(chMiddleware.Timeout(60 * time.Second))

	// Create Huma API configuration
	apiConfig := huma.DefaultConfig(cfg.AppName+" API", "1.0.0")
	apiConfig.Info.Description = "A sample REST API built with Huma framework, featuring authentication, user management, and AWS Cognito integration."
	apiConfig.Info.Contact = &huma.Contact{
		Name:  "API Support",
		Email: "support@example.com",
		URL:   "https://example.com/support",
	}
	apiConfig.Info.License = &huma.License{
		Name: "MIT",
		URL:  "https://opensource.org/licenses/MIT",
	}

	// Add servers information
	apiConfig.Servers = []*huma.Server{
		{
			URL:         fmt.Sprintf("http://localhost:%s", cfg.Port),
			Description: "Development server",
		},
	}

	// Create Huma API
	api := humachi.New(router, apiConfig)

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
		log.Printf("API Documentation: http://localhost:%s/docs", cfg.Port)
		log.Printf("OpenAPI Spec: http://localhost:%s/openapi.json", cfg.Port)
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

// registerRoutes registers all API routes using Huma Groups for better organization
func registerRoutes(api huma.API, db *gorm.DB) {
	// Create API v1 group for versioning
	v1Group := huma.NewGroup(api, "/v1")

	// Add global middleware to v1 group
	v1Group.UseMiddleware(middleware.SimpleCORS())

	// Public endpoints (no auth required)
	publicGroup := huma.NewGroup(api)

	// Health check endpoint
	huma.Get(publicGroup, "/health", func(ctx context.Context, input *struct{}) (*HealthOutput, error) {
		resp := &HealthOutput{}
		resp.Body.Status = "ok"
		resp.Body.Time = time.Now().Format(time.RFC3339)
		resp.Body.Version = "1.0.0"

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

	// Greeting endpoint (example public endpoint)
	huma.Get(publicGroup, "/greeting/{name}", func(ctx context.Context, input *GreetingInput) (*GreetingOutput, error) {
		resp := &GreetingOutput{}
		resp.Body.Message = fmt.Sprintf("Hello, %s!", input.Name)
		return resp, nil
	})

	// Register auth routes with Group functionality
	if err := auth.RegisterRoutes(api, db); err != nil {
		log.Fatalf("Failed to register auth routes: %v", err)
	}

	// Register admin routes (example of role-based routing)
	if err := auth.RegisterAdminRoutes(api, db); err != nil {
		log.Fatalf("Failed to register admin routes: %v", err)
	}

	// Example of versioned API group
	// v1Group could be used for versioned endpoints
	// huma.Get(v1Group, "/users", userController.ListUsers)
	// huma.Get(v1Group, "/users/{user-id}", userController.GetUser)

	// Example of protected endpoints group
	cfg := config.GetConfig()
	protectedGroup := huma.NewGroup(api, "/api")
	protectedGroup.UseMiddleware(middleware.RequireAuth(cfg.JWT.Secret))

	// Example protected endpoint
	// huma.Get(protectedGroup, "/me", userController.GetCurrentUser)

	// Add API documentation customization
	addAPIDocumentation(api)
}

// addAPIDocumentation adds additional documentation and examples to the API
func addAPIDocumentation(api huma.API) {
	// Add security schemes to OpenAPI
	openapi := api.OpenAPI()

	if openapi.Components == nil {
		openapi.Components = &huma.Components{}
	}

	if openapi.Components.SecuritySchemes == nil {
		openapi.Components.SecuritySchemes = make(map[string]*huma.SecurityScheme)
	}

	// Add Bearer token security scheme
	openapi.Components.SecuritySchemes["BearerAuth"] = &huma.SecurityScheme{
		Type:         "http",
		Scheme:       "bearer",
		BearerFormat: "JWT",
		Description:  "JWT Bearer token authentication",
	}

	// Add custom extensions for CLI auto-configuration
	if openapi.Extensions == nil {
		openapi.Extensions = make(map[string]any)
	}

	openapi.Extensions["x-cli-config"] = map[string]any{
		"security": "BearerAuth",
		"headers": map[string]string{
			"User-Agent": "huma-sample-cli/1.0.0",
		},
		"prompt": map[string]any{
			"server": map[string]any{
				"description": "API server URL",
				"default":     "http://localhost:8888",
			},
		},
	}
}
