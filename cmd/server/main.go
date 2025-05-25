package main

import (
	"context"
	"database/sql"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/asakuno/huma-sample/auth"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"

	_ "github.com/danielgtaylor/huma/v2/formats/cbor"
	_ "github.com/go-sql-driver/mysql"
)

// GreetingOutput represents the greeting operation response.
type GreetingOutput struct {
	Body struct {
		Message string `json:"message" example:"Hello, world!" doc:"Greeting message"`
	}
}

func main() {
	ctx := context.Background()

	// Initialize database connection
	db, err := initDatabase()
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}
	defer db.Close()

	// Run database migrations
	if err := runMigrations(db); err != nil {
		log.Fatalf("Failed to run migrations: %v", err)
	}

	// Create a new router
	router := chi.NewMux()

	// Add middleware
	router.Use(middleware.Logger)
	router.Use(middleware.Recoverer)
	router.Use(middleware.RequestID)

	// Create Huma API
	api := humachi.New(router, huma.DefaultConfig("My API with Auth", "1.0.0"))

	// Initialize auth module
	authConfig := auth.NewConfig(db)
	authModule, err := auth.NewModule(ctx, authConfig)
	if err != nil {
		log.Fatalf("Failed to initialize auth module: %v", err)
	}

	// Add CORS middleware
	router.Use(authModule.Middleware.CORSMiddleware())

	// Register auth routes
	authModule.Handler.RegisterRoutes(api)

	// Protected routes group
	protectedRouter := chi.NewRouter()
	protectedRouter.Use(authModule.Middleware.Middleware())

	// Admin routes group
	adminRouter := chi.NewRouter()
	adminRouter.Use(authModule.Middleware.AdminMiddleware())

	// Mount protected and admin routers
	router.Mount("/api/v1", protectedRouter)
	router.Mount("/admin", adminRouter)

	// Register sample greeting endpoint (protected)
	huma.Register(api, huma.Operation{
		OperationID: "greeting",
		Method:      http.MethodGet,
		Path:        "/api/v1/greeting/{name}",
		Summary:     "Get greeting (Protected)",
		Description: "Get a greeting message for the specified name (requires authentication)",
		Tags:        []string{"Greetings"},
	}, func(ctx context.Context, input *struct {
		Name string `path:"name" maxLength:"30" example:"world" doc:"Name to greet"`
	}) (*GreetingOutput, error) {
		resp := &GreetingOutput{}
		resp.Body.Message = fmt.Sprintf("Hello, %s! You are authenticated.", input.Name)
		return resp, nil
	})

	// Register public greeting endpoint
	huma.Register(api, huma.Operation{
		OperationID: "public-greeting",
		Method:      http.MethodGet,
		Path:        "/greeting/{name}",
		Summary:     "Get greeting (Public)",
		Description: "Get a greeting message for the specified name (no authentication required)",
		Tags:        []string{"Greetings"},
	}, func(ctx context.Context, input *struct {
		Name string `path:"name" maxLength:"30" example:"world" doc:"Name to greet"`
	}) (*GreetingOutput, error) {
		resp := &GreetingOutput{}
		resp.Body.Message = fmt.Sprintf("Hello, %s!", input.Name)
		return resp, nil
	})

	// Health check endpoint
	huma.Register(api, huma.Operation{
		OperationID: "health",
		Method:      http.MethodGet,
		Path:        "/health",
		Summary:     "Health check",
		Description: "Check the health status of the API",
		Tags:        []string{"System"},
	}, func(ctx context.Context, input *struct{}) (*struct {
		Body struct {
			Status    string `json:"status" example:"ok"`
			Timestamp string `json:"timestamp" example:"2023-01-01T00:00:00Z"`
		}
	}, error) {
		resp := &struct {
			Body struct {
				Status    string `json:"status" example:"ok"`
				Timestamp string `json:"timestamp" example:"2023-01-01T00:00:00Z"`
			}
		}{}
		resp.Body.Status = "ok"
		resp.Body.Timestamp = "2023-01-01T00:00:00Z" // In real app, use time.Now()
		return resp, nil
	})

	fmt.Println("🚀 Server starting on :8888")
	fmt.Println("📋 API Documentation: http://localhost:8888/docs")
	fmt.Println("🔐 Auth endpoints:")
	fmt.Println("   POST /auth/login - User login")
	fmt.Println("   POST /auth/logout - User logout")
	fmt.Println("   GET  /auth/me - Get user profile")
	fmt.Println("   PUT  /auth/me - Update user profile")
	fmt.Println("   POST /auth/refresh - Refresh token")
	fmt.Println("   POST /auth/forgot-password - Forgot password")
	fmt.Println("   POST /auth/confirm-forgot-password - Confirm forgot password")
	fmt.Println("   POST /admin/users - Create user (admin)")

	// Start the server!
	if err := http.ListenAndServe("0.0.0.0:8888", router); err != nil {
		log.Fatalf("Server failed to start: %v", err)
	}
}

// initDatabase initializes the database connection
func initDatabase() (*sql.DB, error) {
	// Get database configuration from environment variables
	dbUser := getEnvOrDefault("DB_USER", "user")
	dbPassword := getEnvOrDefault("DB_PASSWORD", "password")
	dbHost := getEnvOrDefault("DB_HOST", "mysql")
	dbPort := getEnvOrDefault("DB_PORT", "3306")
	dbName := getEnvOrDefault("DB_NAME", "database")

	// Create DSN (Data Source Name)
	dsn := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?charset=utf8mb4&parseTime=True&loc=Local",
		dbUser, dbPassword, dbHost, dbPort, dbName)

	// Open database connection
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to open database: %w", err)
	}

	// Test the connection
	if err := db.Ping(); err != nil {
		return nil, fmt.Errorf("failed to ping database: %w", err)
	}

	// Configure connection pool
	db.SetMaxOpenConns(25)
	db.SetMaxIdleConns(5)

	return db, nil
}

// runMigrations runs database migrations
func runMigrations(db *sql.DB) error {
	// Read and execute the users table migration
	migrationSQL := `
-- Create users table for storing user information
CREATE TABLE IF NOT EXISTS users (
    id CHAR(36) PRIMARY KEY,
    cognito_id VARCHAR(255) UNIQUE,
    username VARCHAR(255) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    status ENUM('active', 'inactive', 'suspended', 'pending') NOT NULL DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    INDEX idx_users_cognito_id (cognito_id),
    INDEX idx_users_email (email),
    INDEX idx_users_username (username),
    INDEX idx_users_status (status),
    INDEX idx_users_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
`

	_, err := db.Exec(migrationSQL)
	if err != nil {
		return fmt.Errorf("failed to create users table: %w", err)
	}

	fmt.Println("✅ Database migrations completed successfully")
	return nil
}

// getEnvOrDefault gets an environment variable or returns a default value
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}
