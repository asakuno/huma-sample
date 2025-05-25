package auth

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"strings"

	"github.com/asakuno/huma-sample/auth/domain/service"
	"github.com/asakuno/huma-sample/auth/infrastructure/cognito"
	"github.com/asakuno/huma-sample/auth/infrastructure/persistence"
	"github.com/asakuno/huma-sample/auth/presentation/handler"
	"github.com/asakuno/huma-sample/auth/presentation/middleware"
	"github.com/asakuno/huma-sample/auth/usecase"
)

// Config holds the configuration for the auth module
type Config struct {
	Cognito *cognito.Config
	DB      *sql.DB
}

// Module represents the auth module with all its components
type Module struct {
	Handler    *handler.AuthHandler
	Middleware *middleware.JWTMiddleware
}

// NewModule creates a new auth module with dependency injection
func NewModule(ctx context.Context, config *Config) (*Module, error) {
	if config == nil {
		return nil, fmt.Errorf("config is required")
	}

	if config.DB == nil {
		return nil, fmt.Errorf("database connection is required")
	}

	if config.Cognito == nil {
		return nil, fmt.Errorf("cognito config is required")
	}

	// Initialize repositories
	userRepo := persistence.NewUserRepository(config.DB)
	
	// Choose auth repository based on environment
	var authRepo interface{}
	var err error
	
	// Check if we should use mock Cognito (for development)
	if shouldUseMockCognito() {
		fmt.Println("🔧 Using mock Cognito for development environment")
		authRepo = cognito.NewMockAuthRepository()
	} else {
		// Validate Cognito configuration for real Cognito
		if err := config.Cognito.Validate(); err != nil {
			return nil, fmt.Errorf("invalid cognito config: %w", err)
		}

		// Initialize real Cognito client
		cognitoClient, err := cognito.NewClient(ctx, config.Cognito)
		if err != nil {
			return nil, fmt.Errorf("failed to create cognito client: %w", err)
		}
		
		authRepo = cognito.NewAuthRepository(cognitoClient)
		fmt.Println("🔗 Using real AWS Cognito")
	}

	// Initialize services
	authService := service.NewAuthService(userRepo, authRepo.(interface {
		Authenticate(ctx context.Context, req *interface{}) (*interface{}, error) // This is a simplified interface casting
	}))

	// Initialize use cases
	authUsecase := usecase.NewAuthUsecase(authService)

	// Initialize handlers and middleware
	authHandler := handler.NewAuthHandler(authUsecase)
	jwtMiddleware := middleware.NewJWTMiddleware(authUsecase)

	return &Module{
		Handler:    authHandler,
		Middleware: jwtMiddleware,
	}, nil
}

// NewConfig creates a new auth configuration
func NewConfig(db *sql.DB) *Config {
	return &Config{
		Cognito: cognito.NewConfig(),
		DB:      db,
	}
}

// shouldUseMockCognito determines whether to use mock Cognito based on environment
func shouldUseMockCognito() bool {
	// Check explicit mock flag
	if mockCognito := os.Getenv("MOCK_COGNITO"); mockCognito == "true" {
		return true
	}

	// Check if we're in development mode
	if appEnv := os.Getenv("APP_ENV"); appEnv == "development" || appEnv == "dev" {
		// In development, use mock if Cognito credentials look like dummy values
		userPoolID := os.Getenv("COGNITO_USER_POOL_ID")
		clientID := os.Getenv("COGNITO_CLIENT_ID")
		
		if strings.Contains(userPoolID, "XXXXXXXXX") || 
		   strings.Contains(clientID, "dummy") ||
		   userPoolID == "" || clientID == "" {
			return true
		}
	}

	return false
}
