package auth

import (
	"context"
	"database/sql"
	"fmt"

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

	// Validate Cognito configuration
	if err := config.Cognito.Validate(); err != nil {
		return nil, fmt.Errorf("invalid cognito config: %w", err)
	}

	// Initialize Cognito client
	cognitoClient, err := cognito.NewClient(ctx, config.Cognito)
	if err != nil {
		return nil, fmt.Errorf("failed to create cognito client: %w", err)
	}

	// Initialize repositories
	userRepo := persistence.NewUserRepository(config.DB)
	authRepo := cognito.NewAuthRepository(cognitoClient)

	// Initialize services
	authService := service.NewAuthService(userRepo, authRepo)

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
