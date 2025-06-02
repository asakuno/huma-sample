package auth

import (
	"context"

	"github.com/asakuno/huma-sample/app/config"
	"github.com/asakuno/huma-sample/app/middleware"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsConfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/danielgtaylor/huma/v2"
	"gorm.io/gorm"
)

// RegisterRoutes registers all auth routes using Huma Group functionality
func RegisterRoutes(api huma.API, db *gorm.DB) error {
	// Load app configuration
	cfg := config.GetConfig()

	// Create AWS configuration
	ctx := context.Background()

	var awsCfg aws.Config
	var err error

	if cfg.Cognito.UseLocal {
		// For local development, configure to use cognito-local
		awsCfg, err = awsConfig.LoadDefaultConfig(ctx,
			awsConfig.WithRegion(cfg.AWS.Region),
			awsConfig.WithEndpointResolverWithOptions(aws.EndpointResolverWithOptionsFunc(
				func(service, region string, options ...interface{}) (aws.Endpoint, error) {
					if service == cognitoidentityprovider.ServiceID {
						return aws.Endpoint{
							URL:           cfg.Cognito.LocalEndpoint,
							SigningRegion: cfg.AWS.Region,
						}, nil
					}
					// Use default endpoint for other services
					return aws.Endpoint{}, &aws.EndpointNotFoundError{}
				})),
			// Disable SSL for local development
			awsConfig.WithClientLogMode(aws.LogRetries|aws.LogRequestWithBody|aws.LogResponseWithBody),
		)
	} else {
		// For production, use standard AWS configuration
		awsCfg, err = awsConfig.LoadDefaultConfig(ctx,
			awsConfig.WithRegion(cfg.AWS.Region),
		)
	}

	if err != nil {
		return err
	}

	// Create Cognito client
	cognitoClient := cognitoidentityprovider.NewFromConfig(awsCfg)

	// Create repository
	repo := NewAuthRepository(
		db,
		cognitoClient,
		cfg.Cognito.UserPoolID,
		cfg.Cognito.AppClientID,
		cfg.Cognito.AppClientSecret,
	)

	// Create password rules
	passwordRules := DefaultPasswordRules()

	// Create service
	service := NewAuthService(repo, passwordRules)

	// Create controller
	controller := NewController(service)

	// Create auth group with common prefix and middleware
	authGroup := huma.NewGroup(api, "/auth")

	// Add CORS middleware to the group (if needed)
	authGroup.UseMiddleware(middleware.SimpleCORS())

	// Public routes (no authentication required)
	publicGroup := huma.NewGroup(authGroup)

	// Register public auth routes with simplified Huma v2 API
	huma.Post(publicGroup, "/signup", controller.SignUp)
	huma.Post(publicGroup, "/verify-email", controller.VerifyEmail)
	huma.Post(publicGroup, "/login", controller.Login)
	huma.Post(publicGroup, "/refresh", controller.RefreshToken)
	huma.Post(publicGroup, "/forgot-password", controller.ForgotPassword)
	huma.Post(publicGroup, "/reset-password", controller.ResetPassword)
	huma.Get(publicGroup, "/health", controller.HealthCheck)

	// Protected routes (authentication required)
	protectedGroup := huma.NewGroup(authGroup)

	// Add authentication middleware to protected routes
	protectedGroup.UseMiddleware(middleware.RequireAuth(cfg.JWT.Secret))

	// Register protected auth routes
	huma.Post(protectedGroup, "/change-password", controller.ChangePassword)
	huma.Post(protectedGroup, "/logout", controller.Logout)
	huma.Get(protectedGroup, "/profile", controller.GetProfile)

	return nil
}

// RegisterAdminRoutes registers admin-only routes (example of role-based routing)
func RegisterAdminRoutes(api huma.API, db *gorm.DB) error {
	cfg := config.GetConfig()

	// Create admin group with authentication and role requirements
	adminGroup := huma.NewGroup(api, "/admin/auth")

	// Add authentication middleware
	adminGroup.UseMiddleware(middleware.RequireAuth(cfg.JWT.Secret))

	// Add admin role requirement
	adminGroup.UseMiddleware(middleware.RequireRole("admin"))

	// Example admin routes (you would implement these controllers)
	// huma.Get(adminGroup, "/users", adminController.ListUsers)
	// huma.Delete(adminGroup, "/users/{user-id}", adminController.DeleteUser)

	return nil
}
