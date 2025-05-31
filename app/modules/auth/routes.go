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
			awsConfig.WithClientLogMode(aws.LogRetries | aws.LogRequestWithBody | aws.LogResponseWithBody),
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
	
	// Create service
	service := NewAuthService(repo, cfg)
	
	// Create controller
	controller := NewController(service)
	
	// Create auth group with common prefix and middleware
	authGroup := huma.NewGroup(api, "/auth")
	
	// Add CORS middleware to the group (if needed)
	authGroup.UseMiddleware(middleware.SimpleCORS())
	
	// Public routes (no authentication required)
	publicGroup := huma.NewGroup(authGroup)
	
	// Register public auth routes
	huma.Post(publicGroup, "/signup", controller.SignUp,
		huma.Summary("Sign up a new user"),
		huma.Description("Register a new user account with email verification required"),
		huma.Tags("Authentication"),
		huma.Response(200, "User registered successfully"),
		huma.Response(400, "Bad request - validation errors"),
		huma.Response(409, "User already exists"),
	)
	
	huma.Post(publicGroup, "/verify-email", controller.VerifyEmail,
		huma.Summary("Verify email address"),
		huma.Description("Confirm user email with verification code received via email"),
		huma.Tags("Authentication"),
		huma.Response(200, "Email verified successfully"),
		huma.Response(400, "Invalid verification code"),
	)
	
	huma.Post(publicGroup, "/login", controller.Login,
		huma.Summary("Login user"),
		huma.Description("Authenticate user and receive access/refresh tokens"),
		huma.Tags("Authentication"),
		huma.Response(200, "Login successful"),
		huma.Response(401, "Invalid credentials"),
		huma.Response(403, "Account not active"),
	)
	
	huma.Post(publicGroup, "/refresh", controller.RefreshToken,
		huma.Summary("Refresh access token"),
		huma.Description("Get a new access token using refresh token"),
		huma.Tags("Authentication"),
		huma.Response(200, "Token refreshed successfully"),
		huma.Response(401, "Invalid or expired refresh token"),
	)
	
	huma.Post(publicGroup, "/forgot-password", controller.ForgotPassword,
		huma.Summary("Request password reset"),
		huma.Description("Send password reset code to user's email"),
		huma.Tags("Authentication"),
		huma.Response(200, "Password reset code sent"),
		huma.Response(400, "Invalid request"),
	)
	
	huma.Post(publicGroup, "/reset-password", controller.ResetPassword,
		huma.Summary("Reset password"),
		huma.Description("Reset password using confirmation code from email"),
		huma.Tags("Authentication"),
		huma.Response(200, "Password reset successfully"),
		huma.Response(400, "Invalid confirmation code or password requirements not met"),
	)
	
	// Health check for auth service (public)
	huma.Get(publicGroup, "/health", controller.HealthCheck,
		huma.Summary("Auth service health check"),
		huma.Description("Check if the authentication service is healthy"),
		huma.Tags("Health"),
		huma.Response(200, "Service is healthy"),
	)
	
	// Protected routes (authentication required)
	protectedGroup := huma.NewGroup(authGroup)
	
	// Add authentication middleware to protected routes
	protectedGroup.UseMiddleware(middleware.RequireAuth(cfg.JWT.Secret))
	
	// Register protected auth routes
	huma.Post(protectedGroup, "/change-password", controller.ChangePassword,
		huma.Summary("Change password"),
		huma.Description("Change password for authenticated user"),
		huma.Tags("Authentication"),
		huma.Response(200, "Password changed successfully"),
		huma.Response(400, "Current password incorrect or new password doesn't meet requirements"),
		huma.Response(401, "Authentication required"),
	)
	
	huma.Post(protectedGroup, "/logout", controller.Logout,
		huma.Summary("Logout user"),
		huma.Description("Sign out and invalidate tokens"),
		huma.Tags("Authentication"),
		huma.Response(200, "Logged out successfully"),
		huma.Response(401, "Authentication required"),
	)
	
	huma.Get(protectedGroup, "/profile", controller.GetProfile,
		huma.Summary("Get user profile"),
		huma.Description("Get authenticated user information"),
		huma.Tags("User Profile"),
		huma.Response(200, "User profile retrieved successfully"),
		huma.Response(401, "Authentication required"),
		huma.Response(404, "User not found"),
	)
	
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
	// huma.Get(adminGroup, "/users", adminController.ListUsers,
	//     huma.Summary("List all users"),
	//     huma.Description("Get paginated list of all users (admin only)"),
	//     huma.Tags("Admin", "Users"),
	//     huma.Response(200, "Users listed successfully"),
	//     huma.Response(401, "Authentication required"),
	//     huma.Response(403, "Admin access required"),
	// )
	
	// huma.Delete(adminGroup, "/users/{user-id}", adminController.DeleteUser,
	//     huma.Summary("Delete user"),
	//     huma.Description("Delete a user account (admin only)"),
	//     huma.Tags("Admin", "Users"),
	//     huma.Response(200, "User deleted successfully"),
	//     huma.Response(401, "Authentication required"),
	//     huma.Response(403, "Admin access required"),
	//     huma.Response(404, "User not found"),
	// )
	
	return nil
}
