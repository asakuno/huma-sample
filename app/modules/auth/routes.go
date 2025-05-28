package auth

import (
	"github.com/danielgtaylor/huma/v2"
	"gorm.io/gorm"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/aws"
	"context"
	
	appConfig "github.com/asakuno/huma-sample/app/config"
)

// RegisterRoutes registers all auth routes
func RegisterRoutes(api huma.API, db *gorm.DB) error {
	// Load app configuration
	cfg := appConfig.GetConfig()
	
	// Create AWS configuration
	ctx := context.Background()
	
	var awsCfg aws.Config
	var err error
	
	if cfg.Cognito.UseLocal {
		// For local development, configure to use cognito-local
		awsCfg, err = config.LoadDefaultConfig(ctx,
			config.WithRegion(cfg.AWS.Region),
			config.WithEndpointResolverWithOptions(aws.EndpointResolverWithOptionsFunc(
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
			config.WithClientLogMode(aws.LogRetries | aws.LogRequestWithBody | aws.LogResponseWithBody),
		)
	} else {
		// For production, use standard AWS configuration
		awsCfg, err = config.LoadDefaultConfig(ctx,
			config.WithRegion(cfg.AWS.Region),
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
	
	// Register routes
	huma.Post(api, "/auth/signup", controller.SignUp,
		huma.Summary("Sign up a new user"),
		huma.Description("Register a new user account"),
		huma.Response(200),
		huma.Response(400),
	)
	
	huma.Post(api, "/auth/verify-email", controller.VerifyEmail,
		huma.Summary("Verify email address"),
		huma.Description("Confirm user email with verification code"),
		huma.Response(200),
		huma.Response(400),
	)
	
	huma.Post(api, "/auth/login", controller.Login,
		huma.Summary("Login user"),
		huma.Description("Authenticate user and receive tokens"),
		huma.Response(200),
		huma.Response(401),
	)
	
	huma.Post(api, "/auth/refresh", controller.RefreshToken,
		huma.Summary("Refresh access token"),
		huma.Description("Get a new access token using refresh token"),
		huma.Response(200),
		huma.Response(401),
	)
	
	huma.Post(api, "/auth/forgot-password", controller.ForgotPassword,
		huma.Summary("Forgot password"),
		huma.Description("Request password reset code"),
		huma.Response(200),
		huma.Response(400),
	)
	
	huma.Post(api, "/auth/reset-password", controller.ResetPassword,
		huma.Summary("Reset password"),
		huma.Description("Reset password with confirmation code"),
		huma.Response(200),
		huma.Response(400),
	)
	
	huma.Post(api, "/auth/change-password", controller.ChangePassword,
		huma.Summary("Change password"),
		huma.Description("Change password for authenticated user"),
		huma.Response(200),
		huma.Response(400),
		huma.Response(401),
	)
	
	huma.Post(api, "/auth/logout", controller.Logout,
		huma.Summary("Logout user"),
		huma.Description("Sign out and invalidate tokens"),
		huma.Response(200),
	)
	
	huma.Get(api, "/auth/profile", controller.GetProfile,
		huma.Summary("Get user profile"),
		huma.Description("Get authenticated user information"),
		huma.Response(200),
		huma.Response(401),
	)
	
	return nil
}
