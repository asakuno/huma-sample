package auth

import (
	"context"

	"github.com/asakuno/huma-sample/app/middleware"
	"github.com/asakuno/huma-sample/app/shared/errors"
)

// Controller handles HTTP requests for authentication
type Controller struct {
	service Service
}

// NewController creates a new auth controller
func NewController(service Service) *Controller {
	return &Controller{
		service: service,
	}
}

// SignUp handles user registration
func (c *Controller) SignUp(ctx context.Context, input *SignUpRequest) (*SignUpResponse, error) {
	cognitoUserID, err := c.service.SignUp(ctx, input.Body.Email, input.Body.Username, input.Body.Password, input.Body.Name)
	if err != nil {
		return nil, err
	}

	return &SignUpResponse{
		Success: true,
		Message: "User registered successfully. Please check your email for verification code.",
		UserID:  derefString(cognitoUserID),
	}, nil
}

// VerifyEmail handles email verification
func (c *Controller) VerifyEmail(ctx context.Context, input *VerifyEmailRequest) (*VerifyEmailResponse, error) {
	err := c.service.VerifyEmail(ctx, input.Body.Email, input.Body.ConfirmationCode)
	if err != nil {
		return nil, err
	}

	return &VerifyEmailResponse{
		Success: true,
		Message: "Email verified successfully. You can now login.",
	}, nil
}

// Login handles user authentication
func (c *Controller) Login(ctx context.Context, input *LoginRequest) (*LoginResponse, error) {
	user, tokens, err := c.service.Login(ctx, input.Body.Email, input.Body.Password)
	if err != nil {
		return nil, err
	}

	return &LoginResponse{
		User:   *user,
		Tokens: *tokens,
	}, nil
}

// RefreshToken handles token refresh
func (c *Controller) RefreshToken(ctx context.Context, input *RefreshTokenRequest) (*RefreshTokenResponse, error) {
	tokens, err := c.service.RefreshToken(ctx, input.Body.RefreshToken)
	if err != nil {
		return nil, err
	}

	return &RefreshTokenResponse{
		Tokens: *tokens,
	}, nil
}

// ForgotPassword handles forgot password requests
func (c *Controller) ForgotPassword(ctx context.Context, input *ForgotPasswordRequest) (*ForgotPasswordResponse, error) {
	err := c.service.ForgotPassword(ctx, input.Body.Email)
	if err != nil {
		return nil, err
	}

	return &ForgotPasswordResponse{
		Success: true,
		Message: "If the email exists, a password reset code has been sent.",
	}, nil
}

// ResetPassword handles password reset
func (c *Controller) ResetPassword(ctx context.Context, input *ResetPasswordRequest) (*ResetPasswordResponse, error) {
	err := c.service.ResetPassword(ctx, input.Body.Email, input.Body.ConfirmationCode, input.Body.NewPassword)
	if err != nil {
		return nil, err
	}

	return &ResetPasswordResponse{
		Success: true,
		Message: "Password reset successfully. You can now login with your new password.",
	}, nil
}

// ChangePassword handles password change for authenticated users
func (c *Controller) ChangePassword(ctx context.Context, input *ChangePasswordRequest) (*ChangePasswordResponse, error) {
	// Get user from context (injected by auth middleware)
	claims, ok := middleware.GetUserFromContext(ctx)
	if !ok {
		return nil, errors.NewUnauthorizedError("Authentication required")
	}

	// Get access token from context
	token, _ := middleware.GetTokenFromContext(ctx)

	// Use email-based password change
	err := c.service.ChangePasswordByEmail(ctx, claims.Email, token, input.Body.CurrentPassword, input.Body.NewPassword)
	if err != nil {
		return nil, err
	}

	return &ChangePasswordResponse{
		Success: true,
		Message: "Password changed successfully.",
	}, nil
}

// Logout handles user logout
func (c *Controller) Logout(ctx context.Context, input *LogoutRequest) (*LogoutResponse, error) {
	// Get access token from context
	token, ok := middleware.GetTokenFromContext(ctx)
	if !ok {
		return nil, errors.NewUnauthorizedError("Authentication required")
	}

	err := c.service.Logout(ctx, token)
	if err != nil {
		// Logout errors are not critical, just log them
		// In a production system, you'd want to log this error
	}

	return &LogoutResponse{
		Success: true,
		Message: "Logged out successfully.",
	}, nil
}

// GetProfile retrieves the authenticated user's profile
func (c *Controller) GetProfile(ctx context.Context, input *struct{}) (*AuthUser, error) {
	// Get user claims from context
	claims, ok := middleware.GetUserFromContext(ctx)
	if !ok {
		return nil, errors.NewUnauthorizedError("Authentication required")
	}

	// Get user from database using email from token
	user, err := c.service.GetUserByEmail(ctx, claims.Email)
	if err != nil {
		return nil, err
	}

	return user, nil
}

// HealthCheck provides health status for auth service
func (c *Controller) HealthCheck(ctx context.Context, input *struct{}) (*struct {
	Body HealthCheckResponse `json:"body"`
}, error) {
	// You could add actual health checks here
	checks := map[string]HealthCheckDetail{
		"service": {
			Status:  "pass",
			Message: "Auth service is operational",
		},
		"cognito": {
			Status:  "pass",
			Message: "Cognito connection is healthy",
		},
	}

	response := &struct {
		Body HealthCheckResponse `json:"body"`
	}{
		Body: HealthCheckResponse{
			Status:  "ok",
			Service: "auth",
			Checks:  checks,
		},
	}

	return response, nil
}

// Helper function to dereference string pointer safely
func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
