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
	cognitoUserID, err := c.service.SignUp(ctx, input.Email, input.Username, input.Password, input.Name)
	if err != nil {
		// Let Huma handle the error properly - no need for manual conversion
		return nil, err
	}

	resp := &SignUpResponse{}
	resp.Body.Success = true
	resp.Body.Message = "User registered successfully. Please check your email for verification code."
	if cognitoUserID != nil {
		resp.Body.UserID = *cognitoUserID
	}

	return resp, nil
}

// VerifyEmail handles email verification
func (c *Controller) VerifyEmail(ctx context.Context, input *VerifyEmailRequest) (*VerifyEmailResponse, error) {
	err := c.service.VerifyEmail(ctx, input.Email, input.ConfirmationCode)
	if err != nil {
		return nil, err
	}

	resp := &VerifyEmailResponse{}
	resp.Body.Success = true
	resp.Body.Message = "Email verified successfully. You can now login."

	return resp, nil
}

// Login handles user authentication
func (c *Controller) Login(ctx context.Context, input *LoginRequest) (*LoginResponse, error) {
	user, tokens, err := c.service.Login(ctx, input.Email, input.Password)
	if err != nil {
		return nil, err
	}

	resp := &LoginResponse{}
	resp.Body.User = *user
	resp.Body.Tokens = *tokens

	return resp, nil
}

// RefreshToken handles token refresh
func (c *Controller) RefreshToken(ctx context.Context, input *RefreshTokenRequest) (*RefreshTokenResponse, error) {
	tokens, err := c.service.RefreshToken(ctx, input.RefreshToken)
	if err != nil {
		return nil, err
	}

	resp := &RefreshTokenResponse{}
	resp.Body.Tokens = *tokens

	return resp, nil
}

// ForgotPassword handles forgot password requests
func (c *Controller) ForgotPassword(ctx context.Context, input *ForgotPasswordRequest) (*ForgotPasswordResponse, error) {
	err := c.service.ForgotPassword(ctx, input.Email)
	if err != nil {
		return nil, err
	}

	resp := &ForgotPasswordResponse{}
	resp.Body.Success = true
	resp.Body.Message = "If the email exists, a password reset code has been sent."

	return resp, nil
}

// ResetPassword handles password reset
func (c *Controller) ResetPassword(ctx context.Context, input *ResetPasswordRequest) (*ResetPasswordResponse, error) {
	err := c.service.ResetPassword(ctx, input.Email, input.ConfirmationCode, input.NewPassword)
	if err != nil {
		return nil, err
	}

	resp := &ResetPasswordResponse{}
	resp.Body.Success = true
	resp.Body.Message = "Password reset successfully. You can now login with your new password."

	return resp, nil
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

	err := c.service.ChangePassword(ctx, claims.UserID, token, input.CurrentPassword, input.NewPassword)
	if err != nil {
		return nil, err
	}

	resp := &ChangePasswordResponse{}
	resp.Body.Success = true
	resp.Body.Message = "Password changed successfully."

	return resp, nil
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

	resp := &LogoutResponse{}
	resp.Body.Success = true
	resp.Body.Message = "Logged out successfully."

	return resp, nil
}

// GetProfile retrieves the authenticated user's profile
type GetProfileOutput struct {
	Body AuthUser `json:"user" doc:"User profile information"`
}

func (c *Controller) GetProfile(ctx context.Context, input *struct{}) (*GetProfileOutput, error) {
	// Get access token from context
	token, ok := middleware.GetTokenFromContext(ctx)
	if !ok {
		return nil, errors.NewUnauthorizedError("Authentication required")
	}

	user, err := c.service.GetUserFromToken(ctx, token)
	if err != nil {
		return nil, err
	}

	resp := &GetProfileOutput{}
	resp.Body = *user

	return resp, nil
}

// Health check for auth service
type AuthHealthOutput struct {
	Body struct {
		Status  string `json:"status" example:"ok" doc:"Service status"`
		Service string `json:"service" example:"auth" doc:"Service name"`
		Cognito string `json:"cognito" example:"connected" doc:"Cognito connection status"`
	}
}

func (c *Controller) HealthCheck(ctx context.Context, input *struct{}) (*AuthHealthOutput, error) {
	resp := &AuthHealthOutput{}
	resp.Body.Status = "ok"
	resp.Body.Service = "auth"
	
	// You could check Cognito connection here in the future
	resp.Body.Cognito = "connected"

	return resp, nil
}
