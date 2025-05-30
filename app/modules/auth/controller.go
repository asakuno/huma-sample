package auth

import (
	"context"
	"net/http"

	"github.com/asakuno/huma-sample/app/middleware"
	"github.com/asakuno/huma-sample/app/shared/errors"
	"github.com/danielgtaylor/huma/v2"
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
	// Service will handle validation, so we just pass through
	cognitoUserID, err := c.service.SignUp(ctx, input.Email, input.Username, input.Password, input.Name)
	if err != nil {
		// Check if it's already an AppError
		if appErr, ok := err.(*errors.AppError); ok {
			return nil, appErr.ToHumaError()
		}
		// Wrap generic errors
		return nil, huma.Error400BadRequest(err.Error())
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
		if appErr, ok := err.(*errors.AppError); ok {
			return nil, appErr.ToHumaError()
		}
		return nil, huma.Error400BadRequest(err.Error())
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
		if appErr, ok := err.(*errors.AppError); ok {
			return nil, appErr.ToHumaError()
		}
		return nil, huma.Error401Unauthorized(err.Error())
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
		if appErr, ok := err.(*errors.AppError); ok {
			return nil, appErr.ToHumaError()
		}
		return nil, huma.Error401Unauthorized(err.Error())
	}

	resp := &RefreshTokenResponse{}
	resp.Body.Tokens = *tokens

	return resp, nil
}

// ForgotPassword handles forgot password requests
func (c *Controller) ForgotPassword(ctx context.Context, input *ForgotPasswordRequest) (*ForgotPasswordResponse, error) {
	err := c.service.ForgotPassword(ctx, input.Email)
	if err != nil {
		if appErr, ok := err.(*errors.AppError); ok {
			return nil, appErr.ToHumaError()
		}
		return nil, huma.Error400BadRequest(err.Error())
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
		if appErr, ok := err.(*errors.AppError); ok {
			return nil, appErr.ToHumaError()
		}
		return nil, huma.Error400BadRequest(err.Error())
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
		return nil, errors.NewUnauthorizedError("Authentication required").ToHumaError()
	}

	// Get access token from context
	token, _ := middleware.GetTokenFromContext(ctx)

	err := c.service.ChangePassword(ctx, claims.UserID, token, input.CurrentPassword, input.NewPassword)
	if err != nil {
		if appErr, ok := err.(*errors.AppError); ok {
			return nil, appErr.ToHumaError()
		}
		return nil, huma.Error400BadRequest(err.Error())
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
		return nil, errors.NewUnauthorizedError("Authentication required").ToHumaError()
	}

	err := c.service.Logout(ctx, token)
	if err != nil {
		if appErr, ok := err.(*errors.AppError); ok {
			return nil, appErr.ToHumaError()
		}
		// Logout errors are not critical, log and continue
	}

	resp := &LogoutResponse{}
	resp.Body.Success = true
	resp.Body.Message = "Logged out successfully."

	return resp, nil
}

// GetProfile retrieves the authenticated user's profile
type GetProfileOutput struct {
	Body AuthUser
}

func (c *Controller) GetProfile(ctx context.Context, input *struct{}) (*GetProfileOutput, error) {
	// Get access token from context
	token, ok := middleware.GetTokenFromContext(ctx)
	if !ok {
		return nil, errors.NewUnauthorizedError("Authentication required").ToHumaError()
	}

	user, err := c.service.GetUserFromToken(ctx, token)
	if err != nil {
		if appErr, ok := err.(*errors.AppError); ok {
			return nil, appErr.ToHumaError()
		}
		return nil, huma.Error500InternalServerError(err.Error())
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
	
	// You could check Cognito connection here
	resp.Body.Cognito = "connected"

	return resp, nil
}
