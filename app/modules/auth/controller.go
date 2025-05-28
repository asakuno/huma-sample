package auth

import (
	"context"
	"net/http"

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
	cognitoUserID, err := c.service.SignUp(ctx, input.Email, input.Username, input.Password, input.Name)
	if err != nil {
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
		return nil, huma.Error400BadRequest(err.Error())
	}

	resp := &ResetPasswordResponse{}
	resp.Body.Success = true
	resp.Body.Message = "Password reset successfully. You can now login with your new password."

	return resp, nil
}

// ChangePassword handles password change for authenticated users
func (c *Controller) ChangePassword(ctx context.Context, input *ChangePasswordRequest) (*ChangePasswordResponse, error) {
	// TODO: Get user ID from JWT token in context
	// For now, we'll return an error
	return nil, huma.Error501NotImplemented("Change password requires authentication middleware")
}

// Logout handles user logout
func (c *Controller) Logout(ctx context.Context, input *LogoutRequest) (*LogoutResponse, error) {
	// TODO: Get access token from context
	// For now, we'll just return success
	resp := &LogoutResponse{}
	resp.Body.Success = true
	resp.Body.Message = "Logged out successfully."

	return resp, nil
}

// GetProfile retrieves the authenticated user's profile
func (c *Controller) GetProfile(ctx context.Context, input *struct{}) (*struct {
	Body AuthUser
}, error) {
	// TODO: Get access token from context and retrieve user info
	return nil, huma.Error501NotImplemented("Get profile requires authentication middleware")
}
