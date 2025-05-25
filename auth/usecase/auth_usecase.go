package usecase

import (
	"context"
	"errors"
	"fmt"

	"github.com/asakuno/huma-sample/auth/domain/entity"
	"github.com/asakuno/huma-sample/auth/domain/service"
	"github.com/asakuno/huma-sample/auth/usecase/dto"
	"github.com/google/uuid"
)

// AuthUsecase defines the interface for authentication use cases
type AuthUsecase interface {
	// Login authenticates a user and returns login response
	Login(ctx context.Context, req *dto.LoginRequest) (*dto.LoginResponse, error)

	// RefreshToken refreshes an access token
	RefreshToken(ctx context.Context, req *dto.RefreshTokenRequest, userID uuid.UUID) (*dto.RefreshTokenResponse, error)

	// GetProfile gets the current user's profile
	GetProfile(ctx context.Context, userID uuid.UUID) (*dto.UserResponse, error)

	// UpdateProfile updates the current user's profile
	UpdateProfile(ctx context.Context, userID uuid.UUID, req *dto.UpdateProfileRequest) (*dto.UserResponse, error)

	// Logout signs out a user
	Logout(ctx context.Context, accessToken string) error

	// ForgotPassword initiates the forgot password flow
	ForgotPassword(ctx context.Context, req *dto.ForgotPasswordRequest) error

	// ConfirmForgotPassword confirms the forgot password with verification code
	ConfirmForgotPassword(ctx context.Context, req *dto.ConfirmForgotPasswordRequest) error

	// CreateUser creates a new user (admin only)
	CreateUser(ctx context.Context, req *dto.CreateUserRequest) (*dto.UserResponse, error)

	// ValidateToken validates an access token and returns user info
	ValidateToken(ctx context.Context, accessToken string) (*entity.User, error)
}

// authUsecaseImpl implements AuthUsecase
type authUsecaseImpl struct {
	authService *service.AuthService
}

// NewAuthUsecase creates a new AuthUsecase
func NewAuthUsecase(authService *service.AuthService) AuthUsecase {
	return &authUsecaseImpl{
		authService: authService,
	}
}

// Login authenticates a user and returns login response
func (u *authUsecaseImpl) Login(ctx context.Context, req *dto.LoginRequest) (*dto.LoginResponse, error) {
	if req == nil {
		return nil, errors.New("login request is required")
	}

	if req.Username == "" {
		return nil, errors.New("username is required")
	}

	if req.Password == "" {
		return nil, errors.New("password is required")
	}

	user, token, err := u.authService.AuthenticateUser(ctx, req.Username, req.Password)
	if err != nil {
		return nil, fmt.Errorf("login failed: %w", err)
	}

	return dto.NewLoginResponse(user, token), nil
}

// RefreshToken refreshes an access token
func (u *authUsecaseImpl) RefreshToken(ctx context.Context, req *dto.RefreshTokenRequest, userID uuid.UUID) (*dto.RefreshTokenResponse, error) {
	if req == nil {
		return nil, errors.New("refresh token request is required")
	}

	if req.RefreshToken == "" {
		return nil, errors.New("refresh token is required")
	}

	if userID == uuid.Nil {
		return nil, errors.New("user ID is required")
	}

	token, err := u.authService.RefreshUserToken(ctx, req.RefreshToken, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}

	return dto.NewRefreshTokenResponse(token), nil
}

// GetProfile gets the current user's profile
func (u *authUsecaseImpl) GetProfile(ctx context.Context, userID uuid.UUID) (*dto.UserResponse, error) {
	if userID == uuid.Nil {
		return nil, errors.New("user ID is required")
	}

	// Note: In a real implementation, you might want to get the user directly from the repository
	// For now, we'll validate through a dummy token (this is just for demonstration)
	// In practice, the user would be retrieved directly from the database
	user, err := u.authService.ValidateToken(ctx, "dummy_token_for_profile_access")
	if err != nil {
		// Fallback: try to get user directly (this would be the normal flow)
		// For now, return an error as we need proper repository access
		return nil, fmt.Errorf("failed to get user profile: %w", err)
	}

	return dto.NewUserResponse(user), nil
}

// UpdateProfile updates the current user's profile
func (u *authUsecaseImpl) UpdateProfile(ctx context.Context, userID uuid.UUID, req *dto.UpdateProfileRequest) (*dto.UserResponse, error) {
	if userID == uuid.Nil {
		return nil, errors.New("user ID is required")
	}

	if req == nil {
		return nil, errors.New("update profile request is required")
	}

	if req.FirstName == "" {
		return nil, errors.New("first name is required")
	}

	if req.LastName == "" {
		return nil, errors.New("last name is required")
	}

	user, err := u.authService.UpdateUserProfile(ctx, userID, req.FirstName, req.LastName)
	if err != nil {
		return nil, fmt.Errorf("failed to update profile: %w", err)
	}

	return dto.NewUserResponse(user), nil
}

// Logout signs out a user
func (u *authUsecaseImpl) Logout(ctx context.Context, accessToken string) error {
	if accessToken == "" {
		return errors.New("access token is required")
	}

	err := u.authService.SignOutUser(ctx, accessToken)
	if err != nil {
		return fmt.Errorf("failed to logout: %w", err)
	}

	return nil
}

// ForgotPassword initiates the forgot password flow
func (u *authUsecaseImpl) ForgotPassword(ctx context.Context, req *dto.ForgotPasswordRequest) error {
	if req == nil {
		return errors.New("forgot password request is required")
	}

	if req.Username == "" {
		return errors.New("username is required")
	}

	err := u.authService.InitiateForgotPassword(ctx, req.Username)
	if err != nil {
		return fmt.Errorf("failed to initiate forgot password: %w", err)
	}

	return nil
}

// ConfirmForgotPassword confirms the forgot password with verification code
func (u *authUsecaseImpl) ConfirmForgotPassword(ctx context.Context, req *dto.ConfirmForgotPasswordRequest) error {
	if req == nil {
		return errors.New("confirm forgot password request is required")
	}

	if req.Username == "" {
		return errors.New("username is required")
	}

	if req.ConfirmationCode == "" {
		return errors.New("confirmation code is required")
	}

	if req.NewPassword == "" {
		return errors.New("new password is required")
	}

	err := u.authService.ConfirmForgotPassword(ctx, req.Username, req.ConfirmationCode, req.NewPassword)
	if err != nil {
		return fmt.Errorf("failed to confirm forgot password: %w", err)
	}

	return nil
}

// CreateUser creates a new user (admin only)
func (u *authUsecaseImpl) CreateUser(ctx context.Context, req *dto.CreateUserRequest) (*dto.UserResponse, error) {
	if req == nil {
		return nil, errors.New("create user request is required")
	}

	if req.Username == "" {
		return nil, errors.New("username is required")
	}

	if req.Email == "" {
		return nil, errors.New("email is required")
	}

	if req.FirstName == "" {
		return nil, errors.New("first name is required")
	}

	if req.LastName == "" {
		return nil, errors.New("last name is required")
	}

	user, err := u.authService.CreateUser(ctx, req.Username, req.Email, req.FirstName, req.LastName)
	if err != nil {
		return nil, fmt.Errorf("failed to create user: %w", err)
	}

	return dto.NewUserResponse(user), nil
}

// ValidateToken validates an access token and returns user info
func (u *authUsecaseImpl) ValidateToken(ctx context.Context, accessToken string) (*entity.User, error) {
	if accessToken == "" {
		return nil, errors.New("access token is required")
	}

	user, err := u.authService.ValidateToken(ctx, accessToken)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	return user, nil
}
