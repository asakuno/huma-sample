package service

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/asakuno/huma-sample/auth/domain/entity"
	"github.com/asakuno/huma-sample/auth/domain/repository"
	"github.com/google/uuid"
)

// AuthService provides domain services for authentication
type AuthService struct {
	userRepo repository.UserRepository
	authRepo repository.AuthRepository
}

// NewAuthService creates a new AuthService
func NewAuthService(userRepo repository.UserRepository, authRepo repository.AuthRepository) *AuthService {
	return &AuthService{
		userRepo: userRepo,
		authRepo: authRepo,
	}
}

// AuthenticateUser authenticates a user and returns user entity and auth token
func (s *AuthService) AuthenticateUser(ctx context.Context, username, password string) (*entity.User, *entity.AuthToken, error) {
	// Authenticate with Cognito
	authReq := &repository.CognitoAuthRequest{
		Username: username,
		Password: password,
	}

	authResp, err := s.authRepo.Authenticate(ctx, authReq)
	if err != nil {
		return nil, nil, fmt.Errorf("authentication failed: %w", err)
	}

	// Get user info from Cognito
	userInfo, err := s.authRepo.GetUserInfo(ctx, authResp.AccessToken)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get user info: %w", err)
	}

	// Find or create user in local database
	user, err := s.findOrCreateUser(ctx, userInfo)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to find or create user: %w", err)
	}

	// Create auth token
	authToken := entity.NewAuthToken(
		authResp.AccessToken,
		authResp.RefreshToken,
		authResp.IDToken,
		authResp.ExpiresIn,
		user.ID,
	)

	return user, authToken, nil
}

// RefreshUserToken refreshes a user's authentication token
func (s *AuthService) RefreshUserToken(ctx context.Context, refreshToken string, userID uuid.UUID) (*entity.AuthToken, error) {
	// Refresh token with Cognito
	authResp, err := s.authRepo.RefreshToken(ctx, refreshToken)
	if err != nil {
		return nil, fmt.Errorf("failed to refresh token: %w", err)
	}

	// Create new auth token
	authToken := entity.NewAuthToken(
		authResp.AccessToken,
		authResp.RefreshToken,
		authResp.IDToken,
		authResp.ExpiresIn,
		userID,
	)

	return authToken, nil
}

// ValidateToken validates an access token and returns user information
func (s *AuthService) ValidateToken(ctx context.Context, accessToken string) (*entity.User, error) {
	// Validate token with Cognito
	tokenClaims, err := s.authRepo.ValidateToken(ctx, accessToken)
	if err != nil {
		return nil, fmt.Errorf("invalid token: %w", err)
	}

	// Check if token is expired
	if time.Now().After(tokenClaims.ExpiresAt) {
		return nil, errors.New("token has expired")
	}

	// Get user from database
	user, err := s.userRepo.GetByID(ctx, tokenClaims.UserID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	// Check if user is active
	if !user.IsActive() {
		return nil, errors.New("user account is not active")
	}

	return user, nil
}

// SignOutUser signs out a user by invalidating their tokens
func (s *AuthService) SignOutUser(ctx context.Context, accessToken string) error {
	err := s.authRepo.SignOut(ctx, accessToken)
	if err != nil {
		return fmt.Errorf("failed to sign out user: %w", err)
	}
	return nil
}

// InitiateForgotPassword initiates the forgot password flow
func (s *AuthService) InitiateForgotPassword(ctx context.Context, username string) error {
	req := &repository.ForgotPasswordRequest{
		Username: username,
	}

	err := s.authRepo.ForgotPassword(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to initiate forgot password: %w", err)
	}

	return nil
}

// ConfirmForgotPassword confirms the forgot password with verification code
func (s *AuthService) ConfirmForgotPassword(ctx context.Context, username, code, newPassword string) error {
	req := &repository.ConfirmForgotPasswordRequest{
		Username:         username,
		ConfirmationCode: code,
		NewPassword:      newPassword,
	}

	err := s.authRepo.ConfirmForgotPassword(ctx, req)
	if err != nil {
		return fmt.Errorf("failed to confirm forgot password: %w", err)
	}

	return nil
}

// CreateUser creates a new user (admin operation)
func (s *AuthService) CreateUser(ctx context.Context, username, email, firstName, lastName string) (*entity.User, error) {
	// Check if user already exists in local database
	exists, err := s.userRepo.ExistsByEmail(ctx, email)
	if err != nil {
		return nil, fmt.Errorf("failed to check user existence: %w", err)
	}
	if exists {
		return nil, errors.New("user already exists")
	}

	// Create user in Cognito with temporary password
	tempPassword := generateTemporaryPassword()
	err = s.authRepo.CreateUser(ctx, username, email, tempPassword)
	if err != nil {
		return nil, fmt.Errorf("failed to create user in Cognito: %w", err)
	}

	// Create user in local database
	user := entity.NewUser("", username, email, firstName, lastName) // Cognito ID will be set later
	err = s.userRepo.Create(ctx, user)
	if err != nil {
		// Rollback: delete user from Cognito
		_ = s.authRepo.DeleteUser(ctx, username)
		return nil, fmt.Errorf("failed to create user in database: %w", err)
	}

	return user, nil
}

// UpdateUserProfile updates a user's profile information
func (s *AuthService) UpdateUserProfile(ctx context.Context, userID uuid.UUID, firstName, lastName string) (*entity.User, error) {
	user, err := s.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("user not found: %w", err)
	}

	user.UpdateProfile(firstName, lastName)

	err = s.userRepo.Update(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("failed to update user: %w", err)
	}

	return user, nil
}

// findOrCreateUser finds an existing user or creates a new one based on Cognito user info
func (s *AuthService) findOrCreateUser(ctx context.Context, userInfo *repository.CognitoUserInfo) (*entity.User, error) {
	// Try to find user by Cognito ID
	user, err := s.userRepo.GetByCognitoID(ctx, userInfo.Sub)
	if err == nil {
		// User found, activate if not already active
		if !user.IsActive() {
			user.Activate()
			err = s.userRepo.Update(ctx, user)
			if err != nil {
				return nil, fmt.Errorf("failed to activate user: %w", err)
			}
		}
		return user, nil
	}

	// Try to find user by email
	user, err = s.userRepo.GetByEmail(ctx, userInfo.Email)
	if err == nil {
		// User found but missing Cognito ID, update it
		user.CognitoID = userInfo.Sub
		user.Activate()
		err = s.userRepo.Update(ctx, user)
		if err != nil {
			return nil, fmt.Errorf("failed to update user with Cognito ID: %w", err)
		}
		return user, nil
	}

	// User doesn't exist, create new one
	user = entity.NewUser(
		userInfo.Sub,
		userInfo.Username,
		userInfo.Email,
		userInfo.FirstName,
		userInfo.LastName,
	)
	user.Activate() // Activate immediately since they authenticated with Cognito

	err = s.userRepo.Create(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("failed to create new user: %w", err)
	}

	return user, nil
}

// generateTemporaryPassword generates a temporary password for new users
func generateTemporaryPassword() string {
	// In a real implementation, this should generate a secure random password
	// For now, using a simple pattern
	return "TempPass123!"
}
