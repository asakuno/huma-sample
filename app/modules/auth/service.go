package auth

import (
	"context"
	"errors"
	"time"

	"github.com/asakuno/huma-sample/app/config"
	"github.com/asakuno/huma-sample/app/modules/users"
	"github.com/asakuno/huma-sample/app/shared/utils"
)

// Service interface defines the methods for auth service
type Service interface {
	SignUp(ctx context.Context, email, username, password, name string) (*string, error)
	VerifyEmail(ctx context.Context, email, confirmationCode string) error
	Login(ctx context.Context, email, password string) (*AuthUser, *TokenPair, error)
	RefreshToken(ctx context.Context, refreshToken string) (*TokenPair, error)
	ForgotPassword(ctx context.Context, email string) error
	ResetPassword(ctx context.Context, email, confirmationCode, newPassword string) error
	ChangePassword(ctx context.Context, userID uint, currentPassword, newPassword string) error
	Logout(ctx context.Context, accessToken string) error
	GetUserFromToken(ctx context.Context, accessToken string) (*AuthUser, error)
}

// AuthService implements the Service interface
type AuthService struct {
	repo   Repository
	config *config.Config
}

// NewAuthService creates a new auth service
func NewAuthService(repo Repository, config *config.Config) Service {
	return &AuthService{
		repo:   repo,
		config: config,
	}
}

// SignUp registers a new user
func (s *AuthService) SignUp(ctx context.Context, email, username, password, name string) (*string, error) {
	// Validate password strength
	if !utils.ValidatePasswordStrength(password) {
		return nil, errors.New("password does not meet strength requirements")
	}

	// Check if user already exists in database
	existingUser, _ := s.repo.GetUserByEmail(email)
	if existingUser != nil {
		return nil, errors.New("user with this email already exists")
	}

	// Sign up with Cognito
	cognitoUserID, err := s.repo.SignUp(ctx, email, username, password)
	if err != nil {
		return nil, err
	}

	// Create user in database
	hashedPassword, err := utils.HashPassword(password)
	if err != nil {
		return nil, err
	}

	user := &users.User{
		Email:    email,
		Name:     name,
		Password: hashedPassword,
		IsActive: false, // Will be activated after email verification
	}

	if err := s.repo.CreateUser(user); err != nil {
		// TODO: Consider rollback of Cognito user if database creation fails
		return nil, err
	}

	return cognitoUserID, nil
}

// VerifyEmail confirms a user's email address
func (s *AuthService) VerifyEmail(ctx context.Context, email, confirmationCode string) error {
	// Get user from database
	user, err := s.repo.GetUserByEmail(email)
	if err != nil {
		return errors.New("user not found")
	}

	// Confirm with Cognito
	if err := s.repo.ConfirmSignUp(ctx, user.Name, confirmationCode); err != nil {
		return err
	}

	// Activate user in database
	user.IsActive = true
	if err := s.repo.UpdateUser(user); err != nil {
		return err
	}

	return nil
}

// Login authenticates a user and returns tokens
func (s *AuthService) Login(ctx context.Context, email, password string) (*AuthUser, *TokenPair, error) {
	// Get user from database
	user, err := s.repo.GetUserByEmail(email)
	if err != nil {
		return nil, nil, errors.New("invalid credentials")
	}

	// Check if user is active
	if !user.IsActive {
		return nil, nil, errors.New("user account is not active")
	}

	// Authenticate with Cognito
	cognitoTokens, err := s.repo.SignIn(ctx, user.Name, password)
	if err != nil {
		return nil, nil, errors.New("invalid credentials")
	}

	// Update last login
	if err := s.repo.UpdateLastLogin(user.ID); err != nil {
		// Non-critical error, log but don't fail the login
	}

	// Create auth user response
	authUser := &AuthUser{
		ID:            user.ID,
		Email:         user.Email,
		Username:      user.Name,
		EmailVerified: true, // Since they can login, email must be verified
		IsActive:      user.IsActive,
		CreatedAt:     user.CreatedAt,
		UpdatedAt:     user.UpdatedAt,
	}

	// Create token pair
	tokenPair := &TokenPair{
		AccessToken:  cognitoTokens.AccessToken,
		RefreshToken: cognitoTokens.RefreshToken,
		TokenType:    "Bearer",
		ExpiresIn:    int(cognitoTokens.ExpiresIn),
	}

	return authUser, tokenPair, nil
}

// RefreshToken refreshes the access token
func (s *AuthService) RefreshToken(ctx context.Context, refreshToken string) (*TokenPair, error) {
	cognitoTokens, err := s.repo.RefreshToken(ctx, refreshToken)
	if err != nil {
		return nil, err
	}

	return &TokenPair{
		AccessToken: cognitoTokens.AccessToken,
		TokenType:   "Bearer",
		ExpiresIn:   int(cognitoTokens.ExpiresIn),
	}, nil
}

// ForgotPassword initiates the password reset process
func (s *AuthService) ForgotPassword(ctx context.Context, email string) error {
	// Get user from database to get username
	user, err := s.repo.GetUserByEmail(email)
	if err != nil {
		// Don't reveal if user exists or not
		return nil
	}

	// Initiate forgot password with Cognito
	return s.repo.ForgotPassword(ctx, user.Name)
}

// ResetPassword resets the user's password
func (s *AuthService) ResetPassword(ctx context.Context, email, confirmationCode, newPassword string) error {
	// Validate password strength
	if !utils.ValidatePasswordStrength(newPassword) {
		return errors.New("password does not meet strength requirements")
	}

	// Get user from database to get username
	user, err := s.repo.GetUserByEmail(email)
	if err != nil {
		return errors.New("invalid request")
	}

	// Confirm forgot password with Cognito
	if err := s.repo.ConfirmForgotPassword(ctx, user.Name, confirmationCode, newPassword); err != nil {
		return err
	}

	// Update password hash in database
	hashedPassword, err := utils.HashPassword(newPassword)
	if err != nil {
		return err
	}

	user.Password = hashedPassword
	return s.repo.UpdateUser(user)
}

// ChangePassword changes the user's password (for authenticated users)
func (s *AuthService) ChangePassword(ctx context.Context, userID uint, currentPassword, newPassword string) error {
	// Validate password strength
	if !utils.ValidatePasswordStrength(newPassword) {
		return errors.New("password does not meet strength requirements")
	}

	// Get user from database
	user, err := s.repo.GetUserByID(userID)
	if err != nil {
		return errors.New("user not found")
	}

	// Verify current password
	if !utils.CheckPasswordHash(currentPassword, user.Password) {
		return errors.New("current password is incorrect")
	}

	// TODO: Get access token from context and change password in Cognito
	// For now, we'll just update the database

	// Update password hash in database
	hashedPassword, err := utils.HashPassword(newPassword)
	if err != nil {
		return err
	}

	user.Password = hashedPassword
	return s.repo.UpdateUser(user)
}

// Logout signs out a user
func (s *AuthService) Logout(ctx context.Context, accessToken string) error {
	return s.repo.SignOut(ctx, accessToken)
}

// GetUserFromToken retrieves user information from an access token
func (s *AuthService) GetUserFromToken(ctx context.Context, accessToken string) (*AuthUser, error) {
	// Get user info from Cognito
	cognitoUser, err := s.repo.GetUser(ctx, accessToken)
	if err != nil {
		return nil, err
	}

	// Extract email from attributes
	var email string
	for _, attr := range cognitoUser.UserAttributes {
		if *attr.Name == "email" {
			email = *attr.Value
			break
		}
	}

	// Get user from database
	user, err := s.repo.GetUserByEmail(email)
	if err != nil {
		return nil, err
	}

	return &AuthUser{
		ID:            user.ID,
		Email:         user.Email,
		Username:      user.Name,
		EmailVerified: true,
		IsActive:      user.IsActive,
		CreatedAt:     user.CreatedAt,
		UpdatedAt:     user.UpdatedAt,
		LastLoginAt:   (*time.Time)(nil), // Could be fetched from DB if needed
	}, nil
}
