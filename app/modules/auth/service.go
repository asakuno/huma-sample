package auth

import (
	"context"
	"time"

	"github.com/asakuno/huma-sample/app/modules/users"
	"github.com/asakuno/huma-sample/app/shared/errors"
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
	ChangePassword(ctx context.Context, userID uint, accessToken, currentPassword, newPassword string) error
	Logout(ctx context.Context, accessToken string) error
	GetUserFromToken(ctx context.Context, accessToken string) (*AuthUser, error)
}

// PasswordRules defines password validation rules
type PasswordRules struct {
	MinLength        int
	MaxLength        int
	RequireUppercase bool
	RequireLowercase bool
	RequireNumbers   bool
	RequireSymbols   bool
}

// DefaultPasswordRules returns the default password rules
func DefaultPasswordRules() PasswordRules {
	return PasswordRules{
		MinLength:        8,
		MaxLength:        128,
		RequireUppercase: true,
		RequireLowercase: true,
		RequireNumbers:   true,
		RequireSymbols:   true,
	}
}

// AuthService implements the Service interface
type AuthService struct {
	repo          Repository
	passwordRules PasswordRules
}

// NewAuthService creates a new auth service with proper dependency injection
func NewAuthService(repo Repository, passwordRules PasswordRules) Service {
	return &AuthService{
		repo:          repo,
		passwordRules: passwordRules,
	}
}

// SignUp registers a new user
func (s *AuthService) SignUp(ctx context.Context, email, username, password, name string) (*string, error) {
	// Validate password strength
	if validationErrors := s.validatePassword(password); len(validationErrors) > 0 {
		return nil, errors.NewPasswordTooWeakError()
	}

	// Check if user already exists in database
	existingUser, _ := s.repo.GetUserByEmail(email)
	if existingUser != nil {
		return nil, errors.NewUserAlreadyExistsError(email)
	}

	// Sign up with Cognito
	cognitoUserID, err := s.repo.SignUp(ctx, email, username, password)
	if err != nil {
		return nil, errors.WrapError(err, 400, "Failed to register user with authentication service")
	}

	// Create user in database
	hashedPassword, err := utils.HashPassword(password)
	if err != nil {
		return nil, errors.NewInternalServerError("Failed to process password")
	}

	user := &users.User{
		Email:    email,
		Name:     name,
		Password: hashedPassword,
		IsActive: false, // Will be activated after email verification
	}

	if err := s.repo.CreateUser(user); err != nil {
		// TODO: Consider rollback of Cognito user if database creation fails
		return nil, errors.WrapError(err, 500, "Failed to create user record")
	}

	return cognitoUserID, nil
}

// VerifyEmail confirms a user's email address
func (s *AuthService) VerifyEmail(ctx context.Context, email, confirmationCode string) error {
	// Get user from database
	user, err := s.repo.GetUserByEmail(email)
	if err != nil {
		return errors.NewNotFoundError("User")
	}

	// Confirm with Cognito
	if err := s.repo.ConfirmSignUp(ctx, user.Name, confirmationCode); err != nil {
		return errors.WrapError(err, 400, "Failed to verify email with authentication service")
	}

	// Activate user in database
	user.IsActive = true
	if err := s.repo.UpdateUser(user); err != nil {
		return errors.WrapError(err, 500, "Failed to activate user")
	}

	return nil
}

// Login authenticates a user and returns tokens
func (s *AuthService) Login(ctx context.Context, email, password string) (*AuthUser, *TokenPair, error) {
	// Get user from database
	user, err := s.repo.GetUserByEmail(email)
	if err != nil {
		return nil, nil, errors.NewInvalidCredentialsError()
	}

	// Check if user is active
	if !user.IsActive {
		return nil, nil, errors.NewUserNotActiveError()
	}

	// Authenticate with Cognito
	cognitoTokens, err := s.repo.SignIn(ctx, user.Name, password)
	if err != nil {
		return nil, nil, errors.NewInvalidCredentialsError()
	}

	// Update last login
	if err := s.repo.UpdateLastLogin(user.ID); err != nil {
		// Non-critical error, continue without failing the login
		// In production, this should be logged
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
		LastLoginAt:   user.LastLoginAt,
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
		return nil, errors.NewTokenExpiredError()
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
		// Don't reveal if user exists or not for security reasons
		return nil
	}

	// Initiate forgot password with Cognito
	if err := s.repo.ForgotPassword(ctx, user.Name); err != nil {
		// Don't reveal specific errors for security reasons
		return nil
	}

	return nil
}

// ResetPassword resets the user's password
func (s *AuthService) ResetPassword(ctx context.Context, email, confirmationCode, newPassword string) error {
	// Validate password strength
	if validationErrors := s.validatePassword(newPassword); len(validationErrors) > 0 {
		return errors.NewPasswordTooWeakError()
	}

	// Get user from database to get username
	user, err := s.repo.GetUserByEmail(email)
	if err != nil {
		return errors.NewBadRequestError("Invalid request")
	}

	// Confirm forgot password with Cognito
	if err := s.repo.ConfirmForgotPassword(ctx, user.Name, confirmationCode, newPassword); err != nil {
		return errors.WrapError(err, 400, "Failed to reset password")
	}

	// Update password hash in database
	hashedPassword, err := utils.HashPassword(newPassword)
	if err != nil {
		return errors.NewInternalServerError("Failed to process password")
	}

	user.Password = hashedPassword
	if err := s.repo.UpdateUser(user); err != nil {
		return errors.WrapError(err, 500, "Failed to update user password")
	}

	return nil
}

// ChangePassword changes the user's password (for authenticated users)
func (s *AuthService) ChangePassword(ctx context.Context, userID uint, accessToken, currentPassword, newPassword string) error {
	// Validate password strength
	if validationErrors := s.validatePassword(newPassword); len(validationErrors) > 0 {
		return errors.NewPasswordTooWeakError()
	}

	// Get user from database
	user, err := s.repo.GetUserByID(userID)
	if err != nil {
		return errors.NewNotFoundError("User")
	}

	// Verify current password with local hash
	if !utils.CheckPasswordHash(currentPassword, user.Password) {
		return errors.NewBadRequestError("Current password is incorrect")
	}

	// Change password in Cognito
	if err := s.repo.ChangePassword(ctx, accessToken, currentPassword, newPassword); err != nil {
		return errors.WrapError(err, 400, "Failed to change password")
	}

	// Update password hash in database
	hashedPassword, err := utils.HashPassword(newPassword)
	if err != nil {
		return errors.NewInternalServerError("Failed to process password")
	}

	user.Password = hashedPassword
	if err := s.repo.UpdateUser(user); err != nil {
		return errors.WrapError(err, 500, "Failed to update user password")
	}

	return nil
}

// Logout signs out a user
func (s *AuthService) Logout(ctx context.Context, accessToken string) error {
	err := s.repo.SignOut(ctx, accessToken)
	if err != nil {
		// Logout errors are typically not critical
		// In production, this should be logged
		return err
	}
	return nil
}

// GetUserFromToken retrieves user information from an access token
func (s *AuthService) GetUserFromToken(ctx context.Context, accessToken string) (*AuthUser, error) {
	// Get user info from Cognito
	cognitoUser, err := s.repo.GetUser(ctx, accessToken)
	if err != nil {
		return nil, errors.NewInvalidTokenError()
	}

	// Extract email from attributes
	var email string
	for _, attr := range cognitoUser.UserAttributes {
		if *attr.Name == "email" {
			email = *attr.Value
			break
		}
	}

	if email == "" {
		return nil, errors.NewInternalServerError("Email not found in token")
	}

	// Get user from database
	user, err := s.repo.GetUserByEmail(email)
	if err != nil {
		return nil, errors.NewNotFoundError("User")
	}

	return &AuthUser{
		ID:            user.ID,
		Email:         user.Email,
		Username:      user.Name,
		EmailVerified: true,
		IsActive:      user.IsActive,
		CreatedAt:     user.CreatedAt,
		UpdatedAt:     user.UpdatedAt,
		LastLoginAt:   user.LastLoginAt,
	}, nil
}

// validatePassword validates password against configured rules
func (s *AuthService) validatePassword(password string) []string {
	var errors []string
	
	if len(password) < s.passwordRules.MinLength {
		errors = append(errors, "Password must be at least 8 characters long")
	}
	
	if len(password) > s.passwordRules.MaxLength {
		errors = append(errors, "Password must be no more than 128 characters long")
	}
	
	if s.passwordRules.RequireUppercase {
		hasUpper := false
		for _, char := range password {
			if 'A' <= char && char <= 'Z' {
				hasUpper = true
				break
			}
		}
		if !hasUpper {
			errors = append(errors, "Password must contain at least one uppercase letter")
		}
	}
	
	if s.passwordRules.RequireLowercase {
		hasLower := false
		for _, char := range password {
			if 'a' <= char && char <= 'z' {
				hasLower = true
				break
			}
		}
		if !hasLower {
			errors = append(errors, "Password must contain at least one lowercase letter")
		}
	}
	
	if s.passwordRules.RequireNumbers {
		hasDigit := false
		for _, char := range password {
			if '0' <= char && char <= '9' {
				hasDigit = true
				break
			}
		}
		if !hasDigit {
			errors = append(errors, "Password must contain at least one digit")
		}
	}
	
	if s.passwordRules.RequireSymbols {
		hasSpecial := false
		for _, char := range password {
			if isSpecialChar(char) {
				hasSpecial = true
				break
			}
		}
		if !hasSpecial {
			errors = append(errors, "Password must contain at least one special character")
		}
	}
	
	return errors
}

// isSpecialChar checks if a character is a special character
func isSpecialChar(char rune) bool {
	specialChars := "!@#$%^&*()_+-=[]{}|;':\",./<>?"
	for _, sc := range specialChars {
		if char == sc {
			return true
		}
	}
	return false
}
