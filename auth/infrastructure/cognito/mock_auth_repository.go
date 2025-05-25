package cognito

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/asakuno/huma-sample/auth/domain/entity"
	"github.com/asakuno/huma-sample/auth/domain/repository"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
)

// mockAuthRepository implements the AuthRepository interface for development
type mockAuthRepository struct{}

// NewMockAuthRepository creates a new mock AuthRepository for development
func NewMockAuthRepository() repository.AuthRepository {
	return &mockAuthRepository{}
}

// Authenticate authenticates a user with username and password (mock)
func (r *mockAuthRepository) Authenticate(ctx context.Context, req *repository.CognitoAuthRequest) (*repository.CognitoAuthResponse, error) {
	if req == nil {
		return nil, errors.New("authentication request is required")
	}

	// Mock user credentials for development
	validUsers := map[string]string{
		"admin":     "password123",
		"testuser":  "password123",
		"developer": "password123",
	}

	password, exists := validUsers[req.Username]
	if !exists || password != req.Password {
		return nil, errors.New("invalid username or password")
	}

	// Generate mock tokens
	accessToken, err := r.generateMockToken(req.Username, "access", 3600) // 1 hour
	if err != nil {
		return nil, err
	}

	refreshToken, err := r.generateMockToken(req.Username, "refresh", 86400*7) // 7 days
	if err != nil {
		return nil, err
	}

	idToken, err := r.generateMockToken(req.Username, "id", 3600) // 1 hour
	if err != nil {
		return nil, err
	}

	return &repository.CognitoAuthResponse{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		IDToken:      idToken,
		TokenType:    "Bearer",
		ExpiresIn:    3600,
	}, nil
}

// RefreshToken refreshes an access token using a refresh token (mock)
func (r *mockAuthRepository) RefreshToken(ctx context.Context, refreshToken string) (*repository.CognitoAuthResponse, error) {
	if refreshToken == "" {
		return nil, errors.New("refresh token is required")
	}

	// Parse and validate refresh token
	token, err := jwt.Parse(refreshToken, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("JWT_SECRET")), nil
	})

	if err != nil || !token.Valid {
		return nil, errors.New("invalid refresh token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid token claims")
	}

	username, ok := claims["username"].(string)
	if !ok {
		return nil, errors.New("username not found in token")
	}

	tokenType, ok := claims["type"].(string)
	if !ok || tokenType != "refresh" {
		return nil, errors.New("not a refresh token")
	}

	// Generate new tokens
	accessToken, err := r.generateMockToken(username, "access", 3600)
	if err != nil {
		return nil, err
	}

	newRefreshToken, err := r.generateMockToken(username, "refresh", 86400*7)
	if err != nil {
		return nil, err
	}

	idToken, err := r.generateMockToken(username, "id", 3600)
	if err != nil {
		return nil, err
	}

	return &repository.CognitoAuthResponse{
		AccessToken:  accessToken,
		RefreshToken: newRefreshToken,
		IDToken:      idToken,
		TokenType:    "Bearer",
		ExpiresIn:    3600,
	}, nil
}

// GetUserInfo retrieves user information using access token (mock)
func (r *mockAuthRepository) GetUserInfo(ctx context.Context, accessToken string) (*repository.CognitoUserInfo, error) {
	if accessToken == "" {
		return nil, errors.New("access token is required")
	}

	// Parse token to get user info
	token, err := jwt.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("JWT_SECRET")), nil
	})

	if err != nil || !token.Valid {
		return nil, errors.New("invalid access token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid token claims")
	}

	username, ok := claims["username"].(string)
	if !ok {
		return nil, errors.New("username not found in token")
	}

	// Mock user info based on username
	userInfoMap := map[string]*repository.CognitoUserInfo{
		"admin": {
			Sub:       "dev_admin_cognito_id",
			Username:  "admin",
			Email:     "admin@example.com",
			FirstName: "Admin",
			LastName:  "User",
			Status:    "CONFIRMED",
		},
		"testuser": {
			Sub:       "dev_user_cognito_id",
			Username:  "testuser",
			Email:     "test@example.com",
			FirstName: "Test",
			LastName:  "User",
			Status:    "CONFIRMED",
		},
		"developer": {
			Sub:       "dev_developer_cognito_id",
			Username:  "developer",
			Email:     "dev@example.com",
			FirstName: "Developer",
			LastName:  "User",
			Status:    "CONFIRMED",
		},
	}

	userInfo, exists := userInfoMap[username]
	if !exists {
		return nil, errors.New("user not found")
	}

	return userInfo, nil
}

// ValidateToken validates an access token (mock)
func (r *mockAuthRepository) ValidateToken(ctx context.Context, accessToken string) (*entity.TokenClaims, error) {
	if accessToken == "" {
		return nil, errors.New("access token is required")
	}

	// Parse token
	token, err := jwt.Parse(accessToken, func(token *jwt.Token) (interface{}, error) {
		return []byte(os.Getenv("JWT_SECRET")), nil
	})

	if err != nil || !token.Valid {
		return nil, errors.New("invalid access token")
	}

	claims, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, errors.New("invalid token claims")
	}

	username, _ := claims["username"].(string)
	cognitoID, _ := claims["sub"].(string)
	
	// Get user info to populate claims
	userInfo, err := r.GetUserInfo(ctx, accessToken)
	if err != nil {
		return nil, err
	}

	// Parse timestamps
	var expiresAt, issuedAt time.Time
	if exp, ok := claims["exp"].(float64); ok {
		expiresAt = time.Unix(int64(exp), 0)
	}
	if iat, ok := claims["iat"].(float64); ok {
		issuedAt = time.Unix(int64(iat), 0)
	}

	// Generate a mock user ID for the token claims
	userID := uuid.New()

	tokenClaims := &entity.TokenClaims{
		UserID:    userID,
		CognitoID: cognitoID,
		Username:  username,
		Email:     userInfo.Email,
		ExpiresAt: expiresAt,
		IssuedAt:  issuedAt,
		Issuer:    "mock-cognito",
		Audience:  "mock-client",
	}

	return tokenClaims, nil
}

// SignOut signs out a user (mock - always succeeds)
func (r *mockAuthRepository) SignOut(ctx context.Context, accessToken string) error {
	// In a real implementation, this would invalidate the token
	// For mock, we just return success
	return nil
}

// ForgotPassword initiates forgot password flow (mock)
func (r *mockAuthRepository) ForgotPassword(ctx context.Context, req *repository.ForgotPasswordRequest) error {
	if req == nil || req.Username == "" {
		return errors.New("username is required")
	}

	// Mock - always succeeds for valid usernames
	validUsers := []string{"admin", "testuser", "developer"}
	for _, user := range validUsers {
		if user == req.Username {
			fmt.Printf("Mock: Forgot password email sent to user: %s\n", req.Username)
			return nil
		}
	}

	return errors.New("user not found")
}

// ConfirmForgotPassword confirms forgot password (mock)
func (r *mockAuthRepository) ConfirmForgotPassword(ctx context.Context, req *repository.ConfirmForgotPasswordRequest) error {
	if req == nil {
		return errors.New("confirm forgot password request is required")
	}

	// Mock - accepts any 6-digit code
	if len(req.ConfirmationCode) != 6 {
		return errors.New("invalid confirmation code")
	}

	if len(req.NewPassword) < 8 {
		return errors.New("password must be at least 8 characters")
	}

	fmt.Printf("Mock: Password reset successful for user: %s\n", req.Username)
	return nil
}

// CreateUser creates a new user (mock)
func (r *mockAuthRepository) CreateUser(ctx context.Context, username, email, tempPassword string) error {
	fmt.Printf("Mock: User created - Username: %s, Email: %s\n", username, email)
	return nil
}

// SetUserPassword sets a permanent password (mock)
func (r *mockAuthRepository) SetUserPassword(ctx context.Context, username, password string) error {
	fmt.Printf("Mock: Password set for user: %s\n", username)
	return nil
}

// DeleteUser deletes a user (mock)
func (r *mockAuthRepository) DeleteUser(ctx context.Context, username string) error {
	fmt.Printf("Mock: User deleted: %s\n", username)
	return nil
}

// ListUsers lists users (mock)
func (r *mockAuthRepository) ListUsers(ctx context.Context, limit int, paginationToken string) ([]*repository.CognitoUserInfo, string, error) {
	users := []*repository.CognitoUserInfo{
		{
			Sub:       "dev_admin_cognito_id",
			Username:  "admin",
			Email:     "admin@example.com",
			FirstName: "Admin",
			LastName:  "User",
			Status:    "CONFIRMED",
		},
		{
			Sub:       "dev_user_cognito_id",
			Username:  "testuser",
			Email:     "test@example.com",
			FirstName: "Test",
			LastName:  "User",
			Status:    "CONFIRMED",
		},
		{
			Sub:       "dev_developer_cognito_id",
			Username:  "developer",
			Email:     "dev@example.com",
			FirstName: "Developer",
			LastName:  "User",
			Status:    "CONFIRMED",
		},
	}

	return users, "", nil
}

// generateMockToken generates a mock JWT token
func (r *mockAuthRepository) generateMockToken(username, tokenType string, expirySeconds int) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"username": username,
		"sub":      fmt.Sprintf("dev_%s_cognito_id", username),
		"type":     tokenType,
		"iat":      now.Unix(),
		"exp":      now.Add(time.Duration(expirySeconds) * time.Second).Unix(),
		"iss":      "mock-cognito",
		"aud":      "mock-client",
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	jwtSecret := os.Getenv("JWT_SECRET")
	if jwtSecret == "" {
		jwtSecret = "mock-jwt-secret-for-development"
	}

	return token.SignedString([]byte(jwtSecret))
}
