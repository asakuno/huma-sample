package tests

import (
	"context"
	"testing"
	"time"

	"github.com/asakuno/huma-sample/app/middleware"
	"github.com/asakuno/huma-sample/app/modules/auth"
	"github.com/asakuno/huma-sample/app/modules/users"
	"github.com/asakuno/huma-sample/app/shared/utils"
)

func TestController_SignUp(t *testing.T) {
	tests := []struct {
		name          string
		request       *auth.SignUpRequest
		setupMock     func(*MockRepository)
		expectError   bool
		expectedError string
	}{
		{
			name: "successful signup",
			request: &auth.SignUpRequest{
				Body: struct {
					Email    string `json:"email" format:"email" doc:"User email address" example:"user@example.com"`
					Username string `json:"username" minLength:"3" maxLength:"50" pattern:"^[a-zA-Z0-9_-]+$" doc:"Username (alphanumeric, underscore, hyphen)" example:"john_doe"`
					Password string `json:"password" minLength:"8" maxLength:"128" doc:"Password (minimum 8 characters)" example:"MySecurePass123!"`
					Name     string `json:"name" minLength:"2" maxLength:"100" doc:"Full name" example:"John Doe"`
				}{
					Email:    "newuser@example.com",
					Username: "newuser",
					Password: "validpass123",
					Name:     "New User",
				},
			},
			setupMock: func(m *MockRepository) {
				// Successful case - no existing user
			},
			expectError: false,
		},
		{
			name: "duplicate email",
			request: &auth.SignUpRequest{
				Body: struct {
					Email    string `json:"email" format:"email" doc:"User email address" example:"user@example.com"`
					Username string `json:"username" minLength:"3" maxLength:"50" pattern:"^[a-zA-Z0-9_-]+$" doc:"Username (alphanumeric, underscore, hyphen)" example:"john_doe"`
					Password string `json:"password" minLength:"8" maxLength:"128" doc:"Password (minimum 8 characters)" example:"MySecurePass123!"`
					Name     string `json:"name" minLength:"2" maxLength:"100" doc:"Full name" example:"John Doe"`
				}{
					Email:    "existing@example.com",
					Username: "newuser",
					Password: "validpass123",
					Name:     "New User",
				},
			},
			setupMock: func(m *MockRepository) {
				existingUser := &users.User{
					ID:    1,
					Email: "existing@example.com",
					Name:  "Existing User",
				}
				m.AddMockUser(existingUser)
			},
			expectError:   true,
			expectedError: "already exists",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := SetupTestConfig(t)
			defer config.CleanupTestDB(t)

			mockRepo := config.Repository.(*MockRepository)
			tt.setupMock(mockRepo)

			response, err := config.Controller.SignUp(context.Background(), tt.request)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
					return
				}
				if tt.expectedError != "" && !containsString(err.Error(), tt.expectedError) {
					t.Errorf("Expected error containing '%s', got '%s'", tt.expectedError, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
					return
				}
				if response == nil {
					t.Errorf("Expected response but got nil")
					return
				}
				if !response.Success {
					t.Errorf("Expected success=true, got success=false")
				}
				if response.UserID == "" {
					t.Errorf("Expected user ID but got empty string")
				}
			}
		})
	}
}

func TestController_Login(t *testing.T) {
	tests := []struct {
		name          string
		request       *auth.LoginRequest
		setupMock     func(*MockRepository)
		expectError   bool
		expectedError string
	}{
		{
			name: "successful login",
			request: &auth.LoginRequest{
				Body: struct {
					Email    string `json:"email" format:"email" doc:"User email address" example:"user@example.com"`
					Password string `json:"password" minLength:"1" doc:"User password" example:"MySecurePass123!"`
				}{
					Email:    "test@example.com",
					Password: "validpass123",
				},
			},
			setupMock: func(m *MockRepository) {
				user := &users.User{
					ID:       1,
					Email:    "test@example.com",
					Name:     "Test User",
					Password: "hashedpassword",
					IsActive: true,
				}
				m.AddMockUser(user)
			},
			expectError: false,
		},
		{
			name: "invalid credentials",
			request: &auth.LoginRequest{
				Body: struct {
					Email    string `json:"email" format:"email" doc:"User email address" example:"user@example.com"`
					Password string `json:"password" minLength:"1" doc:"User password" example:"MySecurePass123!"`
				}{
					Email:    "notfound@example.com",
					Password: "validpass123",
				},
			},
			setupMock: func(m *MockRepository) {
				// No user added
			},
			expectError:   true,
			expectedError: "Invalid email or password",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := SetupTestConfig(t)
			defer config.CleanupTestDB(t)

			mockRepo := config.Repository.(*MockRepository)
			tt.setupMock(mockRepo)

			response, err := config.Controller.Login(context.Background(), tt.request)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
					return
				}
				if tt.expectedError != "" && !containsString(err.Error(), tt.expectedError) {
					t.Errorf("Expected error containing '%s', got '%s'", tt.expectedError, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
					return
				}
				if response == nil {
					t.Errorf("Expected response but got nil")
					return
				}
				if response.User.Email != tt.request.Body.Email {
					t.Errorf("Expected email %s, got %s", tt.request.Body.Email, response.User.Email)
				}
				if response.Tokens.AccessToken == "" {
					t.Errorf("Expected access token but got empty string")
				}
			}
		})
	}
}

func TestController_GetProfile(t *testing.T) {
	tests := []struct {
		name          string
		setupContext  func() context.Context
		setupMock     func(*MockRepository)
		expectError   bool
		expectedError string
	}{
		{
			name: "successful profile retrieval",
			setupContext: func() context.Context {
				ctx := context.Background()
				claims := &utils.JWTClaims{
					Email:     "test@example.com",
					CognitoID: "cognito-user-id",
				}
				return context.WithValue(ctx, middleware.UserContextKey, claims)
			},
			setupMock: func(m *MockRepository) {
				user := &users.User{
					ID:        1,
					Email:     "test@example.com",
					Name:      "Test User",
					IsActive:  true,
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
				}
				m.AddMockUser(user)
			},
			expectError: false,
		},
		{
			name: "no authentication context",
			setupContext: func() context.Context {
				return context.Background()
			},
			setupMock: func(m *MockRepository) {
				// No setup needed
			},
			expectError:   true,
			expectedError: "Authentication required",
		},
		{
			name: "user not found",
			setupContext: func() context.Context {
				ctx := context.Background()
				claims := &utils.JWTClaims{
					Email:     "notfound@example.com",
					CognitoID: "cognito-user-id",
				}
				return context.WithValue(ctx, middleware.UserContextKey, claims)
			},
			setupMock: func(m *MockRepository) {
				// No user added
			},
			expectError:   true,
			expectedError: "not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := SetupTestConfig(t)
			defer config.CleanupTestDB(t)

			mockRepo := config.Repository.(*MockRepository)
			tt.setupMock(mockRepo)

			ctx := tt.setupContext()
			authUser, err := config.Controller.GetProfile(ctx, &struct{}{})

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
					return
				}
				if tt.expectedError != "" && !containsString(err.Error(), tt.expectedError) {
					t.Errorf("Expected error containing '%s', got '%s'", tt.expectedError, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
					return
				}
				if authUser == nil {
					t.Errorf("Expected auth user but got nil")
				}
			}
		})
	}
}

func TestController_ChangePassword(t *testing.T) {
	tests := []struct {
		name          string
		request       *auth.ChangePasswordRequest
		setupContext  func() context.Context
		setupMock     func(*MockRepository)
		expectError   bool
		expectedError string
	}{
		{
			name: "successful password change",
			request: &auth.ChangePasswordRequest{
				Body: struct {
					CurrentPassword string `json:"current_password" minLength:"1" doc:"Current password" example:"MyOldPassword123!"`
					NewPassword     string `json:"new_password" minLength:"8" maxLength:"128" doc:"New password (minimum 8 characters)" example:"MyNewPassword123!"`
				}{
					CurrentPassword: "currentpass123",
					NewPassword:     "newpass123",
				},
			},
			setupContext: func() context.Context {
				ctx := context.Background()
				claims := &utils.JWTClaims{
					Email:     "test@example.com",
					CognitoID: "cognito-user-id",
				}
				ctx = context.WithValue(ctx, middleware.UserContextKey, claims)
				return context.WithValue(ctx, middleware.TokenContextKey, "mock-access-token")
			},
			setupMock: func(m *MockRepository) {
				hashedPassword, _ := utils.HashPassword("currentpass123")
				user := &users.User{
					ID:       1,
					Email:    "test@example.com",
					Name:     "Test User",
					Password: hashedPassword,
					IsActive: true,
				}
				m.AddMockUser(user)
			},
			expectError: false,
		},
		{
			name: "no authentication context",
			request: &auth.ChangePasswordRequest{
				Body: struct {
					CurrentPassword string `json:"current_password" minLength:"1" doc:"Current password" example:"MyOldPassword123!"`
					NewPassword     string `json:"new_password" minLength:"8" maxLength:"128" doc:"New password (minimum 8 characters)" example:"MyNewPassword123!"`
				}{
					CurrentPassword: "currentpass123",
					NewPassword:     "newpass123",
				},
			},
			setupContext: func() context.Context {
				return context.Background()
			},
			setupMock: func(m *MockRepository) {
				// No setup needed
			},
			expectError:   true,
			expectedError: "Authentication required",
		},
		{
			name: "user not found",
			request: &auth.ChangePasswordRequest{
				Body: struct {
					CurrentPassword string `json:"current_password" minLength:"1" doc:"Current password" example:"MyOldPassword123!"`
					NewPassword     string `json:"new_password" minLength:"8" maxLength:"128" doc:"New password (minimum 8 characters)" example:"MyNewPassword123!"`
				}{
					CurrentPassword: "currentpass123",
					NewPassword:     "newpass123",
				},
			},
			setupContext: func() context.Context {
				ctx := context.Background()
				claims := &utils.JWTClaims{
					Email:     "notfound@example.com",
					CognitoID: "cognito-user-id",
				}
				ctx = context.WithValue(ctx, middleware.UserContextKey, claims)
				return context.WithValue(ctx, middleware.TokenContextKey, "mock-access-token")
			},
			setupMock: func(m *MockRepository) {
				// No user added
			},
			expectError:   true,
			expectedError: "not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := SetupTestConfig(t)
			defer config.CleanupTestDB(t)

			mockRepo := config.Repository.(*MockRepository)
			tt.setupMock(mockRepo)

			ctx := tt.setupContext()
			response, err := config.Controller.ChangePassword(ctx, tt.request)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
					return
				}
				if tt.expectedError != "" && !containsString(err.Error(), tt.expectedError) {
					t.Errorf("Expected error containing '%s', got '%s'", tt.expectedError, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
					return
				}
				if response == nil {
					t.Errorf("Expected response but got nil")
					return
				}
				if !response.Success {
					t.Errorf("Expected success=true, got success=false")
				}
			}
		})
	}
}

func TestController_RefreshToken(t *testing.T) {
	tests := []struct {
		name          string
		request       *auth.RefreshTokenRequest
		setupMock     func(*MockRepository)
		expectError   bool
		expectedError string
	}{
		{
			name: "successful token refresh",
			request: &auth.RefreshTokenRequest{
				Body: struct {
					RefreshToken string `json:"refresh_token" minLength:"1" doc:"Refresh token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
				}{
					RefreshToken: "valid-refresh-token",
				},
			},
			setupMock: func(m *MockRepository) {
				// Success case
			},
			expectError: false,
		},
		{
			name: "invalid refresh token",
			request: &auth.RefreshTokenRequest{
				Body: struct {
					RefreshToken string `json:"refresh_token" minLength:"1" doc:"Refresh token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
				}{
					RefreshToken: "invalid-token",
				},
			},
			setupMock: func(m *MockRepository) {
				m.SetFailure(true, "Invalid refresh token")
			},
			expectError:   true,
			expectedError: "expired",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := SetupTestConfig(t)
			defer config.CleanupTestDB(t)

			mockRepo := config.Repository.(*MockRepository)
			tt.setupMock(mockRepo)

			response, err := config.Controller.RefreshToken(context.Background(), tt.request)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error but got none")
					return
				}
				if tt.expectedError != "" && !containsString(err.Error(), tt.expectedError) {
					t.Errorf("Expected error containing '%s', got '%s'", tt.expectedError, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
					return
				}
				if response == nil {
					t.Errorf("Expected response but got nil")
					return
				}
				if response.Tokens.AccessToken == "" {
					t.Errorf("Expected access token but got empty string")
				}
			}
		})
	}
}

func TestController_HealthCheck(t *testing.T) {
	config := SetupTestConfig(t)
	defer config.CleanupTestDB(t)

	response, err := config.Controller.HealthCheck(context.Background(), &struct{}{})

	if err != nil {
		t.Errorf("Unexpected error: %v", err)
		return
	}

	if response == nil {
		t.Errorf("Expected response but got nil")
		return
	}

	if response.Body.Status != "ok" {
		t.Errorf("Expected status 'ok', got '%s'", response.Body.Status)
	}

	if response.Body.Service != "auth" {
		t.Errorf("Expected service 'auth', got '%s'", response.Body.Service)
	}

	// Check that health checks are present
	if response.Body.Checks == nil {
		t.Errorf("Expected health checks but got nil")
	}

	if len(response.Body.Checks) == 0 {
		t.Errorf("Expected health checks but got empty map")
	}
}