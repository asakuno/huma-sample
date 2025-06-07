package tests

import (
	"context"
	"testing"
	"time"

	"github.com/asakuno/huma-sample/app/modules/auth"
	"github.com/asakuno/huma-sample/app/modules/users"
	"github.com/asakuno/huma-sample/app/shared/utils"
)

func TestAuthService_SignUp(t *testing.T) {
	tests := []struct {
		name           string
		email          string
		username       string
		password       string
		fullName       string
		setupMock      func(*MockRepository)
		expectError    bool
		expectedError  string
	}{
		{
			name:     "successful signup",
			email:    "newuser@example.com",
			username: "newuser",
			password: "validpass123",
			fullName: "New User",
			setupMock: func(m *MockRepository) {
				// No existing user, successful creation
			},
			expectError: false,
		},
		{
			name:     "existing user",
			email:    "existing@example.com",
			username: "existing",
			password: "validpass123",
			fullName: "Existing User",
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
		{
			name:     "weak password",
			email:    "newuser@example.com",
			username: "newuser",
			password: "weak", // Too short
			fullName: "New User",
			setupMock: func(m *MockRepository) {
				// Empty setup
			},
			expectError:   true,
			expectedError: "Password does not meet strength requirements",
		},
		{
			name:     "cognito signup failure",
			email:    "newuser@example.com",
			username: "newuser",
			password: "validpass123",
			fullName: "New User",
			setupMock: func(m *MockRepository) {
				m.SetFailure(true, "Cognito signup failed")
			},
			expectError:   true,
			expectedError: "Failed to register user",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := SetupTestConfig(t)
			defer config.CleanupTestDB(t)

			mockRepo := config.Repository.(*MockRepository)
			tt.setupMock(mockRepo)

			cognitoUserID, err := config.Service.SignUp(
				context.Background(),
				tt.email,
				tt.username,
				tt.password,
				tt.fullName,
			)

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
				if cognitoUserID == nil {
					t.Errorf("Expected cognito user ID but got nil")
				}
			}
		})
	}
}

func TestAuthService_Login(t *testing.T) {
	tests := []struct {
		name          string
		email         string
		password      string
		setupMock     func(*MockRepository)
		expectError   bool
		expectedError string
	}{
		{
			name:     "successful login",
			email:    "test@example.com",
			password: "validpass123",
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
			name:     "user not found",
			email:    "notfound@example.com",
			password: "validpass123",
			setupMock: func(m *MockRepository) {
				// No user added
			},
			expectError:   true,
			expectedError: "Invalid email or password",
		},
		{
			name:     "inactive user",
			email:    "inactive@example.com",
			password: "validpass123",
			setupMock: func(m *MockRepository) {
				user := &users.User{
					ID:       1,
					Email:    "inactive@example.com",
					Name:     "Inactive User",
					Password: "hashedpassword",
					IsActive: false,
				}
				m.AddMockUser(user)
			},
			expectError:   true,
			expectedError: "not active",
		},
		{
			name:     "cognito signin failure",
			email:    "test@example.com",
			password: "validpass123",
			setupMock: func(m *MockRepository) {
				user := &users.User{
					ID:       1,
					Email:    "test@example.com",
					Name:     "Test User",
					Password: "hashedpassword",
					IsActive: true,
				}
				m.AddMockUser(user)
				m.SetFailure(true, "Cognito signin failed")
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

			authUser, tokenPair, err := config.Service.Login(
				context.Background(),
				tt.email,
				tt.password,
			)

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
				if tokenPair == nil {
					t.Errorf("Expected token pair but got nil")
				}
				if authUser.Email != tt.email {
					t.Errorf("Expected email %s, got %s", tt.email, authUser.Email)
				}
			}
		})
	}
}

func TestAuthService_RefreshToken(t *testing.T) {
	tests := []struct {
		name          string
		refreshToken  string
		setupMock     func(*MockRepository)
		expectError   bool
		expectedError string
	}{
		{
			name:         "successful refresh",
			refreshToken: "valid-refresh-token",
			setupMock: func(m *MockRepository) {
				// Success case
			},
			expectError: false,
		},
		{
			name:         "invalid refresh token",
			refreshToken: "invalid-token",
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

			tokenPair, err := config.Service.RefreshToken(
				context.Background(),
				tt.refreshToken,
			)

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
				if tokenPair == nil {
					t.Errorf("Expected token pair but got nil")
				}
				if tokenPair.AccessToken == "" {
					t.Errorf("Expected access token but got empty string")
				}
			}
		})
	}
}

func TestAuthService_ChangePasswordByEmail(t *testing.T) {
	tests := []struct {
		name            string
		email           string
		accessToken     string
		currentPassword string
		newPassword     string
		setupMock       func(*MockRepository)
		expectError     bool
		expectedError   string
	}{
		{
			name:            "successful password change",
			email:           "test@example.com",
			accessToken:     "valid-access-token",
			currentPassword: "currentpass123",
			newPassword:     "newpass123",
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
			name:            "user not found",
			email:           "notfound@example.com",
			accessToken:     "valid-access-token",
			currentPassword: "currentpass123",
			newPassword:     "newpass123",
			setupMock: func(m *MockRepository) {
				// No user added
			},
			expectError:   true,
			expectedError: "not found",
		},
		{
			name:            "weak new password",
			email:           "test@example.com",
			accessToken:     "valid-access-token",
			currentPassword: "currentpass123",
			newPassword:     "weak", // Too short
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
			expectError:   true,
			expectedError: "Password does not meet strength requirements",
		},
		{
			name:            "incorrect current password",
			email:           "test@example.com",
			accessToken:     "valid-access-token",
			currentPassword: "wrongpassword",
			newPassword:     "newpass123",
			setupMock: func(m *MockRepository) {
				hashedPassword, _ := utils.HashPassword("correctpassword")
				user := &users.User{
					ID:       1,
					Email:    "test@example.com",
					Name:     "Test User",
					Password: hashedPassword,
					IsActive: true,
				}
				m.AddMockUser(user)
			},
			expectError:   true,
			expectedError: "incorrect",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			config := SetupTestConfig(t)
			defer config.CleanupTestDB(t)

			mockRepo := config.Repository.(*MockRepository)
			tt.setupMock(mockRepo)

			err := config.Service.ChangePasswordByEmail(
				context.Background(),
				tt.email,
				tt.accessToken,
				tt.currentPassword,
				tt.newPassword,
			)

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
				}
			}
		})
	}
}

func TestAuthService_GetUserByEmail(t *testing.T) {
	tests := []struct {
		name          string
		email         string
		setupMock     func(*MockRepository)
		expectError   bool
		expectedError string
	}{
		{
			name:  "successful user retrieval",
			email: "test@example.com",
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
			name:  "user not found",
			email: "notfound@example.com",
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

			authUser, err := config.Service.GetUserByEmail(
				context.Background(),
				tt.email,
			)

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
				if authUser.Email != tt.email {
					t.Errorf("Expected email %s, got %s", tt.email, authUser.Email)
				}
			}
		})
	}
}

func TestPasswordValidation(t *testing.T) {
	config := SetupTestConfig(t)
	defer config.CleanupTestDB(t)

	// Test with strict password rules
	strictRules := auth.PasswordRules{
		MinLength:        8,
		MaxLength:        20,
		RequireUppercase: true,
		RequireLowercase: true,
		RequireNumbers:   true,
		RequireSymbols:   true,
	}

	strictService := auth.NewAuthService(config.Repository, strictRules)

	tests := []struct {
		name        string
		password    string
		expectError bool
	}{
		{
			name:        "valid complex password",
			password:    "Test@123",
			expectError: false,
		},
		{
			name:        "too short",
			password:    "Test@1",
			expectError: true,
		},
		{
			name:        "missing uppercase",
			password:    "test@123",
			expectError: true,
		},
		{
			name:        "missing lowercase",
			password:    "TEST@123",
			expectError: true,
		},
		{
			name:        "missing number",
			password:    "Test@abc",
			expectError: true,
		},
		{
			name:        "missing symbol",
			password:    "Test1234",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Reset the mock for each test
			mockRepo := config.Repository.(*MockRepository)
			mockRepo.SetFailure(false, "")

			_, err := strictService.SignUp(
				context.Background(),
				"test@example.com",
				"testuser",
				tt.password,
				"Test User",
			)

			if tt.expectError {
				if err == nil {
					t.Errorf("Expected error for password '%s' but got none", tt.password)
				} else if !containsString(err.Error(), "Password does not meet strength requirements") {
					t.Errorf("Expected 'Password does not meet strength requirements' error, got: %v", err)
				}
			} else {
				if err != nil && containsString(err.Error(), "Password does not meet strength requirements") {
					t.Errorf("Password '%s' should be valid but got error: %v", tt.password, err)
				}
			}
		})
	}
}

// Helper function to check if a string contains a substring
func containsString(str, substr string) bool {
	return len(str) >= len(substr) && (str == substr || len(substr) == 0 || 
		(len(str) > len(substr) && (str[:len(substr)] == substr || 
		str[len(str)-len(substr):] == substr || 
		containsStringHelper(str, substr))))
}

func containsStringHelper(str, substr string) bool {
	for i := 0; i <= len(str)-len(substr); i++ {
		if str[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}