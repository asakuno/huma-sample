package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/asakuno/huma-sample/app/config"
	"github.com/asakuno/huma-sample/app/modules/auth/mocks"
	"github.com/asakuno/huma-sample/app/modules/users"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthService_SignUp(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockRepository(ctrl)
	cfg := &config.Config{
		JWT: config.JWTConfig{
			Secret: "test-secret",
		},
	}
	service := NewAuthService(mockRepo, cfg)

	ctx := context.Background()

	tests := []struct {
		name          string
		email         string
		username      string
		password      string
		fullName      string
		setupMocks    func()
		expectedError string
	}{
		{
			name:     "Successful SignUp",
			email:    "test@example.com",
			username: "testuser",
			password: "ValidPassword123!",
			fullName: "Test User",
			setupMocks: func() {
				// Check if user exists
				mockRepo.EXPECT().
					GetUserByEmail("test@example.com").
					Return(nil, errors.New("not found"))

				// Sign up with Cognito
				cognitoUserID := "cognito-123"
				mockRepo.EXPECT().
					SignUp(ctx, "test@example.com", "testuser", "ValidPassword123!").
					Return(&cognitoUserID, nil)

				// Create user in database
				mockRepo.EXPECT().
					CreateUser(gomock.Any()).
					DoAndReturn(func(user *users.User) error {
						assert.Equal(t, "test@example.com", user.Email)
						assert.Equal(t, "Test User", user.Name)
						assert.False(t, user.IsActive) // Should be inactive until verified
						return nil
					})
			},
			expectedError: "",
		},
		{
			name:     "Weak Password",
			email:    "test@example.com",
			username: "testuser",
			password: "weak",
			fullName: "Test User",
			setupMocks: func() {
				// No mocks needed, validation fails first
			},
			expectedError: "password does not meet strength requirements",
		},
		{
			name:     "User Already Exists",
			email:    "test@example.com",
			username: "testuser",
			password: "ValidPassword123!",
			fullName: "Test User",
			setupMocks: func() {
				existingUser := &users.User{
					Email: "test@example.com",
				}
				mockRepo.EXPECT().
					GetUserByEmail("test@example.com").
					Return(existingUser, nil)
			},
			expectedError: "user with this email already exists",
		},
		{
			name:     "Cognito SignUp Error",
			email:    "test@example.com",
			username: "testuser",
			password: "ValidPassword123!",
			fullName: "Test User",
			setupMocks: func() {
				mockRepo.EXPECT().
					GetUserByEmail("test@example.com").
					Return(nil, errors.New("not found"))

				mockRepo.EXPECT().
					SignUp(ctx, "test@example.com", "testuser", "ValidPassword123!").
					Return(nil, errors.New("cognito error"))
			},
			expectedError: "cognito error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMocks()

			userID, err := service.SignUp(ctx, tt.email, tt.username, tt.password, tt.fullName)

			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
				assert.Nil(t, userID)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, userID)
			}
		})
	}
}

func TestAuthService_VerifyEmail(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockRepository(ctrl)
	cfg := &config.Config{}
	service := NewAuthService(mockRepo, cfg)

	ctx := context.Background()

	tests := []struct {
		name             string
		email            string
		confirmationCode string
		setupMocks       func()
		expectedError    string
	}{
		{
			name:             "Successful Verification",
			email:            "test@example.com",
			confirmationCode: "123456",
			setupMocks: func() {
				user := &users.User{
					ID:       1,
					Email:    "test@example.com",
					Name:     "testuser",
					IsActive: false,
				}
				mockRepo.EXPECT().
					GetUserByEmail("test@example.com").
					Return(user, nil)

				mockRepo.EXPECT().
					ConfirmSignUp(ctx, "testuser", "123456").
					Return(nil)

				mockRepo.EXPECT().
					UpdateUser(gomock.Any()).
					DoAndReturn(func(u *users.User) error {
						assert.True(t, u.IsActive)
						return nil
					})
			},
			expectedError: "",
		},
		{
			name:             "User Not Found",
			email:            "nonexistent@example.com",
			confirmationCode: "123456",
			setupMocks: func() {
				mockRepo.EXPECT().
					GetUserByEmail("nonexistent@example.com").
					Return(nil, errors.New("not found"))
			},
			expectedError: "user not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMocks()

			err := service.VerifyEmail(ctx, tt.email, tt.confirmationCode)

			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAuthService_Login(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockRepository(ctrl)
	cfg := &config.Config{}
	service := NewAuthService(mockRepo, cfg)

	ctx := context.Background()

	tests := []struct {
		name          string
		email         string
		password      string
		setupMocks    func()
		expectedError string
	}{
		{
			name:     "Successful Login",
			email:    "test@example.com",
			password: "ValidPassword123!",
			setupMocks: func() {
				user := &users.User{
					ID:       1,
					Email:    "test@example.com",
					Name:     "testuser",
					IsActive: true,
				}
				mockRepo.EXPECT().
					GetUserByEmail("test@example.com").
					Return(user, nil)

				cognitoTokens := &CognitoTokens{
					AccessToken:  "access-token",
					IDToken:      "id-token",
					RefreshToken: "refresh-token",
					ExpiresIn:    3600,
				}
				mockRepo.EXPECT().
					SignIn(ctx, "testuser", "ValidPassword123!").
					Return(cognitoTokens, nil)

				mockRepo.EXPECT().
					UpdateLastLogin(uint(1)).
					Return(nil)
			},
			expectedError: "",
		},
		{
			name:     "User Not Found",
			email:    "nonexistent@example.com",
			password: "ValidPassword123!",
			setupMocks: func() {
				mockRepo.EXPECT().
					GetUserByEmail("nonexistent@example.com").
					Return(nil, errors.New("not found"))
			},
			expectedError: "invalid credentials",
		},
		{
			name:     "User Not Active",
			email:    "test@example.com",
			password: "ValidPassword123!",
			setupMocks: func() {
				user := &users.User{
					ID:       1,
					Email:    "test@example.com",
					Name:     "testuser",
					IsActive: false,
				}
				mockRepo.EXPECT().
					GetUserByEmail("test@example.com").
					Return(user, nil)
			},
			expectedError: "user account is not active",
		},
		{
			name:     "Invalid Credentials",
			email:    "test@example.com",
			password: "WrongPassword",
			setupMocks: func() {
				user := &users.User{
					ID:       1,
					Email:    "test@example.com",
					Name:     "testuser",
					IsActive: true,
				}
				mockRepo.EXPECT().
					GetUserByEmail("test@example.com").
					Return(user, nil)

				mockRepo.EXPECT().
					SignIn(ctx, "testuser", "WrongPassword").
					Return(nil, errors.New("invalid credentials"))
			},
			expectedError: "invalid credentials",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMocks()

			authUser, tokenPair, err := service.Login(ctx, tt.email, tt.password)

			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
				assert.Nil(t, authUser)
				assert.Nil(t, tokenPair)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, authUser)
				assert.NotNil(t, tokenPair)
				assert.Equal(t, "access-token", tokenPair.AccessToken)
				assert.Equal(t, "refresh-token", tokenPair.RefreshToken)
			}
		})
	}
}

func TestAuthService_RefreshToken(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockRepository(ctrl)
	cfg := &config.Config{}
	service := NewAuthService(mockRepo, cfg)

	ctx := context.Background()

	t.Run("Successful Refresh", func(t *testing.T) {
		cognitoTokens := &CognitoTokens{
			AccessToken: "new-access-token",
			IDToken:     "new-id-token",
			ExpiresIn:   3600,
		}
		mockRepo.EXPECT().
			RefreshToken(ctx, "refresh-token").
			Return(cognitoTokens, nil)

		tokenPair, err := service.RefreshToken(ctx, "refresh-token")

		assert.NoError(t, err)
		assert.NotNil(t, tokenPair)
		assert.Equal(t, "new-access-token", tokenPair.AccessToken)
		assert.Equal(t, "Bearer", tokenPair.TokenType)
		assert.Equal(t, 3600, tokenPair.ExpiresIn)
	})

	t.Run("Invalid Refresh Token", func(t *testing.T) {
		mockRepo.EXPECT().
			RefreshToken(ctx, "invalid-token").
			Return(nil, errors.New("invalid token"))

		tokenPair, err := service.RefreshToken(ctx, "invalid-token")

		assert.Error(t, err)
		assert.Nil(t, tokenPair)
	})
}

func TestAuthService_ForgotPassword(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockRepository(ctrl)
	cfg := &config.Config{}
	service := NewAuthService(mockRepo, cfg)

	ctx := context.Background()

	t.Run("Successful Forgot Password", func(t *testing.T) {
		user := &users.User{
			Email: "test@example.com",
			Name:  "testuser",
		}
		mockRepo.EXPECT().
			GetUserByEmail("test@example.com").
			Return(user, nil)

		mockRepo.EXPECT().
			ForgotPassword(ctx, "testuser").
			Return(nil)

		err := service.ForgotPassword(ctx, "test@example.com")
		assert.NoError(t, err)
	})

	t.Run("User Not Found - Silent Success", func(t *testing.T) {
		mockRepo.EXPECT().
			GetUserByEmail("nonexistent@example.com").
			Return(nil, errors.New("not found"))

		// Should not reveal if user exists
		err := service.ForgotPassword(ctx, "nonexistent@example.com")
		assert.NoError(t, err)
	})
}

func TestAuthService_ResetPassword(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockRepository(ctrl)
	cfg := &config.Config{}
	service := NewAuthService(mockRepo, cfg)

	ctx := context.Background()

	tests := []struct {
		name             string
		email            string
		confirmationCode string
		newPassword      string
		setupMocks       func()
		expectedError    string
	}{
		{
			name:             "Successful Reset",
			email:            "test@example.com",
			confirmationCode: "123456",
			newPassword:      "NewPassword123!",
			setupMocks: func() {
				user := &users.User{
					ID:    1,
					Email: "test@example.com",
					Name:  "testuser",
				}
				mockRepo.EXPECT().
					GetUserByEmail("test@example.com").
					Return(user, nil)

				mockRepo.EXPECT().
					ConfirmForgotPassword(ctx, "testuser", "123456", "NewPassword123!").
					Return(nil)

				mockRepo.EXPECT().
					UpdateUser(gomock.Any()).
					DoAndReturn(func(u *users.User) error {
						assert.NotEmpty(t, u.Password)
						return nil
					})
			},
			expectedError: "",
		},
		{
			name:             "Weak Password",
			email:            "test@example.com",
			confirmationCode: "123456",
			newPassword:      "weak",
			setupMocks:       func() {},
			expectedError:    "password does not meet strength requirements",
		},
		{
			name:             "User Not Found",
			email:            "nonexistent@example.com",
			confirmationCode: "123456",
			newPassword:      "NewPassword123!",
			setupMocks: func() {
				mockRepo.EXPECT().
					GetUserByEmail("nonexistent@example.com").
					Return(nil, errors.New("not found"))
			},
			expectedError: "invalid request",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMocks()

			err := service.ResetPassword(ctx, tt.email, tt.confirmationCode, tt.newPassword)

			if tt.expectedError != "" {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedError)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAuthService_GetUserFromToken(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockRepository(ctrl)
	cfg := &config.Config{}
	service := NewAuthService(mockRepo, cfg)

	ctx := context.Background()

	t.Run("Successful Get User", func(t *testing.T) {
		emailAttr := "email"
		emailValue := "test@example.com"
		cognitoOutput := &types.GetUserOutput{
			Username: strPtr("testuser"),
			UserAttributes: []types.AttributeType{
				{
					Name:  &emailAttr,
					Value: &emailValue,
				},
			},
		}
		mockRepo.EXPECT().
			GetUser(ctx, "access-token").
			Return(cognitoOutput, nil)

		user := &users.User{
			ID:       1,
			Email:    "test@example.com",
			Name:     "testuser",
			IsActive: true,
		}
		mockRepo.EXPECT().
			GetUserByEmail("test@example.com").
			Return(user, nil)

		authUser, err := service.GetUserFromToken(ctx, "access-token")

		assert.NoError(t, err)
		assert.NotNil(t, authUser)
		assert.Equal(t, uint(1), authUser.ID)
		assert.Equal(t, "test@example.com", authUser.Email)
		assert.Equal(t, "testuser", authUser.Username)
	})

	t.Run("Invalid Token", func(t *testing.T) {
		mockRepo.EXPECT().
			GetUser(ctx, "invalid-token").
			Return(nil, errors.New("invalid token"))

		authUser, err := service.GetUserFromToken(ctx, "invalid-token")

		assert.Error(t, err)
		assert.Nil(t, authUser)
	})
}

// Helper function
func strPtr(s string) *string {
	return &s
}
