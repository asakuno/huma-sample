package auth

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/asakuno/huma-sample/app/config"
	"github.com/asakuno/huma-sample/app/modules/auth/mocks"
	"github.com/asakuno/huma-sample/app/modules/users"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestAuthService_SignUp(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockRepository(ctrl)
	cfg := &config.Config{
		Cognito: config.CognitoConfig{
			UserPoolID:  "test-pool",
			AppClientID: "test-client",
		},
	}
	service := NewAuthService(mockRepo, cfg)

	ctx := context.Background()

	tests := []struct {
		name         string
		email        string
		username     string
		password     string
		fullName     string
		setupMocks   func()
		wantErr      bool
		expectedErr  string
		wantUserID   *string
	}{
		{
			name:     "Successful signup",
			email:    "test@example.com",
			username: "testuser",
			password: "Password123!",
			fullName: "Test User",
			setupMocks: func() {
				// User doesn't exist
				mockRepo.EXPECT().GetUserByEmail("test@example.com").Return(nil, errors.New("not found"))
				
				// Cognito signup succeeds
				userID := "cognito-123"
				mockRepo.EXPECT().SignUp(ctx, "test@example.com", "testuser", "Password123!").Return(&userID, nil)
				
				// Database user creation succeeds
				mockRepo.EXPECT().CreateUser(gomock.Any()).DoAndReturn(func(user *users.User) error {
					assert.Equal(t, "test@example.com", user.Email)
					assert.Equal(t, "Test User", user.Name)
					assert.False(t, user.IsActive)
					return nil
				})
			},
			wantErr:    false,
			wantUserID: stringPtr("cognito-123"),
		},
		{
			name:     "Weak password",
			email:    "test@example.com",
			username: "testuser",
			password: "weak",
			fullName: "Test User",
			setupMocks: func() {
				// No mock calls expected
			},
			wantErr:     true,
			expectedErr: "password does not meet strength requirements",
		},
		{
			name:     "User already exists",
			email:    "existing@example.com",
			username: "existinguser",
			password: "Password123!",
			fullName: "Existing User",
			setupMocks: func() {
				mockRepo.EXPECT().GetUserByEmail("existing@example.com").Return(&users.User{
					Email: "existing@example.com",
				}, nil)
			},
			wantErr:     true,
			expectedErr: "user with this email already exists",
		},
		{
			name:     "Cognito signup fails",
			email:    "test@example.com",
			username: "testuser",
			password: "Password123!",
			fullName: "Test User",
			setupMocks: func() {
				mockRepo.EXPECT().GetUserByEmail("test@example.com").Return(nil, errors.New("not found"))
				mockRepo.EXPECT().SignUp(ctx, "test@example.com", "testuser", "Password123!").Return(nil, errors.New("cognito error"))
			},
			wantErr:     true,
			expectedErr: "cognito error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMocks()
			
			userID, err := service.SignUp(ctx, tt.email, tt.username, tt.password, tt.fullName)
			
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErr)
				assert.Nil(t, userID)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.wantUserID, userID)
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
		wantErr          bool
		expectedErr      string
	}{
		{
			name:             "Successful verification",
			email:            "test@example.com",
			confirmationCode: "123456",
			setupMocks: func() {
				user := &users.User{
					ID:       1,
					Email:    "test@example.com",
					Name:     "testuser",
					IsActive: false,
				}
				mockRepo.EXPECT().GetUserByEmail("test@example.com").Return(user, nil)
				mockRepo.EXPECT().ConfirmSignUp(ctx, "testuser", "123456").Return(nil)
				mockRepo.EXPECT().UpdateUser(gomock.Any()).DoAndReturn(func(u *users.User) error {
					assert.True(t, u.IsActive)
					return nil
				})
			},
			wantErr: false,
		},
		{
			name:             "User not found",
			email:            "notfound@example.com",
			confirmationCode: "123456",
			setupMocks: func() {
				mockRepo.EXPECT().GetUserByEmail("notfound@example.com").Return(nil, errors.New("not found"))
			},
			wantErr:     true,
			expectedErr: "user not found",
		},
		{
			name:             "Cognito confirmation fails",
			email:            "test@example.com",
			confirmationCode: "wrong",
			setupMocks: func() {
				user := &users.User{Name: "testuser"}
				mockRepo.EXPECT().GetUserByEmail("test@example.com").Return(user, nil)
				mockRepo.EXPECT().ConfirmSignUp(ctx, "testuser", "wrong").Return(errors.New("invalid code"))
			},
			wantErr:     true,
			expectedErr: "invalid code",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMocks()
			
			err := service.VerifyEmail(ctx, tt.email, tt.confirmationCode)
			
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErr)
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
		name        string
		email       string
		password    string
		setupMocks  func()
		wantErr     bool
		expectedErr string
		checkResult func(*AuthUser, *TokenPair)
	}{
		{
			name:     "Successful login",
			email:    "test@example.com",
			password: "Password123!",
			setupMocks: func() {
				user := &users.User{
					ID:        1,
					Email:     "test@example.com",
					Name:      "testuser",
					IsActive:  true,
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
				}
				mockRepo.EXPECT().GetUserByEmail("test@example.com").Return(user, nil)
				
				cognitoTokens := &CognitoTokens{
					AccessToken:  "access-token",
					RefreshToken: "refresh-token",
					IDToken:      "id-token",
					ExpiresIn:    3600,
				}
				mockRepo.EXPECT().SignIn(ctx, "testuser", "Password123!").Return(cognitoTokens, nil)
				mockRepo.EXPECT().UpdateLastLogin(uint(1)).Return(nil)
			},
			wantErr: false,
			checkResult: func(authUser *AuthUser, tokenPair *TokenPair) {
				assert.NotNil(t, authUser)
				assert.Equal(t, uint(1), authUser.ID)
				assert.Equal(t, "test@example.com", authUser.Email)
				assert.Equal(t, "testuser", authUser.Username)
				assert.True(t, authUser.EmailVerified)
				assert.True(t, authUser.IsActive)
				
				assert.NotNil(t, tokenPair)
				assert.Equal(t, "access-token", tokenPair.AccessToken)
				assert.Equal(t, "refresh-token", tokenPair.RefreshToken)
				assert.Equal(t, "Bearer", tokenPair.TokenType)
				assert.Equal(t, 3600, tokenPair.ExpiresIn)
			},
		},
		{
			name:     "User not found",
			email:    "notfound@example.com",
			password: "Password123!",
			setupMocks: func() {
				mockRepo.EXPECT().GetUserByEmail("notfound@example.com").Return(nil, errors.New("not found"))
			},
			wantErr:     true,
			expectedErr: "invalid credentials",
		},
		{
			name:     "User not active",
			email:    "inactive@example.com",
			password: "Password123!",
			setupMocks: func() {
				user := &users.User{
					Email:    "inactive@example.com",
					IsActive: false,
				}
				mockRepo.EXPECT().GetUserByEmail("inactive@example.com").Return(user, nil)
			},
			wantErr:     true,
			expectedErr: "user account is not active",
		},
		{
			name:     "Invalid password",
			email:    "test@example.com",
			password: "WrongPassword!",
			setupMocks: func() {
				user := &users.User{
					Email:    "test@example.com",
					Name:     "testuser",
					IsActive: true,
				}
				mockRepo.EXPECT().GetUserByEmail("test@example.com").Return(user, nil)
				mockRepo.EXPECT().SignIn(ctx, "testuser", "WrongPassword!").Return(nil, errors.New("invalid password"))
			},
			wantErr:     true,
			expectedErr: "invalid credentials",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMocks()
			
			authUser, tokenPair, err := service.Login(ctx, tt.email, tt.password)
			
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErr)
				assert.Nil(t, authUser)
				assert.Nil(t, tokenPair)
			} else {
				assert.NoError(t, err)
				if tt.checkResult != nil {
					tt.checkResult(authUser, tokenPair)
				}
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

	tests := []struct {
		name         string
		refreshToken string
		setupMocks   func()
		wantErr      bool
		expectedErr  string
		checkResult  func(*TokenPair)
	}{
		{
			name:         "Successful refresh",
			refreshToken: "valid-refresh-token",
			setupMocks: func() {
				cognitoTokens := &CognitoTokens{
					AccessToken: "new-access-token",
					IDToken:     "new-id-token",
					ExpiresIn:   3600,
				}
				mockRepo.EXPECT().RefreshToken(ctx, "valid-refresh-token").Return(cognitoTokens, nil)
			},
			wantErr: false,
			checkResult: func(tokenPair *TokenPair) {
				assert.NotNil(t, tokenPair)
				assert.Equal(t, "new-access-token", tokenPair.AccessToken)
				assert.Equal(t, "Bearer", tokenPair.TokenType)
				assert.Equal(t, 3600, tokenPair.ExpiresIn)
			},
		},
		{
			name:         "Invalid refresh token",
			refreshToken: "invalid-refresh-token",
			setupMocks: func() {
				mockRepo.EXPECT().RefreshToken(ctx, "invalid-refresh-token").Return(nil, errors.New("invalid token"))
			},
			wantErr:     true,
			expectedErr: "invalid token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMocks()
			
			tokenPair, err := service.RefreshToken(ctx, tt.refreshToken)
			
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErr)
				assert.Nil(t, tokenPair)
			} else {
				assert.NoError(t, err)
				if tt.checkResult != nil {
					tt.checkResult(tokenPair)
				}
			}
		})
	}
}

func TestAuthService_ForgotPassword(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockRepository(ctrl)
	cfg := &config.Config{}
	service := NewAuthService(mockRepo, cfg)

	ctx := context.Background()

	tests := []struct {
		name       string
		email      string
		setupMocks func()
		wantErr    bool
	}{
		{
			name:  "Successful forgot password - user exists",
			email: "test@example.com",
			setupMocks: func() {
				user := &users.User{
					Email: "test@example.com",
					Name:  "testuser",
				}
				mockRepo.EXPECT().GetUserByEmail("test@example.com").Return(user, nil)
				mockRepo.EXPECT().ForgotPassword(ctx, "testuser").Return(nil)
			},
			wantErr: false,
		},
		{
			name:  "User not found - should not return error",
			email: "notfound@example.com",
			setupMocks: func() {
				mockRepo.EXPECT().GetUserByEmail("notfound@example.com").Return(nil, errors.New("not found"))
			},
			wantErr: false, // Should not reveal if user exists
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMocks()
			
			err := service.ForgotPassword(ctx, tt.email)
			
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
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
		wantErr          bool
		expectedErr      string
	}{
		{
			name:             "Successful password reset",
			email:            "test@example.com",
			confirmationCode: "123456",
			newPassword:      "NewPassword123!",
			setupMocks: func() {
				user := &users.User{
					ID:    1,
					Email: "test@example.com",
					Name:  "testuser",
				}
				mockRepo.EXPECT().GetUserByEmail("test@example.com").Return(user, nil)
				mockRepo.EXPECT().ConfirmForgotPassword(ctx, "testuser", "123456", "NewPassword123!").Return(nil)
				mockRepo.EXPECT().UpdateUser(gomock.Any()).DoAndReturn(func(u *users.User) error {
					assert.NotEmpty(t, u.Password)
					return nil
				})
			},
			wantErr: false,
		},
		{
			name:             "Weak password",
			email:            "test@example.com",
			confirmationCode: "123456",
			newPassword:      "weak",
			setupMocks:       func() {},
			wantErr:          true,
			expectedErr:      "password does not meet strength requirements",
		},
		{
			name:             "User not found",
			email:            "notfound@example.com",
			confirmationCode: "123456",
			newPassword:      "NewPassword123!",
			setupMocks: func() {
				mockRepo.EXPECT().GetUserByEmail("notfound@example.com").Return(nil, errors.New("not found"))
			},
			wantErr:     true,
			expectedErr: "invalid request",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMocks()
			
			err := service.ResetPassword(ctx, tt.email, tt.confirmationCode, tt.newPassword)
			
			if tt.wantErr {
				assert.Error(t, err)
				assert.Contains(t, err.Error(), tt.expectedErr)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAuthService_Logout(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockRepository(ctrl)
	cfg := &config.Config{}
	service := NewAuthService(mockRepo, cfg)

	ctx := context.Background()

	tests := []struct {
		name        string
		accessToken string
		setupMocks  func()
		wantErr     bool
	}{
		{
			name:        "Successful logout",
			accessToken: "valid-access-token",
			setupMocks: func() {
				mockRepo.EXPECT().SignOut(ctx, "valid-access-token").Return(nil)
			},
			wantErr: false,
		},
		{
			name:        "Logout error",
			accessToken: "invalid-access-token",
			setupMocks: func() {
				mockRepo.EXPECT().SignOut(ctx, "invalid-access-token").Return(errors.New("logout error"))
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMocks()
			
			err := service.Logout(ctx, tt.accessToken)
			
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

// Helper function
func stringPtr(s string) *string {
	return &s
}
