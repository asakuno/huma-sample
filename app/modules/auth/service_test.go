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
)

func TestAuthService_SignUp(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockRepo := mocks.NewMockRepository(ctrl)
	cfg := &config.Config{
		JWT: config.JWTConfig{Secret: "test-secret"},
	}
	service := NewAuthService(mockRepo, cfg)

	tests := []struct {
		name      string
		email     string
		username  string
		password  string
		fullName  string
		setupMock func()
		wantErr   bool
		errMsg    string
	}{
		{
			name:     "successful signup",
			email:    "test@example.com",
			username: "testuser",
			password: "Password123!",
			fullName: "Test User",
			setupMock: func() {
				// Check if user exists
				mockRepo.EXPECT().
					GetUserByEmail("test@example.com").
					Return(nil, errors.New("user not found"))

				// Sign up with Cognito
				userID := "cognito-123"
				mockRepo.EXPECT().
					SignUp(gomock.Any(), "test@example.com", "testuser", "Password123!").
					Return(&userID, nil)

				// Create user in database
				mockRepo.EXPECT().
					CreateUser(gomock.Any()).
					DoAndReturn(func(user *users.User) error {
						assert.Equal(t, "test@example.com", user.Email)
						assert.Equal(t, "Test User", user.Name)
						assert.False(t, user.IsActive)
						return nil
					})
			},
			wantErr: false,
		},
		{
			name:     "weak password",
			email:    "test@example.com",
			username: "testuser",
			password: "weak",
			fullName: "Test User",
			setupMock: func() {
				// No mocks needed - validation fails before any calls
			},
			wantErr: true,
			errMsg:  "password does not meet strength requirements",
		},
		{
			name:     "user already exists",
			email:    "existing@example.com",
			username: "existinguser",
			password: "Password123!",
			fullName: "Existing User",
			setupMock: func() {
				mockRepo.EXPECT().
					GetUserByEmail("existing@example.com").
					Return(&users.User{Email: "existing@example.com"}, nil)
			},
			wantErr: true,
			errMsg:  "user with this email already exists",
		},
		{
			name:     "cognito signup fails",
			email:    "test@example.com",
			username: "testuser",
			password: "Password123!",
			fullName: "Test User",
			setupMock: func() {
				mockRepo.EXPECT().
					GetUserByEmail("test@example.com").
					Return(nil, errors.New("user not found"))

				mockRepo.EXPECT().
					SignUp(gomock.Any(), "test@example.com", "testuser", "Password123!").
					Return(nil, errors.New("cognito error"))
			},
			wantErr: true,
			errMsg:  "cognito error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()

			userID, err := service.SignUp(context.Background(), tt.email, tt.username, tt.password, tt.fullName)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, userID)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
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

	tests := []struct {
		name             string
		email            string
		confirmationCode string
		setupMock        func()
		wantErr          bool
		errMsg           string
	}{
		{
			name:             "successful verification",
			email:            "test@example.com",
			confirmationCode: "123456",
			setupMock: func() {
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
					ConfirmSignUp(gomock.Any(), "testuser", "123456").
					Return(nil)

				mockRepo.EXPECT().
					UpdateUser(gomock.Any()).
					DoAndReturn(func(u *users.User) error {
						assert.True(t, u.IsActive)
						return nil
					})
			},
			wantErr: false,
		},
		{
			name:             "user not found",
			email:            "nonexistent@example.com",
			confirmationCode: "123456",
			setupMock: func() {
				mockRepo.EXPECT().
					GetUserByEmail("nonexistent@example.com").
					Return(nil, errors.New("user not found"))
			},
			wantErr: true,
			errMsg:  "user not found",
		},
		{
			name:             "invalid confirmation code",
			email:            "test@example.com",
			confirmationCode: "000000",
			setupMock: func() {
				user := &users.User{
					Email: "test@example.com",
					Name:  "testuser",
				}
				mockRepo.EXPECT().
					GetUserByEmail("test@example.com").
					Return(user, nil)

				mockRepo.EXPECT().
					ConfirmSignUp(gomock.Any(), "testuser", "000000").
					Return(errors.New("invalid code"))
			},
			wantErr: true,
			errMsg:  "invalid code",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()

			err := service.VerifyEmail(context.Background(), tt.email, tt.confirmationCode)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
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

	tests := []struct {
		name      string
		email     string
		password  string
		setupMock func()
		wantErr   bool
		errMsg    string
	}{
		{
			name:     "successful login",
			email:    "test@example.com",
			password: "Password123!",
			setupMock: func() {
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
					SignIn(gomock.Any(), "testuser", "Password123!").
					Return(cognitoTokens, nil)

				mockRepo.EXPECT().
					UpdateLastLogin(uint(1)).
					Return(nil)
			},
			wantErr: false,
		},
		{
			name:     "user not found",
			email:    "nonexistent@example.com",
			password: "Password123!",
			setupMock: func() {
				mockRepo.EXPECT().
					GetUserByEmail("nonexistent@example.com").
					Return(nil, errors.New("user not found"))
			},
			wantErr: true,
			errMsg:  "invalid credentials",
		},
		{
			name:     "inactive user",
			email:    "inactive@example.com",
			password: "Password123!",
			setupMock: func() {
				user := &users.User{
					Email:    "inactive@example.com",
					Name:     "inactiveuser",
					IsActive: false,
				}
				mockRepo.EXPECT().
					GetUserByEmail("inactive@example.com").
					Return(user, nil)
			},
			wantErr: true,
			errMsg:  "user account is not active",
		},
		{
			name:     "wrong password",
			email:    "test@example.com",
			password: "WrongPassword",
			setupMock: func() {
				user := &users.User{
					Email:    "test@example.com",
					Name:     "testuser",
					IsActive: true,
				}
				mockRepo.EXPECT().
					GetUserByEmail("test@example.com").
					Return(user, nil)

				mockRepo.EXPECT().
					SignIn(gomock.Any(), "testuser", "WrongPassword").
					Return(nil, errors.New("invalid password"))
			},
			wantErr: true,
			errMsg:  "invalid credentials",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()

			authUser, tokenPair, err := service.Login(context.Background(), tt.email, tt.password)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, authUser)
				assert.Nil(t, tokenPair)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, authUser)
				assert.NotNil(t, tokenPair)
				assert.Equal(t, tt.email, authUser.Email)
				assert.NotEmpty(t, tokenPair.AccessToken)
				assert.NotEmpty(t, tokenPair.RefreshToken)
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

	tests := []struct {
		name         string
		refreshToken string
		setupMock    func()
		wantErr      bool
		errMsg       string
	}{
		{
			name:         "successful refresh",
			refreshToken: "valid-refresh-token",
			setupMock: func() {
				cognitoTokens := &CognitoTokens{
					AccessToken: "new-access-token",
					IDToken:     "new-id-token",
					ExpiresIn:   3600,
				}
				mockRepo.EXPECT().
					RefreshToken(gomock.Any(), "valid-refresh-token").
					Return(cognitoTokens, nil)
			},
			wantErr: false,
		},
		{
			name:         "invalid refresh token",
			refreshToken: "invalid-refresh-token",
			setupMock: func() {
				mockRepo.EXPECT().
					RefreshToken(gomock.Any(), "invalid-refresh-token").
					Return(nil, errors.New("invalid token"))
			},
			wantErr: true,
			errMsg:  "invalid token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()

			tokenPair, err := service.RefreshToken(context.Background(), tt.refreshToken)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, tokenPair)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, tokenPair)
				assert.NotEmpty(t, tokenPair.AccessToken)
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

	tests := []struct {
		name      string
		email     string
		setupMock func()
		wantErr   bool
	}{
		{
			name:  "successful forgot password",
			email: "test@example.com",
			setupMock: func() {
				user := &users.User{
					Email: "test@example.com",
					Name:  "testuser",
				}
				mockRepo.EXPECT().
					GetUserByEmail("test@example.com").
					Return(user, nil)

				mockRepo.EXPECT().
					ForgotPassword(gomock.Any(), "testuser").
					Return(nil)
			},
			wantErr: false,
		},
		{
			name:  "user not found - returns nil",
			email: "nonexistent@example.com",
			setupMock: func() {
				mockRepo.EXPECT().
					GetUserByEmail("nonexistent@example.com").
					Return(nil, errors.New("user not found"))
			},
			wantErr: false, // Service returns nil to not reveal user existence
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()

			err := service.ForgotPassword(context.Background(), tt.email)

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

	tests := []struct {
		name             string
		email            string
		confirmationCode string
		newPassword      string
		setupMock        func()
		wantErr          bool
		errMsg           string
	}{
		{
			name:             "successful password reset",
			email:            "test@example.com",
			confirmationCode: "123456",
			newPassword:      "NewPassword123!",
			setupMock: func() {
				user := &users.User{
					ID:    1,
					Email: "test@example.com",
					Name:  "testuser",
				}
				mockRepo.EXPECT().
					GetUserByEmail("test@example.com").
					Return(user, nil)

				mockRepo.EXPECT().
					ConfirmForgotPassword(gomock.Any(), "testuser", "123456", "NewPassword123!").
					Return(nil)

				mockRepo.EXPECT().
					UpdateUser(gomock.Any()).
					DoAndReturn(func(u *users.User) error {
						assert.NotEmpty(t, u.Password)
						return nil
					})
			},
			wantErr: false,
		},
		{
			name:             "weak password",
			email:            "test@example.com",
			confirmationCode: "123456",
			newPassword:      "weak",
			setupMock: func() {
				// No mocks needed - validation fails before any calls
			},
			wantErr: true,
			errMsg:  "password does not meet strength requirements",
		},
		{
			name:             "user not found",
			email:            "nonexistent@example.com",
			confirmationCode: "123456",
			newPassword:      "NewPassword123!",
			setupMock: func() {
				mockRepo.EXPECT().
					GetUserByEmail("nonexistent@example.com").
					Return(nil, errors.New("user not found"))
			},
			wantErr: true,
			errMsg:  "invalid request",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()

			err := service.ResetPassword(context.Background(), tt.email, tt.confirmationCode, tt.newPassword)

			if tt.wantErr {
				assert.Error(t, err)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
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

	tests := []struct {
		name        string
		accessToken string
		setupMock   func()
		wantErr     bool
	}{
		{
			name:        "successful logout",
			accessToken: "valid-access-token",
			setupMock: func() {
				mockRepo.EXPECT().
					SignOut(gomock.Any(), "valid-access-token").
					Return(nil)
			},
			wantErr: false,
		},
		{
			name:        "logout error",
			accessToken: "invalid-access-token",
			setupMock: func() {
				mockRepo.EXPECT().
					SignOut(gomock.Any(), "invalid-access-token").
					Return(errors.New("logout failed"))
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()

			err := service.Logout(context.Background(), tt.accessToken)

			if tt.wantErr {
				assert.Error(t, err)
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

	tests := []struct {
		name        string
		accessToken string
		setupMock   func()
		wantErr     bool
		errMsg      string
	}{
		{
			name:        "successful get user",
			accessToken: "valid-access-token",
			setupMock: func() {
				email := "test@example.com"
				cognitoOutput := &types.GetUserOutput{
					UserAttributes: []types.AttributeType{
						{Name: &[]string{"email"}[0], Value: &email},
					},
				}
				mockRepo.EXPECT().
					GetUser(gomock.Any(), "valid-access-token").
					Return(cognitoOutput, nil)

				user := &users.User{
					ID:        1,
					Email:     "test@example.com",
					Name:      "testuser",
					IsActive:  true,
					CreatedAt: time.Now(),
					UpdatedAt: time.Now(),
				}
				mockRepo.EXPECT().
					GetUserByEmail("test@example.com").
					Return(user, nil)
			},
			wantErr: false,
		},
		{
			name:        "invalid token",
			accessToken: "invalid-token",
			setupMock: func() {
				mockRepo.EXPECT().
					GetUser(gomock.Any(), "invalid-token").
					Return(nil, errors.New("invalid token"))
			},
			wantErr: true,
			errMsg:  "invalid token",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()

			authUser, err := service.GetUserFromToken(context.Background(), tt.accessToken)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, authUser)
				if tt.errMsg != "" {
					assert.Contains(t, err.Error(), tt.errMsg)
				}
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, authUser)
				assert.NotEmpty(t, authUser.Email)
			}
		})
	}
}
