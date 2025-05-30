package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/asakuno/huma-sample/app/modules/auth/mocks"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestController_SignUp(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockService := mocks.NewMockService(ctrl)
	controller := NewController(mockService)

	tests := []struct {
		name        string
		input       *SignUpRequest
		setupMock   func()
		wantErr     bool
		wantSuccess bool
	}{
		{
			name: "successful signup",
			input: &SignUpRequest{
				Email:    "test@example.com",
				Username: "testuser",
				Password: "Password123!",
				Name:     "Test User",
			},
			setupMock: func() {
				userID := "user-123"
				mockService.EXPECT().
					SignUp(gomock.Any(), "test@example.com", "testuser", "Password123!", "Test User").
					Return(&userID, nil)
			},
			wantErr:     false,
			wantSuccess: true,
		},
		{
			name: "signup with existing email",
			input: &SignUpRequest{
				Email:    "existing@example.com",
				Username: "testuser",
				Password: "Password123!",
				Name:     "Test User",
			},
			setupMock: func() {
				mockService.EXPECT().
					SignUp(gomock.Any(), "existing@example.com", "testuser", "Password123!", "Test User").
					Return(nil, errors.New("user with this email already exists"))
			},
			wantErr:     true,
			wantSuccess: false,
		},
		{
			name: "signup with weak password",
			input: &SignUpRequest{
				Email:    "test@example.com",
				Username: "testuser",
				Password: "weak",
				Name:     "Test User",
			},
			setupMock: func() {
				mockService.EXPECT().
					SignUp(gomock.Any(), "test@example.com", "testuser", "weak", "Test User").
					Return(nil, errors.New("password does not meet strength requirements"))
			},
			wantErr:     true,
			wantSuccess: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()

			resp, err := controller.SignUp(context.Background(), tt.input)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.Equal(t, tt.wantSuccess, resp.Body.Success)
				assert.NotEmpty(t, resp.Body.Message)
			}
		})
	}
}

func TestController_VerifyEmail(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockService := mocks.NewMockService(ctrl)
	controller := NewController(mockService)

	tests := []struct {
		name      string
		input     *VerifyEmailRequest
		setupMock func()
		wantErr   bool
	}{
		{
			name: "successful verification",
			input: &VerifyEmailRequest{
				Email:            "test@example.com",
				ConfirmationCode: "123456",
			},
			setupMock: func() {
				mockService.EXPECT().
					VerifyEmail(gomock.Any(), "test@example.com", "123456").
					Return(nil)
			},
			wantErr: false,
		},
		{
			name: "invalid confirmation code",
			input: &VerifyEmailRequest{
				Email:            "test@example.com",
				ConfirmationCode: "000000",
			},
			setupMock: func() {
				mockService.EXPECT().
					VerifyEmail(gomock.Any(), "test@example.com", "000000").
					Return(errors.New("invalid confirmation code"))
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()

			resp, err := controller.VerifyEmail(context.Background(), tt.input)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.True(t, resp.Body.Success)
				assert.NotEmpty(t, resp.Body.Message)
			}
		})
	}
}

func TestController_Login(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockService := mocks.NewMockService(ctrl)
	controller := NewController(mockService)

	tests := []struct {
		name      string
		input     *LoginRequest
		setupMock func()
		wantErr   bool
	}{
		{
			name: "successful login",
			input: &LoginRequest{
				Email:    "test@example.com",
				Password: "Password123!",
			},
			setupMock: func() {
				authUser := &AuthUser{
					ID:            1,
					Email:         "test@example.com",
					Username:      "testuser",
					EmailVerified: true,
					IsActive:      true,
				}
				tokenPair := &TokenPair{
					AccessToken:  "access-token",
					RefreshToken: "refresh-token",
					TokenType:    "Bearer",
					ExpiresIn:    3600,
				}
				mockService.EXPECT().
					Login(gomock.Any(), "test@example.com", "Password123!").
					Return(authUser, tokenPair, nil)
			},
			wantErr: false,
		},
		{
			name: "invalid credentials",
			input: &LoginRequest{
				Email:    "test@example.com",
				Password: "WrongPassword",
			},
			setupMock: func() {
				mockService.EXPECT().
					Login(gomock.Any(), "test@example.com", "WrongPassword").
					Return(nil, nil, errors.New("invalid credentials"))
			},
			wantErr: true,
		},
		{
			name: "inactive user",
			input: &LoginRequest{
				Email:    "inactive@example.com",
				Password: "Password123!",
			},
			setupMock: func() {
				mockService.EXPECT().
					Login(gomock.Any(), "inactive@example.com", "Password123!").
					Return(nil, nil, errors.New("user account is not active"))
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()

			resp, err := controller.Login(context.Background(), tt.input)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.NotEmpty(t, resp.Body.User.Email)
				assert.NotEmpty(t, resp.Body.Tokens.AccessToken)
				assert.NotEmpty(t, resp.Body.Tokens.RefreshToken)
			}
		})
	}
}

func TestController_RefreshToken(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockService := mocks.NewMockService(ctrl)
	controller := NewController(mockService)

	tests := []struct {
		name      string
		input     *RefreshTokenRequest
		setupMock func()
		wantErr   bool
	}{
		{
			name: "successful token refresh",
			input: &RefreshTokenRequest{
				RefreshToken: "valid-refresh-token",
			},
			setupMock: func() {
				tokenPair := &TokenPair{
					AccessToken:  "new-access-token",
					RefreshToken: "new-refresh-token",
					TokenType:    "Bearer",
					ExpiresIn:    3600,
				}
				mockService.EXPECT().
					RefreshToken(gomock.Any(), "valid-refresh-token").
					Return(tokenPair, nil)
			},
			wantErr: false,
		},
		{
			name: "invalid refresh token",
			input: &RefreshTokenRequest{
				RefreshToken: "invalid-refresh-token",
			},
			setupMock: func() {
				mockService.EXPECT().
					RefreshToken(gomock.Any(), "invalid-refresh-token").
					Return(nil, errors.New("invalid refresh token"))
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()

			resp, err := controller.RefreshToken(context.Background(), tt.input)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.NotEmpty(t, resp.Body.Tokens.AccessToken)
			}
		})
	}
}

func TestController_ForgotPassword(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockService := mocks.NewMockService(ctrl)
	controller := NewController(mockService)

	tests := []struct {
		name      string
		input     *ForgotPasswordRequest
		setupMock func()
		wantErr   bool
	}{
		{
			name: "successful forgot password",
			input: &ForgotPasswordRequest{
				Email: "test@example.com",
			},
			setupMock: func() {
				mockService.EXPECT().
					ForgotPassword(gomock.Any(), "test@example.com").
					Return(nil)
			},
			wantErr: false,
		},
		{
			name: "non-existent email",
			input: &ForgotPasswordRequest{
				Email: "nonexistent@example.com",
			},
			setupMock: func() {
				mockService.EXPECT().
					ForgotPassword(gomock.Any(), "nonexistent@example.com").
					Return(nil) // Service returns nil even for non-existent emails
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()

			resp, err := controller.ForgotPassword(context.Background(), tt.input)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.True(t, resp.Body.Success)
				assert.NotEmpty(t, resp.Body.Message)
			}
		})
	}
}

func TestController_ResetPassword(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockService := mocks.NewMockService(ctrl)
	controller := NewController(mockService)

	tests := []struct {
		name      string
		input     *ResetPasswordRequest
		setupMock func()
		wantErr   bool
	}{
		{
			name: "successful password reset",
			input: &ResetPasswordRequest{
				Email:            "test@example.com",
				ConfirmationCode: "123456",
				NewPassword:      "NewPassword123!",
			},
			setupMock: func() {
				mockService.EXPECT().
					ResetPassword(gomock.Any(), "test@example.com", "123456", "NewPassword123!").
					Return(nil)
			},
			wantErr: false,
		},
		{
			name: "invalid confirmation code",
			input: &ResetPasswordRequest{
				Email:            "test@example.com",
				ConfirmationCode: "000000",
				NewPassword:      "NewPassword123!",
			},
			setupMock: func() {
				mockService.EXPECT().
					ResetPassword(gomock.Any(), "test@example.com", "000000", "NewPassword123!").
					Return(errors.New("invalid confirmation code"))
			},
			wantErr: true,
		},
		{
			name: "weak new password",
			input: &ResetPasswordRequest{
				Email:            "test@example.com",
				ConfirmationCode: "123456",
				NewPassword:      "weak",
			},
			setupMock: func() {
				mockService.EXPECT().
					ResetPassword(gomock.Any(), "test@example.com", "123456", "weak").
					Return(errors.New("password does not meet strength requirements"))
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()

			resp, err := controller.ResetPassword(context.Background(), tt.input)

			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.True(t, resp.Body.Success)
				assert.NotEmpty(t, resp.Body.Message)
			}
		})
	}
}

func TestController_Logout(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockService := mocks.NewMockService(ctrl)
	controller := NewController(mockService)

	tests := []struct {
		name      string
		input     *LogoutRequest
		setupMock func()
		wantErr   bool
	}{
		{
			name: "successful logout",
			input: &LogoutRequest{
				RefreshToken: "refresh-token",
			},
			setupMock: func() {
				// Currently, the controller doesn't call the service for logout
				// This is a placeholder for when authentication middleware is implemented
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMock()

			resp, err := controller.Logout(context.Background(), tt.input)

			assert.NoError(t, err)
			assert.NotNil(t, resp)
			assert.True(t, resp.Body.Success)
			assert.NotEmpty(t, resp.Body.Message)
		})
	}
}
