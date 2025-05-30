package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/asakuno/huma-sample/app/modules/auth/mocks"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/humatest"
	"github.com/golang/mock/gomock"
	"github.com/stretchr/testify/assert"
)

func TestController_SignUp(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockService := mocks.NewMockService(ctrl)
	controller := NewController(mockService)

	tests := []struct {
		name         string
		input        SignUpRequest
		setupMocks   func()
		expectedCode int
		checkBody    func(t *testing.T, body map[string]interface{})
	}{
		{
			name: "Successful SignUp",
			input: SignUpRequest{
				Email:    "test@example.com",
				Username: "testuser",
				Password: "ValidPassword123!",
				Name:     "Test User",
			},
			setupMocks: func() {
				userID := "cognito-123"
				mockService.EXPECT().
					SignUp(gomock.Any(), "test@example.com", "testuser", "ValidPassword123!", "Test User").
					Return(&userID, nil)
			},
			expectedCode: 200,
			checkBody: func(t *testing.T, body map[string]interface{}) {
				assert.True(t, body["success"].(bool))
				assert.Contains(t, body["message"], "successfully")
				assert.Equal(t, "cognito-123", body["user_id"])
			},
		},
		{
			name: "SignUp Error",
			input: SignUpRequest{
				Email:    "test@example.com",
				Username: "testuser",
				Password: "weak",
				Name:     "Test User",
			},
			setupMocks: func() {
				mockService.EXPECT().
					SignUp(gomock.Any(), "test@example.com", "testuser", "weak", "Test User").
					Return(nil, errors.New("password does not meet requirements"))
			},
			expectedCode: 400,
			checkBody: func(t *testing.T, body map[string]interface{}) {
				assert.Contains(t, body["message"], "password does not meet requirements")
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMocks()

			ctx := context.Background()
			resp, err := controller.SignUp(ctx, &tt.input)

			if tt.expectedCode == 200 {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				tt.checkBody(t, map[string]interface{}{
					"success": resp.Body.Success,
					"message": resp.Body.Message,
					"user_id": resp.Body.UserID,
				})
			} else {
				assert.Error(t, err)
				humaErr, ok := err.(huma.StatusError)
				assert.True(t, ok)
				assert.Equal(t, tt.expectedCode, humaErr.GetStatus())
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
		name         string
		input        LoginRequest
		setupMocks   func()
		expectedCode int
	}{
		{
			name: "Successful Login",
			input: LoginRequest{
				Email:    "test@example.com",
				Password: "ValidPassword123!",
			},
			setupMocks: func() {
				authUser := &AuthUser{
					ID:       1,
					Email:    "test@example.com",
					Username: "testuser",
				}
				tokenPair := &TokenPair{
					AccessToken:  "access-token",
					RefreshToken: "refresh-token",
					TokenType:    "Bearer",
					ExpiresIn:    3600,
				}
				mockService.EXPECT().
					Login(gomock.Any(), "test@example.com", "ValidPassword123!").
					Return(authUser, tokenPair, nil)
			},
			expectedCode: 200,
		},
		{
			name: "Invalid Credentials",
			input: LoginRequest{
				Email:    "test@example.com",
				Password: "WrongPassword",
			},
			setupMocks: func() {
				mockService.EXPECT().
					Login(gomock.Any(), "test@example.com", "WrongPassword").
					Return(nil, nil, errors.New("invalid credentials"))
			},
			expectedCode: 401,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMocks()

			ctx := context.Background()
			resp, err := controller.Login(ctx, &tt.input)

			if tt.expectedCode == 200 {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.NotEmpty(t, resp.Body.Tokens.AccessToken)
			} else {
				assert.Error(t, err)
				humaErr, ok := err.(huma.StatusError)
				assert.True(t, ok)
				assert.Equal(t, tt.expectedCode, humaErr.GetStatus())
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
		name         string
		input        VerifyEmailRequest
		setupMocks   func()
		expectedCode int
	}{
		{
			name: "Successful Verification",
			input: VerifyEmailRequest{
				Email:            "test@example.com",
				ConfirmationCode: "123456",
			},
			setupMocks: func() {
				mockService.EXPECT().
					VerifyEmail(gomock.Any(), "test@example.com", "123456").
					Return(nil)
			},
			expectedCode: 200,
		},
		{
			name: "Invalid Code",
			input: VerifyEmailRequest{
				Email:            "test@example.com",
				ConfirmationCode: "000000",
			},
			setupMocks: func() {
				mockService.EXPECT().
					VerifyEmail(gomock.Any(), "test@example.com", "000000").
					Return(errors.New("invalid confirmation code"))
			},
			expectedCode: 400,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMocks()

			ctx := context.Background()
			resp, err := controller.VerifyEmail(ctx, &tt.input)

			if tt.expectedCode == 200 {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.True(t, resp.Body.Success)
			} else {
				assert.Error(t, err)
				humaErr, ok := err.(huma.StatusError)
				assert.True(t, ok)
				assert.Equal(t, tt.expectedCode, humaErr.GetStatus())
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
		name         string
		input        RefreshTokenRequest
		setupMocks   func()
		expectedCode int
	}{
		{
			name: "Successful Refresh",
			input: RefreshTokenRequest{
				RefreshToken: "valid-refresh-token",
			},
			setupMocks: func() {
				tokenPair := &TokenPair{
					AccessToken: "new-access-token",
					TokenType:   "Bearer",
					ExpiresIn:   3600,
				}
				mockService.EXPECT().
					RefreshToken(gomock.Any(), "valid-refresh-token").
					Return(tokenPair, nil)
			},
			expectedCode: 200,
		},
		{
			name: "Invalid Refresh Token",
			input: RefreshTokenRequest{
				RefreshToken: "invalid-token",
			},
			setupMocks: func() {
				mockService.EXPECT().
					RefreshToken(gomock.Any(), "invalid-token").
					Return(nil, errors.New("invalid refresh token"))
			},
			expectedCode: 401,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMocks()

			ctx := context.Background()
			resp, err := controller.RefreshToken(ctx, &tt.input)

			if tt.expectedCode == 200 {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.NotEmpty(t, resp.Body.Tokens.AccessToken)
			} else {
				assert.Error(t, err)
				humaErr, ok := err.(huma.StatusError)
				assert.True(t, ok)
				assert.Equal(t, tt.expectedCode, humaErr.GetStatus())
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
		name         string
		input        ForgotPasswordRequest
		setupMocks   func()
		expectedCode int
	}{
		{
			name: "Successful Request",
			input: ForgotPasswordRequest{
				Email: "test@example.com",
			},
			setupMocks: func() {
				mockService.EXPECT().
					ForgotPassword(gomock.Any(), "test@example.com").
					Return(nil)
			},
			expectedCode: 200,
		},
		{
			name: "Service Error",
			input: ForgotPasswordRequest{
				Email: "test@example.com",
			},
			setupMocks: func() {
				mockService.EXPECT().
					ForgotPassword(gomock.Any(), "test@example.com").
					Return(errors.New("service error"))
			},
			expectedCode: 400,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMocks()

			ctx := context.Background()
			resp, err := controller.ForgotPassword(ctx, &tt.input)

			if tt.expectedCode == 200 {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.True(t, resp.Body.Success)
			} else {
				assert.Error(t, err)
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
		name         string
		input        ResetPasswordRequest
		setupMocks   func()
		expectedCode int
	}{
		{
			name: "Successful Reset",
			input: ResetPasswordRequest{
				Email:            "test@example.com",
				ConfirmationCode: "123456",
				NewPassword:      "NewPassword123!",
			},
			setupMocks: func() {
				mockService.EXPECT().
					ResetPassword(gomock.Any(), "test@example.com", "123456", "NewPassword123!").
					Return(nil)
			},
			expectedCode: 200,
		},
		{
			name: "Invalid Code",
			input: ResetPasswordRequest{
				Email:            "test@example.com",
				ConfirmationCode: "000000",
				NewPassword:      "NewPassword123!",
			},
			setupMocks: func() {
				mockService.EXPECT().
					ResetPassword(gomock.Any(), "test@example.com", "000000", "NewPassword123!").
					Return(errors.New("invalid confirmation code"))
			},
			expectedCode: 400,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.setupMocks()

			ctx := context.Background()
			resp, err := controller.ResetPassword(ctx, &tt.input)

			if tt.expectedCode == 200 {
				assert.NoError(t, err)
				assert.NotNil(t, resp)
				assert.True(t, resp.Body.Success)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func TestController_Logout(t *testing.T) {
	ctrl := gomock.NewController(t)
	defer ctrl.Finish()

	mockService := mocks.NewMockService(ctrl)
	controller := NewController(mockService)

	t.Run("Successful Logout", func(t *testing.T) {
		input := LogoutRequest{}
		ctx := context.Background()

		resp, err := controller.Logout(ctx, &input)

		assert.NoError(t, err)
		assert.NotNil(t, resp)
		assert.True(t, resp.Body.Success)
		assert.Contains(t, resp.Body.Message, "Logged out successfully")
	})
}
