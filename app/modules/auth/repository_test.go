package auth

import (
	"context"
	"errors"
	"testing"

	"github.com/asakuno/huma-sample/app/config"
	"github.com/asakuno/huma-sample/app/modules/users"
	"github.com/aws/aws-sdk-go-v2/aws"
	awsConfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
)

// Mock Cognito client for testing
type mockCognitoClient struct {
	SignUpFunc                 func(ctx context.Context, params *cognitoidentityprovider.SignUpInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.SignUpOutput, error)
	ConfirmSignUpFunc          func(ctx context.Context, params *cognitoidentityprovider.ConfirmSignUpInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.ConfirmSignUpOutput, error)
	InitiateAuthFunc           func(ctx context.Context, params *cognitoidentityprovider.InitiateAuthInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.InitiateAuthOutput, error)
	ForgotPasswordFunc         func(ctx context.Context, params *cognitoidentityprovider.ForgotPasswordInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.ForgotPasswordOutput, error)
	ConfirmForgotPasswordFunc  func(ctx context.Context, params *cognitoidentityprovider.ConfirmForgotPasswordInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.ConfirmForgotPasswordOutput, error)
	ChangePasswordFunc         func(ctx context.Context, params *cognitoidentityprovider.ChangePasswordInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.ChangePasswordOutput, error)
	GlobalSignOutFunc          func(ctx context.Context, params *cognitoidentityprovider.GlobalSignOutInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.GlobalSignOutOutput, error)
	DeleteUserFunc             func(ctx context.Context, params *cognitoidentityprovider.DeleteUserInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.DeleteUserOutput, error)
	GetUserFunc                func(ctx context.Context, params *cognitoidentityprovider.GetUserInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.GetUserOutput, error)
}

func (m *mockCognitoClient) SignUp(ctx context.Context, params *cognitoidentityprovider.SignUpInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.SignUpOutput, error) {
	if m.SignUpFunc != nil {
		return m.SignUpFunc(ctx, params, optFns...)
	}
	return nil, errors.New("SignUpFunc not implemented")
}

func (m *mockCognitoClient) ConfirmSignUp(ctx context.Context, params *cognitoidentityprovider.ConfirmSignUpInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.ConfirmSignUpOutput, error) {
	if m.ConfirmSignUpFunc != nil {
		return m.ConfirmSignUpFunc(ctx, params, optFns...)
	}
	return nil, errors.New("ConfirmSignUpFunc not implemented")
}

func (m *mockCognitoClient) InitiateAuth(ctx context.Context, params *cognitoidentityprovider.InitiateAuthInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.InitiateAuthOutput, error) {
	if m.InitiateAuthFunc != nil {
		return m.InitiateAuthFunc(ctx, params, optFns...)
	}
	return nil, errors.New("InitiateAuthFunc not implemented")
}

func (m *mockCognitoClient) ForgotPassword(ctx context.Context, params *cognitoidentityprovider.ForgotPasswordInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.ForgotPasswordOutput, error) {
	if m.ForgotPasswordFunc != nil {
		return m.ForgotPasswordFunc(ctx, params, optFns...)
	}
	return nil, errors.New("ForgotPasswordFunc not implemented")
}

func (m *mockCognitoClient) ConfirmForgotPassword(ctx context.Context, params *cognitoidentityprovider.ConfirmForgotPasswordInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.ConfirmForgotPasswordOutput, error) {
	if m.ConfirmForgotPasswordFunc != nil {
		return m.ConfirmForgotPasswordFunc(ctx, params, optFns...)
	}
	return nil, errors.New("ConfirmForgotPasswordFunc not implemented")
}

func (m *mockCognitoClient) ChangePassword(ctx context.Context, params *cognitoidentityprovider.ChangePasswordInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.ChangePasswordOutput, error) {
	if m.ChangePasswordFunc != nil {
		return m.ChangePasswordFunc(ctx, params, optFns...)
	}
	return nil, errors.New("ChangePasswordFunc not implemented")
}

func (m *mockCognitoClient) GlobalSignOut(ctx context.Context, params *cognitoidentityprovider.GlobalSignOutInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.GlobalSignOutOutput, error) {
	if m.GlobalSignOutFunc != nil {
		return m.GlobalSignOutFunc(ctx, params, optFns...)
	}
	return nil, errors.New("GlobalSignOutFunc not implemented")
}

func (m *mockCognitoClient) DeleteUser(ctx context.Context, params *cognitoidentityprovider.DeleteUserInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.DeleteUserOutput, error) {
	if m.DeleteUserFunc != nil {
		return m.DeleteUserFunc(ctx, params, optFns...)
	}
	return nil, errors.New("DeleteUserFunc not implemented")
}

func (m *mockCognitoClient) GetUser(ctx context.Context, params *cognitoidentityprovider.GetUserInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.GetUserOutput, error) {
	if m.GetUserFunc != nil {
		return m.GetUserFunc(ctx, params, optFns...)
	}
	return nil, errors.New("GetUserFunc not implemented")
}

// Setup test database
func setupTestDB(t *testing.T) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{})
	require.NoError(t, err)

	// Migrate test schema
	err = db.AutoMigrate(&users.User{})
	require.NoError(t, err)

	return db
}

func TestAuthRepository_SignUp(t *testing.T) {
	db := setupTestDB(t)
	
	tests := []struct {
		name            string
		email           string
		username        string
		password        string
		mockFunc        func() *mockCognitoClient
		expectedUserID  string
		expectedError   bool
	}{
		{
			name:     "Successful SignUp",
			email:    "test@example.com",
			username: "testuser",
			password: "TestPassword123!",
			mockFunc: func() *mockCognitoClient {
				return &mockCognitoClient{
					SignUpFunc: func(ctx context.Context, params *cognitoidentityprovider.SignUpInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.SignUpOutput, error) {
						userSub := "12345-abcde"
						return &cognitoidentityprovider.SignUpOutput{
							UserSub: &userSub,
						}, nil
					},
				}
			},
			expectedUserID: "12345-abcde",
			expectedError:  false,
		},
		{
			name:     "SignUp Error",
			email:    "test@example.com",
			username: "testuser",
			password: "TestPassword123!",
			mockFunc: func() *mockCognitoClient {
				return &mockCognitoClient{
					SignUpFunc: func(ctx context.Context, params *cognitoidentityprovider.SignUpInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.SignUpOutput, error) {
						return nil, errors.New("user already exists")
					},
				}
			},
			expectedUserID: "",
			expectedError:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := tt.mockFunc()
			repo := &AuthRepository{
				db:            db,
				cognitoClient: mockClient,
				userPoolID:    "test-pool",
				appClientID:   "test-client",
			}

			ctx := context.Background()
			userID, err := repo.SignUp(ctx, tt.email, tt.username, tt.password)

			if tt.expectedError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expectedUserID, *userID)
			}
		})
	}
}

func TestAuthRepository_SignIn(t *testing.T) {
	db := setupTestDB(t)
	
	tests := []struct {
		name          string
		username      string
		password      string
		mockFunc      func() *mockCognitoClient
		expectedError bool
	}{
		{
			name:     "Successful SignIn",
			username: "testuser",
			password: "TestPassword123!",
			mockFunc: func() *mockCognitoClient {
				return &mockCognitoClient{
					InitiateAuthFunc: func(ctx context.Context, params *cognitoidentityprovider.InitiateAuthInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.InitiateAuthOutput, error) {
						accessToken := "access-token"
						idToken := "id-token"
						refreshToken := "refresh-token"
						expiresIn := int32(3600)
						
						return &cognitoidentityprovider.InitiateAuthOutput{
							AuthenticationResult: &types.AuthenticationResultType{
								AccessToken:  &accessToken,
								IdToken:      &idToken,
								RefreshToken: &refreshToken,
								ExpiresIn:    expiresIn,
							},
						}, nil
					},
				}
			},
			expectedError: false,
		},
		{
			name:     "Invalid Credentials",
			username: "testuser",
			password: "WrongPassword",
			mockFunc: func() *mockCognitoClient {
				return &mockCognitoClient{
					InitiateAuthFunc: func(ctx context.Context, params *cognitoidentityprovider.InitiateAuthInput, optFns ...func(*cognitoidentityprovider.Options)) (*cognitoidentityprovider.InitiateAuthOutput, error) {
						return nil, errors.New("invalid credentials")
					},
				}
			},
			expectedError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockClient := tt.mockFunc()
			repo := &AuthRepository{
				db:            db,
				cognitoClient: mockClient,
				userPoolID:    "test-pool",
				appClientID:   "test-client",
			}

			ctx := context.Background()
			tokens, err := repo.SignIn(ctx, tt.username, tt.password)

			if tt.expectedError {
				assert.Error(t, err)
				assert.Nil(t, tokens)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, tokens)
				assert.Equal(t, "access-token", tokens.AccessToken)
				assert.Equal(t, "id-token", tokens.IDToken)
				assert.Equal(t, "refresh-token", tokens.RefreshToken)
			}
		})
	}
}

func TestAuthRepository_DatabaseOperations(t *testing.T) {
	db := setupTestDB(t)
	
	// Create a test user
	testUser := &users.User{
		Email:    "test@example.com",
		Name:     "testuser",
		Password: "$2a$10$abcdefghijklmnopqrstuvwxyz", // Mock hashed password
		IsActive: true,
	}
	err := db.Create(testUser).Error
	require.NoError(t, err)

	repo := &AuthRepository{
		db: db,
	}

	t.Run("GetUserByEmail", func(t *testing.T) {
		user, err := repo.GetUserByEmail("test@example.com")
		assert.NoError(t, err)
		assert.NotNil(t, user)
		assert.Equal(t, "test@example.com", user.Email)
		assert.Equal(t, "testuser", user.Name)

		// Test non-existent user
		user, err = repo.GetUserByEmail("nonexistent@example.com")
		assert.Error(t, err)
		assert.Nil(t, user)
	})

	t.Run("GetUserByUsername", func(t *testing.T) {
		user, err := repo.GetUserByUsername("testuser")
		assert.NoError(t, err)
		assert.NotNil(t, user)
		assert.Equal(t, "testuser", user.Name)
	})

	t.Run("GetUserByID", func(t *testing.T) {
		user, err := repo.GetUserByID(testUser.ID)
		assert.NoError(t, err)
		assert.NotNil(t, user)
		assert.Equal(t, testUser.ID, user.ID)
	})

	t.Run("UpdateLastLogin", func(t *testing.T) {
		err := repo.UpdateLastLogin(testUser.ID)
		assert.NoError(t, err)

		// Verify update
		var updatedUser users.User
		err = db.First(&updatedUser, testUser.ID).Error
		require.NoError(t, err)
		assert.NotNil(t, updatedUser.LastLoginAt)
	})
}

func TestCalculateSecretHash(t *testing.T) {
	username := "testuser"
	clientID := "test-client-id"
	clientSecret := "test-client-secret"

	hash := calculateSecretHash(username, clientID, clientSecret)
	assert.NotEmpty(t, hash)
	
	// Verify hash is consistent
	hash2 := calculateSecretHash(username, clientID, clientSecret)
	assert.Equal(t, hash, hash2)
	
	// Different inputs should produce different hashes
	hash3 := calculateSecretHash("different-user", clientID, clientSecret)
	assert.NotEqual(t, hash, hash3)
}
