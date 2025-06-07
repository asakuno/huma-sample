package tests

import (
	"context"
	"testing"

	"github.com/asakuno/huma-sample/app/config"
	"github.com/asakuno/huma-sample/app/modules/auth"
	"github.com/asakuno/huma-sample/app/modules/users"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// TestConfig holds test configuration
type TestConfig struct {
	DB              *gorm.DB
	Repository      auth.Repository
	Service         auth.Service
	Controller      *auth.Controller
	TestUserEmail   string
	TestUserID      uint
	TestPassword    string
}

// SetupTestDB creates an in-memory SQLite database for testing
func SetupTestDB(t *testing.T) *gorm.DB {
	db, err := gorm.Open(sqlite.Open(":memory:"), &gorm.Config{
		Logger: logger.New(
			nil, // writer
			logger.Config{
				LogLevel: logger.Silent,
			},
		),
	})
	if err != nil {
		t.Fatalf("Failed to create test database: %v", err)
	}

	// Auto migrate test tables
	err = db.AutoMigrate(&users.User{})
	if err != nil {
		t.Fatalf("Failed to migrate test database: %v", err)
	}

	return db
}

// SetupTestConfig creates a complete test configuration with all components
func SetupTestConfig(t *testing.T) *TestConfig {
	db := SetupTestDB(t)

	// Create mock repository (we'll implement this for unit tests)
	repo := NewMockRepository()

	// Create service with relaxed password rules for testing
	passwordRules := auth.PasswordRules{
		MinLength:        6,
		MaxLength:        128,
		RequireUppercase: false,
		RequireLowercase: false,
		RequireNumbers:   false,
		RequireSymbols:   false,
	}
	service := auth.NewAuthService(repo, passwordRules)

	// Create controller
	controller := auth.NewController(service)

	return &TestConfig{
		DB:            db,
		Repository:    repo,
		Service:       service,
		Controller:    controller,
		TestUserEmail: "test@example.com",
		TestUserID:    1,
		TestPassword:  "testpass123",
	}
}

// CreateTestUser creates a test user in the database
func (tc *TestConfig) CreateTestUser(t *testing.T) *users.User {
	user := &users.User{
		Email:    tc.TestUserEmail,
		Name:     "Test User",
		Password: "$2a$14$ajq8Q7fbtFRQvXpdCq7Jcuy.Rp/9m5L6cKc6LjZCLtzYx9VRgwC6e", // hashedpassword
		IsActive: true,
	}

	err := tc.DB.Create(user).Error
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	tc.TestUserID = user.ID
	return user
}

// CleanupTestDB cleans up the test database
func (tc *TestConfig) CleanupTestDB(t *testing.T) {
	sqlDB, err := tc.DB.DB()
	if err != nil {
		t.Errorf("Failed to get SQL DB: %v", err)
		return
	}
	sqlDB.Close()
}

// MockRepository implements auth.Repository for testing
type MockRepository struct {
	users          map[string]*users.User
	cognitoUserID  string
	shouldFail     bool
	failureMessage string
}

// NewMockRepository creates a new mock repository
func NewMockRepository() *MockRepository {
	return &MockRepository{
		users:         make(map[string]*users.User),
		cognitoUserID: "mock-cognito-user-id",
		shouldFail:    false,
	}
}

// SetFailure configures the mock to fail with an error
func (m *MockRepository) SetFailure(shouldFail bool, message string) {
	m.shouldFail = shouldFail
	m.failureMessage = message
}

// AddMockUser adds a user to the mock repository
func (m *MockRepository) AddMockUser(user *users.User) {
	m.users[user.Email] = user
}

// Mock implementation of Repository interface
func (m *MockRepository) SignUp(ctx context.Context, email, username, password string) (*string, error) {
	if m.shouldFail {
		return nil, &config.MockError{Message: m.failureMessage}
	}
	return &m.cognitoUserID, nil
}

func (m *MockRepository) ConfirmSignUp(ctx context.Context, username, confirmationCode string) error {
	if m.shouldFail {
		return &config.MockError{Message: m.failureMessage}
	}
	return nil
}

func (m *MockRepository) SignIn(ctx context.Context, email, password string) (*auth.CognitoTokens, error) {
	if m.shouldFail {
		return nil, &config.MockError{Message: m.failureMessage}
	}
	
	tokens := &auth.CognitoTokens{
		AccessToken:  "mock-access-token",
		IDToken:      "mock-id-token",
		RefreshToken: "mock-refresh-token",
		ExpiresIn:    3600,
	}
	return tokens, nil
}

func (m *MockRepository) RefreshToken(ctx context.Context, refreshToken string) (*auth.CognitoTokens, error) {
	if m.shouldFail {
		return nil, &config.MockError{Message: m.failureMessage}
	}
	
	tokens := &auth.CognitoTokens{
		AccessToken: "mock-new-access-token",
		ExpiresIn:   3600,
	}
	return tokens, nil
}

func (m *MockRepository) ForgotPassword(ctx context.Context, username string) error {
	if m.shouldFail {
		return &config.MockError{Message: m.failureMessage}
	}
	return nil
}

func (m *MockRepository) ConfirmForgotPassword(ctx context.Context, username, confirmationCode, newPassword string) error {
	if m.shouldFail {
		return &config.MockError{Message: m.failureMessage}
	}
	return nil
}

func (m *MockRepository) ChangePassword(ctx context.Context, accessToken, currentPassword, newPassword string) error {
	if m.shouldFail {
		return &config.MockError{Message: m.failureMessage}
	}
	return nil
}

func (m *MockRepository) SignOut(ctx context.Context, accessToken string) error {
	if m.shouldFail {
		return &config.MockError{Message: m.failureMessage}
	}
	return nil
}

func (m *MockRepository) GetUser(ctx context.Context, accessToken string) (*cognitoidentityprovider.GetUserOutput, error) {
	if m.shouldFail {
		return nil, &config.MockError{Message: m.failureMessage}
	}
	
	// Return mock cognito user output
	output := &cognitoidentityprovider.GetUserOutput{
		Username: stringPtr("mock-username"),
		UserAttributes: []types.AttributeType{
			{
				Name:  stringPtr("email"),
				Value: stringPtr("test@example.com"),
			},
		},
	}
	return output, nil
}

func (m *MockRepository) GetUserByEmail(email string) (*users.User, error) {
	if m.shouldFail {
		return nil, &config.MockError{Message: m.failureMessage}
	}
	
	user, exists := m.users[email]
	if !exists {
		return nil, &config.MockError{Message: "User not found"}
	}
	return user, nil
}

func (m *MockRepository) GetUserByID(id uint) (*users.User, error) {
	if m.shouldFail {
		return nil, &config.MockError{Message: m.failureMessage}
	}
	
	for _, user := range m.users {
		if user.ID == id {
			return user, nil
		}
	}
	return nil, &config.MockError{Message: "User not found"}
}

func (m *MockRepository) CreateUser(user *users.User) error {
	if m.shouldFail {
		return &config.MockError{Message: m.failureMessage}
	}
	
	user.ID = uint(len(m.users) + 1)
	m.users[user.Email] = user
	return nil
}

func (m *MockRepository) UpdateUser(user *users.User) error {
	if m.shouldFail {
		return &config.MockError{Message: m.failureMessage}
	}
	
	m.users[user.Email] = user
	return nil
}

func (m *MockRepository) UpdateLastLogin(userID uint) error {
	if m.shouldFail {
		return &config.MockError{Message: m.failureMessage}
	}
	return nil
}

func (m *MockRepository) GetUserByUsername(username string) (*users.User, error) {
	if m.shouldFail {
		return nil, &config.MockError{Message: m.failureMessage}
	}
	
	for _, user := range m.users {
		if user.Name == username {
			return user, nil
		}
	}
	return nil, &config.MockError{Message: "User not found"}
}

func (m *MockRepository) DeleteUser(ctx context.Context, accessToken string) error {
	if m.shouldFail {
		return &config.MockError{Message: m.failureMessage}
	}
	return nil
}

// Helper function
func stringPtr(s string) *string {
	return &s
}