package tests

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/asakuno/huma-sample/app/config"
	"github.com/asakuno/huma-sample/app/modules/auth"
	"github.com/asakuno/huma-sample/app/modules/users"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider"
	"github.com/aws/aws-sdk-go-v2/service/cognitoidentityprovider/types"
	"github.com/danielgtaylor/huma/v2"
	"github.com/danielgtaylor/huma/v2/adapters/humachi"
	"github.com/go-chi/chi/v5"
	"gorm.io/driver/sqlite"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

// IntegrationTestConfig holds integration test configuration
type IntegrationTestConfig struct {
	DB     *gorm.DB
	API    huma.API
	Router *chi.Mux
	Config *config.Config
}

// SetupIntegrationTest creates a complete integration test environment
func SetupIntegrationTest(t *testing.T) *IntegrationTestConfig {
	// Create in-memory database
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

	// Auto migrate
	err = db.AutoMigrate(&users.User{})
	if err != nil {
		t.Fatalf("Failed to migrate test database: %v", err)
	}

	// Create test config
	testConfig := &config.Config{
		AppName: "huma-sample-test",
		AppEnv:  "test",
		Port:    "8888",
		JWT: config.JWTConfig{
			Secret: "test-jwt-secret",
		},
		Cognito: config.CognitoConfig{
			UserPoolID:    "test-pool",
			AppClientID:   "test-client",
			UseLocal:      true,
			LocalEndpoint: "http://localhost:9229",
		},
	}

	// Create router and API
	router := chi.NewMux()
	api := humachi.New(router, huma.DefaultConfig("Test API", "1.0.0"))

	// Register auth routes with real repository
	repo := NewIntegrationRepository(db)
	passwordRules := auth.DefaultPasswordRules()
	service := auth.NewAuthService(repo, passwordRules)
	controller := auth.NewController(service)

	// Register routes
	authGroup := huma.NewGroup(api, "/auth")
	huma.Post(authGroup, "/signup", controller.SignUp)
	huma.Post(authGroup, "/login", controller.Login)
	huma.Get(authGroup, "/profile", controller.GetProfile)
	huma.Post(authGroup, "/refresh", controller.RefreshToken)
	huma.Post(authGroup, "/change-password", controller.ChangePassword)
	huma.Get(authGroup, "/health", controller.HealthCheck)

	return &IntegrationTestConfig{
		DB:     db,
		API:    api,
		Router: router,
		Config: testConfig,
	}
}

// CleanupIntegrationTest cleans up integration test resources
func (itc *IntegrationTestConfig) CleanupIntegrationTest(t *testing.T) {
	sqlDB, err := itc.DB.DB()
	if err != nil {
		t.Errorf("Failed to get SQL DB: %v", err)
		return
	}
	sqlDB.Close()
}

// IntegrationRepository is a real repository implementation for integration tests
type IntegrationRepository struct {
	db *gorm.DB
}

// NewIntegrationRepository creates a new integration repository
func NewIntegrationRepository(db *gorm.DB) *IntegrationRepository {
	return &IntegrationRepository{db: db}
}

// Integration repository implementations (simplified for testing)
func (r *IntegrationRepository) SignUp(ctx context.Context, email, username, password string) (*string, error) {
	cognitoID := "integration-test-cognito-id"
	return &cognitoID, nil
}

func (r *IntegrationRepository) ConfirmSignUp(ctx context.Context, username, confirmationCode string) error {
	return nil
}

func (r *IntegrationRepository) SignIn(ctx context.Context, email, password string) (*auth.CognitoTokens, error) {
	// For integration testing, check if there's a user in the database with matching credentials
	var user users.User
	err := r.db.Where("email = ?", email).First(&user).Error
	if err != nil {
		return nil, errors.New("Invalid credentials")
	}
	
	// For the test case, we're using a known password format
	// In a real integration test, you'd verify the password hash
	if password != "password" && password != "testpass123" {
		return nil, errors.New("Invalid credentials")
	}
	
	tokens := &auth.CognitoTokens{
		AccessToken:  "integration-test-access-token",
		IDToken:      "integration-test-id-token",
		RefreshToken: "integration-test-refresh-token",
		ExpiresIn:    3600,
	}
	return tokens, nil
}

func (r *IntegrationRepository) RefreshToken(ctx context.Context, refreshToken string) (*auth.CognitoTokens, error) {
	tokens := &auth.CognitoTokens{
		AccessToken: "integration-test-new-access-token",
		ExpiresIn:   3600,
	}
	return tokens, nil
}

func (r *IntegrationRepository) ForgotPassword(ctx context.Context, username string) error {
	return nil
}

func (r *IntegrationRepository) ConfirmForgotPassword(ctx context.Context, username, confirmationCode, newPassword string) error {
	return nil
}

func (r *IntegrationRepository) ChangePassword(ctx context.Context, accessToken, currentPassword, newPassword string) error {
	return nil
}

func (r *IntegrationRepository) SignOut(ctx context.Context, accessToken string) error {
	return nil
}

func (r *IntegrationRepository) DeleteUser(ctx context.Context, accessToken string) error {
	return nil
}

func (r *IntegrationRepository) GetUser(ctx context.Context, accessToken string) (*cognitoidentityprovider.GetUserOutput, error) {
	output := &cognitoidentityprovider.GetUserOutput{
		Username: stringPtr("integration-test-username"),
		UserAttributes: []types.AttributeType{
			{
				Name:  stringPtr("email"),
				Value: stringPtr("test@example.com"),
			},
		},
	}
	return output, nil
}

func (r *IntegrationRepository) GetUserByEmail(email string) (*users.User, error) {
	var user users.User
	err := r.db.Where("email = ?", email).First(&user).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *IntegrationRepository) GetUserByUsername(username string) (*users.User, error) {
	var user users.User
	err := r.db.Where("name = ?", username).First(&user).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *IntegrationRepository) GetUserByID(id uint) (*users.User, error) {
	var user users.User
	err := r.db.First(&user, id).Error
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func (r *IntegrationRepository) CreateUser(user *users.User) error {
	return r.db.Create(user).Error
}

func (r *IntegrationRepository) UpdateUser(user *users.User) error {
	return r.db.Save(user).Error
}

func (r *IntegrationRepository) UpdateLastLogin(userID uint) error {
	return r.db.Model(&users.User{}).Where("id = ?", userID).Update("last_login_at", time.Now()).Error
}

// Integration tests
func TestIntegration_SignUpAndLogin(t *testing.T) {
	itc := SetupIntegrationTest(t)
	defer itc.CleanupIntegrationTest(t)

	// Test signup
	signupPayload := `{
		"email": "integration@example.com",
		"username": "integration",
		"password": "testpass123",
		"name": "Integration Test User"
	}`

	req := httptest.NewRequest("POST", "/auth/signup", strings.NewReader(signupPayload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	itc.Router.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent && w.Code != http.StatusOK {
		t.Errorf("Expected status 200 or 204 for signup, got %d. Body: %s", w.Code, w.Body.String())
	}

	// Verify user was created in database
	var user users.User
	err := itc.DB.Where("email = ?", "integration@example.com").First(&user).Error
	if err != nil {
		t.Errorf("User was not created in database: %v", err)
	}

	// Activate user for login test
	user.IsActive = true
	itc.DB.Save(&user)

	// Test login
	loginPayload := `{
		"email": "integration@example.com",
		"password": "testpass123"
	}`

	req = httptest.NewRequest("POST", "/auth/login", strings.NewReader(loginPayload))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()

	itc.Router.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent && w.Code != http.StatusOK {
		t.Errorf("Expected status 200 or 204 for login, got %d. Body: %s", w.Code, w.Body.String())
	}

	// Check for tokens in response headers (as this is how our API returns them)
	tokensHeader := w.Header().Get("Tokens")
	if tokensHeader == "" {
		t.Errorf("Expected tokens in response headers but got none")
	}
}

func TestIntegration_AuthenticationFlow(t *testing.T) {
	itc := SetupIntegrationTest(t)
	defer itc.CleanupIntegrationTest(t)

	// Create and activate a test user
	user := &users.User{
		Email:    "authflow@example.com",
		Name:     "Auth Flow User",
		Password: "$2a$14$ajq8Q7fbtFRQvXpdCq7Jcuy.Rp/9m5L6cKc6LjZCLtzYx9VRgwC6e", // hashed "password"
		IsActive: true,
	}
	err := itc.DB.Create(user).Error
	if err != nil {
		t.Fatalf("Failed to create test user: %v", err)
	}

	// Test 1: Successful login
	loginPayload := `{
		"email": "authflow@example.com",
		"password": "password"
	}`

	req := httptest.NewRequest("POST", "/auth/login", strings.NewReader(loginPayload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	itc.Router.ServeHTTP(w, req)

	if w.Code != http.StatusNoContent && w.Code != http.StatusOK {
		t.Errorf("Expected status 200 or 204 for login, got %d. Body: %s", w.Code, w.Body.String())
	}

	// Test 2: Invalid credentials
	invalidLoginPayload := `{
		"email": "authflow@example.com",
		"password": "wrongpassword"
	}`

	req = httptest.NewRequest("POST", "/auth/login", strings.NewReader(invalidLoginPayload))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()

	itc.Router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401 for invalid login, got %d", w.Code)
	}

	// Test 3: Non-existent user
	nonExistentPayload := `{
		"email": "nonexistent@example.com",
		"password": "password"
	}`

	req = httptest.NewRequest("POST", "/auth/login", strings.NewReader(nonExistentPayload))
	req.Header.Set("Content-Type", "application/json")
	w = httptest.NewRecorder()

	itc.Router.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401 for non-existent user, got %d", w.Code)
	}
}

func TestIntegration_HealthCheck(t *testing.T) {
	itc := SetupIntegrationTest(t)
	defer itc.CleanupIntegrationTest(t)

	req := httptest.NewRequest("GET", "/auth/health", nil)
	w := httptest.NewRecorder()

	itc.Router.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200 for health check, got %d", w.Code)
	}

	// Check response contains expected health check data
	body := w.Body.String()
	if !containsString(body, "status") {
		t.Errorf("Expected health check response to contain 'status'")
	}
}

func TestIntegration_RefreshToken(t *testing.T) {
	itc := SetupIntegrationTest(t)
	defer itc.CleanupIntegrationTest(t)

	refreshPayload := `{
		"refresh_token": "integration-test-refresh-token"
	}`

	req := httptest.NewRequest("POST", "/auth/refresh", strings.NewReader(refreshPayload))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	itc.Router.ServeHTTP(w, req)

	if w.Code != http.StatusOK && w.Code != http.StatusNoContent {
		t.Errorf("Expected status 200 or 204 for refresh token, got %d. Body: %s", w.Code, w.Body.String())
	}
}

func TestIntegration_ErrorHandling(t *testing.T) {
	itc := SetupIntegrationTest(t)
	defer itc.CleanupIntegrationTest(t)

	tests := []struct {
		name           string
		method         string
		path           string
		payload        string
		expectedStatus int
	}{
		{
			name:           "invalid JSON",
			method:         "POST",
			path:           "/auth/signup",
			payload:        `{"invalid": json}`,
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "missing required fields",
			method:         "POST",
			path:           "/auth/signup",
			payload:        `{"email": "test@example.com"}`,
			expectedStatus: http.StatusUnprocessableEntity,
		},
		{
			name:           "invalid email format",
			method:         "POST",
			path:           "/auth/signup",
			payload:        `{"email": "invalid-email", "username": "test", "password": "password123", "name": "Test"}`,
			expectedStatus: http.StatusUnprocessableEntity,
		},
		{
			name:           "empty request body",
			method:         "POST",
			path:           "/auth/login",
			payload:        "",
			expectedStatus: http.StatusBadRequest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest(tt.method, tt.path, strings.NewReader(tt.payload))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			itc.Router.ServeHTTP(w, req)

			if w.Code != tt.expectedStatus {
				t.Errorf("Expected status %d for %s, got %d. Body: %s", 
					tt.expectedStatus, tt.name, w.Code, w.Body.String())
			}
		})
	}
}

func TestIntegration_DatabaseOperations(t *testing.T) {
	itc := SetupIntegrationTest(t)
	defer itc.CleanupIntegrationTest(t)

	// Test user creation and retrieval
	user := &users.User{
		Email:    "dbtest@example.com",
		Name:     "DB Test User",
		Password: "hashedpassword",
		IsActive: true,
	}

	// Create user
	err := itc.DB.Create(user).Error
	if err != nil {
		t.Errorf("Failed to create user: %v", err)
	}

	if user.ID == 0 {
		t.Errorf("Expected user ID to be set after creation")
	}

	// Retrieve user
	var retrievedUser users.User
	err = itc.DB.Where("email = ?", "dbtest@example.com").First(&retrievedUser).Error
	if err != nil {
		t.Errorf("Failed to retrieve user: %v", err)
	}

	if retrievedUser.Email != user.Email {
		t.Errorf("Expected email %s, got %s", user.Email, retrievedUser.Email)
	}

	// Update user
	retrievedUser.Name = "Updated Name"
	err = itc.DB.Save(&retrievedUser).Error
	if err != nil {
		t.Errorf("Failed to update user: %v", err)
	}

	// Verify update
	var updatedUser users.User
	err = itc.DB.First(&updatedUser, retrievedUser.ID).Error
	if err != nil {
		t.Errorf("Failed to retrieve updated user: %v", err)
	}

	if updatedUser.Name != "Updated Name" {
		t.Errorf("Expected name 'Updated Name', got %s", updatedUser.Name)
	}
}

func TestIntegration_ConcurrentRequests(t *testing.T) {
	itc := SetupIntegrationTest(t)
	defer itc.CleanupIntegrationTest(t)

	// Test concurrent health checks
	concurrency := 10
	done := make(chan bool, concurrency)

	for i := 0; i < concurrency; i++ {
		go func() {
			req := httptest.NewRequest("GET", "/auth/health", nil)
			w := httptest.NewRecorder()

			itc.Router.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Errorf("Expected status 200 for concurrent health check, got %d", w.Code)
			}

			done <- true
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < concurrency; i++ {
		<-done
	}
}