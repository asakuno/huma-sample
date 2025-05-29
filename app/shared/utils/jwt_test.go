package utils

import (
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
)

func TestGenerateJWT(t *testing.T) {
	tests := []struct {
		name            string
		userID          uint
		email           string
		username        string
		cognitoID       string
		secretKey       string
		expirationHours int
		wantErr         bool
	}{
		{
			name:            "Valid JWT generation",
			userID:          1,
			email:           "test@example.com",
			username:        "testuser",
			cognitoID:       "cognito-123",
			secretKey:       "test-secret-key",
			expirationHours: 24,
			wantErr:         false,
		},
		{
			name:            "Empty secret key",
			userID:          1,
			email:           "test@example.com",
			username:        "testuser",
			cognitoID:       "cognito-123",
			secretKey:       "",
			expirationHours: 24,
			wantErr:         false, // JWT allows empty keys but it's not secure
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := GenerateJWT(tt.userID, tt.email, tt.username, tt.cognitoID, tt.secretKey, tt.expirationHours)
			
			if tt.wantErr {
				assert.Error(t, err)
				assert.Empty(t, token)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, token)
			}
		})
	}
}

func TestValidateJWT(t *testing.T) {
	// Generate a valid token first
	secretKey := "test-secret-key"
	userID := uint(1)
	email := "test@example.com"
	username := "testuser"
	cognitoID := "cognito-123"
	validToken, _ := GenerateJWT(userID, email, username, cognitoID, secretKey, 1)
	
	// Generate an expired token
	expiredClaims := &JWTClaims{
		UserID:    userID,
		Email:     email,
		Username:  username,
		CognitoID: cognitoID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(-1 * time.Hour)),
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-2 * time.Hour)),
		},
	}
	expiredToken := jwt.NewWithClaims(jwt.SigningMethodHS256, expiredClaims)
	expiredTokenString, _ := expiredToken.SignedString([]byte(secretKey))

	tests := []struct {
		name      string
		token     string
		secretKey string
		wantErr   bool
		validate  func(t *testing.T, claims *JWTClaims)
	}{
		{
			name:      "Valid token",
			token:     validToken,
			secretKey: secretKey,
			wantErr:   false,
			validate: func(t *testing.T, claims *JWTClaims) {
				assert.Equal(t, userID, claims.UserID)
				assert.Equal(t, email, claims.Email)
				assert.Equal(t, username, claims.Username)
				assert.Equal(t, cognitoID, claims.CognitoID)
			},
		},
		{
			name:      "Invalid token",
			token:     "invalid.token.here",
			secretKey: secretKey,
			wantErr:   true,
		},
		{
			name:      "Wrong secret key",
			token:     validToken,
			secretKey: "wrong-secret-key",
			wantErr:   true,
		},
		{
			name:      "Expired token",
			token:     expiredTokenString,
			secretKey: secretKey,
			wantErr:   true,
		},
		{
			name:      "Empty token",
			token:     "",
			secretKey: secretKey,
			wantErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			claims, err := ValidateJWT(tt.token, tt.secretKey)
			
			if tt.wantErr {
				assert.Error(t, err)
				assert.Nil(t, claims)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, claims)
				if tt.validate != nil {
					tt.validate(t, claims)
				}
			}
		})
	}
}

func TestRefreshJWT(t *testing.T) {
	secretKey := "test-secret-key"
	userID := uint(1)
	email := "test@example.com"
	username := "testuser"
	cognitoID := "cognito-123"
	validToken, _ := GenerateJWT(userID, email, username, cognitoID, secretKey, 1)

	tests := []struct {
		name            string
		oldToken        string
		secretKey       string
		expirationHours int
		wantErr         bool
	}{
		{
			name:            "Valid token refresh",
			oldToken:        validToken,
			secretKey:       secretKey,
			expirationHours: 24,
			wantErr:         false,
		},
		{
			name:            "Invalid token",
			oldToken:        "invalid.token.here",
			secretKey:       secretKey,
			expirationHours: 24,
			wantErr:         true,
		},
		{
			name:            "Wrong secret key",
			oldToken:        validToken,
			secretKey:       "wrong-secret-key",
			expirationHours: 24,
			wantErr:         true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			newToken, err := RefreshJWT(tt.oldToken, tt.secretKey, tt.expirationHours)
			
			if tt.wantErr {
				assert.Error(t, err)
				assert.Empty(t, newToken)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, newToken)
				assert.NotEqual(t, tt.oldToken, newToken) // New token should be different
				
				// Validate the new token
				claims, err := ValidateJWT(newToken, tt.secretKey)
				assert.NoError(t, err)
				assert.Equal(t, userID, claims.UserID)
				assert.Equal(t, email, claims.Email)
			}
		})
	}
}

func TestExtractTokenFromAuthHeader(t *testing.T) {
	tests := []struct {
		name       string
		authHeader string
		wantToken  string
		wantErr    bool
	}{
		{
			name:       "Valid Bearer token",
			authHeader: "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test",
			wantToken:  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test",
			wantErr:    false,
		},
		{
			name:       "Empty header",
			authHeader: "",
			wantToken:  "",
			wantErr:    true,
		},
		{
			name:       "No Bearer prefix",
			authHeader: "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test",
			wantToken:  "",
			wantErr:    true,
		},
		{
			name:       "Wrong prefix",
			authHeader: "Basic eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test",
			wantToken:  "",
			wantErr:    true,
		},
		{
			name:       "Only Bearer prefix",
			authHeader: "Bearer ",
			wantToken:  "",
			wantErr:    false,
		},
		{
			name:       "Bearer with lowercase",
			authHeader: "bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.test",
			wantToken:  "",
			wantErr:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			token, err := ExtractTokenFromAuthHeader(tt.authHeader)
			
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.wantToken, token)
		})
	}
}
