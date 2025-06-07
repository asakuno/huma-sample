package utils

import (
	"errors"
	"strings"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// JWTClaims represents the custom JWT claims
type JWTClaims struct {
	UserID    uint   `json:"user_id"`
	Email     string `json:"email"`
	Username  string `json:"username"`
	CognitoID string `json:"cognito_id"`
	jwt.RegisteredClaims
}

// GenerateJWT generates a new JWT token for a user
func GenerateJWT(userID uint, email, username, cognitoID, secretKey string, expirationHours int) (string, error) {
	// Set expiration time
	expirationTime := time.Now().Add(time.Duration(expirationHours) * time.Hour)

	// Create the JWT claims
	claims := &JWTClaims{
		UserID:    userID,
		Email:     email,
		Username:  username,
		CognitoID: cognitoID,
		RegisteredClaims: jwt.RegisteredClaims{
			ExpiresAt: jwt.NewNumericDate(expirationTime),
			IssuedAt:  jwt.NewNumericDate(time.Now()),
			NotBefore: jwt.NewNumericDate(time.Now()),
		},
	}

	// Create token with claims
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)

	// Generate encoded token
	tokenString, err := token.SignedString([]byte(secretKey))
	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// ValidateJWT validates and parses a JWT token
func ValidateJWT(tokenString, secretKey string) (*JWTClaims, error) {
	// Parse the token
	token, err := jwt.ParseWithClaims(tokenString, &JWTClaims{}, func(token *jwt.Token) (interface{}, error) {
		// Validate the signing method
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, errors.New("unexpected signing method")
		}
		return []byte(secretKey), nil
	})

	if err != nil {
		return nil, err
	}

	// Check if token is valid
	if !token.Valid {
		return nil, errors.New("invalid token")
	}

	// Extract claims
	claims, ok := token.Claims.(*JWTClaims)
	if !ok {
		return nil, errors.New("invalid token claims")
	}

	return claims, nil
}

// RefreshJWT creates a new JWT token with extended expiration
func RefreshJWT(oldTokenString, secretKey string, expirationHours int) (string, error) {
	// Validate the old token
	claims, err := ValidateJWT(oldTokenString, secretKey)
	if err != nil {
		return "", err
	}

	// Generate new token with same claims but new expiration
	return GenerateJWT(claims.UserID, claims.Email, claims.Username, claims.CognitoID, secretKey, expirationHours)
}

// ExtractTokenFromAuthHeader extracts JWT token from Authorization header
// Expected format: "Bearer <token>"
func ExtractTokenFromAuthHeader(authHeader string) (string, error) {
	if len(authHeader) < 7 || authHeader[:7] != "Bearer " {
		return "", errors.New("invalid authorization header format")
	}
	return authHeader[7:], nil
}

// CognitoJWTClaims represents Cognito JWT token claims
type CognitoJWTClaims struct {
	Email            string `json:"email"`
	CognitoUsername  string `json:"cognito:username"`
	TokenUse         string `json:"token_use"`
	AuthTime         int64  `json:"auth_time"`
	Iss              string `json:"iss"`
	Exp              int64  `json:"exp"`
	Iat              int64  `json:"iat"`
	ClientID         string `json:"client_id"`
	Sub              string `json:"sub"`
	jwt.RegisteredClaims
}

// ParseCognitoJWT parses a Cognito JWT token without validation (for local development)
// In production, you should validate the signature properly
func ParseCognitoJWT(tokenString string) (*CognitoJWTClaims, error) {
	// Split the token into parts
	parts := strings.Split(tokenString, ".")
	if len(parts) != 3 {
		return nil, errors.New("invalid JWT token format")
	}

	// Decode the payload (second part)
	payload := parts[1]
	
	// Add padding if necessary for base64 decoding
	for len(payload)%4 != 0 {
		payload += "="
	}

	// Parse using jwt library without validation (for local development)
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, &CognitoJWTClaims{})
	if err != nil {
		return nil, err
	}

	// Extract claims
	claims, ok := token.Claims.(*CognitoJWTClaims)
	if !ok {
		return nil, errors.New("invalid token claims")
	}

	return claims, nil
}
