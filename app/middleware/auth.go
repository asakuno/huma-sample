package middleware

import (
	"context"
	"strings"

	"github.com/asakuno/huma-sample/app/shared/errors"
	"github.com/asakuno/huma-sample/app/shared/utils"
	"github.com/danielgtaylor/huma/v2"
)

// contextKey is a custom type for context keys to avoid collisions
type contextKey string

const (
	// UserContextKey is the key for storing user info in context
	UserContextKey contextKey = "user"
	// TokenContextKey is the key for storing token info in context
	TokenContextKey contextKey = "token"
)

// AuthConfig holds authentication middleware configuration
type AuthConfig struct {
	// JWTSecret is the secret key for JWT validation
	JWTSecret string

	// SkipPaths is a list of paths to skip authentication
	SkipPaths []string

	// TokenLookup is a string in the form of "<source>:<name>" that is used
	// to extract token from the request.
	// Optional. Default value "header:Authorization".
	// Possible values:
	// - "header:<name>"
	// - "query:<name>"
	// - "cookie:<name>"
	TokenLookup string

	// AuthScheme to be used in the Authorization header.
	// Optional. Default value "Bearer".
	AuthScheme string
}

// DefaultAuthConfig returns a default auth configuration
func DefaultAuthConfig(jwtSecret string) AuthConfig {
	return AuthConfig{
		JWTSecret:   jwtSecret,
		SkipPaths:   []string{},
		TokenLookup: "header:Authorization",
		AuthScheme:  "Bearer",
	}
}

// JWT returns a Huma middleware that validates JWT tokens
func JWT(config AuthConfig) func(ctx huma.Context, next func(huma.Context)) {
	// Set defaults if not provided
	if config.TokenLookup == "" {
		config.TokenLookup = "header:Authorization"
	}
	if config.AuthScheme == "" {
		config.AuthScheme = "Bearer"
	}

	// Parse token lookup configuration
	parts := strings.Split(config.TokenLookup, ":")
	if len(parts) != 2 {
		panic("Invalid token lookup format. Expected 'source:name'")
	}
	lookupSource := parts[0]
	lookupName := parts[1]

	return func(ctx huma.Context, next func(huma.Context)) {
		// Check if path should skip authentication
		path := ctx.URL().Path
		for _, skipPath := range config.SkipPaths {
			if strings.HasPrefix(path, skipPath) {
				next(ctx)
				return
			}
		}

		var token string
		var err error

		// Extract token from request based on configuration
		switch lookupSource {
		case "header":
			token, err = extractTokenFromHeader(ctx, lookupName, config.AuthScheme)
		case "query":
			token = ctx.Query(lookupName)
			if token == "" {
				err = errors.NewUnauthorizedError("Missing token in query parameter")
			}
		case "cookie":
			token, err = extractTokenFromCookie(ctx, lookupName)
		default:
			err = errors.NewInternalServerError("Invalid token lookup source")
		}

		if err != nil {
			handleAuthError(ctx, err)
			return
		}

		// Parse Cognito JWT to extract user information
		cognitoClaims, err := utils.ParseCognitoJWT(token)
		if err != nil {
			handleAuthError(ctx, errors.NewUnauthorizedError("Invalid token format"))
			return
		}

		// Store the token in context
		newCtx := context.WithValue(ctx.Context(), TokenContextKey, token)
		
		// Create user claims from Cognito JWT
		claims := &utils.JWTClaims{
			Email:     cognitoClaims.Email,
			CognitoID: cognitoClaims.Sub,
		}
		newCtx = context.WithValue(newCtx, UserContextKey, claims)

		// Create a new Huma context with the updated context
		wrappedCtx := huma.WithContext(ctx, newCtx)

		// Continue to the next handler
		next(wrappedCtx)
	}
}

// RequireAuth returns a simple auth middleware that requires authentication
func RequireAuth(jwtSecret string) func(ctx huma.Context, next func(huma.Context)) {
	return JWT(DefaultAuthConfig(jwtSecret))
}

// OptionalAuth returns an auth middleware that doesn't fail if token is missing
func OptionalAuth(jwtSecret string) func(ctx huma.Context, next func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		var token string

		// Try to extract token from Authorization header
		auth := ctx.Header("Authorization")
		if auth != "" && strings.HasPrefix(auth, "Bearer ") {
			token = auth[7:]
		}

		// If token exists, parse it
		if token != "" {
			cognitoClaims, err := utils.ParseCognitoJWT(token)
			if err == nil {
				// Valid token, add to context
				claims := &utils.JWTClaims{
					Email:     cognitoClaims.Email,
					CognitoID: cognitoClaims.Sub,
				}
				newCtx := context.WithValue(ctx.Context(), UserContextKey, claims)
				newCtx = context.WithValue(newCtx, TokenContextKey, token)
				ctx = huma.WithContext(ctx, newCtx)
			}
			// If invalid, just continue without user info (no error)
		}

		next(ctx)
	}
}

// GetUserFromContext retrieves user claims from context
func GetUserFromContext(ctx context.Context) (*utils.JWTClaims, bool) {
	claims, ok := ctx.Value(UserContextKey).(*utils.JWTClaims)
	return claims, ok
}

// GetTokenFromContext retrieves token from context
func GetTokenFromContext(ctx context.Context) (string, bool) {
	token, ok := ctx.Value(TokenContextKey).(string)
	return token, ok
}

// RequireRole returns a middleware that checks if user has required role
func RequireRole(roles ...string) func(ctx huma.Context, next func(huma.Context)) {
	return func(ctx huma.Context, next func(huma.Context)) {
		claims, ok := GetUserFromContext(ctx.Context())
		if !ok {
			handleAuthError(ctx, errors.NewUnauthorizedError("Authentication required"))
			return
		}

		// Check if user has required role
		// This is a simplified implementation - in production you'd want to:
		// 1. Fetch user details from database to get current roles
		// 2. Implement a proper role hierarchy system
		// 3. Cache role information for performance

		hasRole := false
		for _, requiredRole := range roles {
			// Example role check - adapt based on your role structure
			if claims.Email == "admin@example.com" && requiredRole == "admin" {
				hasRole = true
				break
			}
			if requiredRole == "user" {
				hasRole = true
				break
			}
		}

		if !hasRole {
			handleAuthError(ctx, errors.NewForbiddenError("Insufficient permissions"))
			return
		}

		next(ctx)
	}
}

// RateLimit returns a simple rate limiting middleware
func RateLimit(requestsPerMinute int) func(ctx huma.Context, next func(huma.Context)) {
	// This is a simplified rate limiter - in production use a proper implementation
	// like go-redis/redis_rate or github.com/ulule/limiter
	return func(ctx huma.Context, next func(huma.Context)) {
		// TODO: Implement proper rate limiting
		// For now, just pass through
		next(ctx)
	}
}

// Helper functions

// extractTokenFromHeader extracts JWT token from Authorization header
func extractTokenFromHeader(ctx huma.Context, headerName, authScheme string) (string, error) {
	auth := ctx.Header(headerName)
	if auth == "" {
		return "", errors.NewUnauthorizedError("Missing authorization header")
	}

	// Check auth scheme
	if authScheme != "" {
		prefix := authScheme + " "
		if !strings.HasPrefix(auth, prefix) {
			return "", errors.NewUnauthorizedError("Invalid authorization header format")
		}
		return auth[len(prefix):], nil
	}

	return auth, nil
}

// extractTokenFromCookie extracts token from cookie
func extractTokenFromCookie(ctx huma.Context, cookieName string) (string, error) {
	// Huma doesn't have direct cookie support, so we parse from header
	cookieHeader := ctx.Header("Cookie")
	if cookieHeader == "" {
		return "", errors.NewUnauthorizedError("Missing cookie header")
	}

	token := extractCookie(cookieHeader, cookieName)
	if token == "" {
		return "", errors.NewUnauthorizedError("Token not found in cookie")
	}

	return token, nil
}

// extractCookie helper function to extract cookie value by name
func extractCookie(cookieHeader, name string) string {
	if cookieHeader == "" {
		return ""
	}

	cookies := strings.Split(cookieHeader, "; ")
	for _, cookie := range cookies {
		parts := strings.SplitN(cookie, "=", 2)
		if len(parts) == 2 && parts[0] == name {
			return parts[1]
		}
	}

	return ""
}

// handleAuthError writes an authentication error response
func handleAuthError(ctx huma.Context, err error) {
	// For Huma v2, we should use panic to let Huma handle the error properly
	// This is the recommended way to handle errors in Huma middleware
	if statusErr, ok := err.(huma.StatusError); ok {
		panic(statusErr)
	} else {
		panic(huma.Error500InternalServerError(err.Error()))
	}
}
