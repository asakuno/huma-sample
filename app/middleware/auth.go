package middleware

import (
	"context"
	"strings"

	"github.com/asakuno/huma-sample/app/shared/errors"
	"github.com/asakuno/huma-sample/app/shared/utils"
	"github.com/danielgtaylor/huma/v2"
)

// contextKey is a custom type for context keys
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
	// Set defaults
	if config.TokenLookup == "" {
		config.TokenLookup = "header:Authorization"
	}
	if config.AuthScheme == "" {
		config.AuthScheme = "Bearer"
	}

	// Parse token lookup
	parts := strings.Split(config.TokenLookup, ":")
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

		// Extract token from request
		switch lookupSource {
		case "header":
			auth := ctx.Header(lookupName)
			if auth == "" {
				handleAuthError(ctx, errors.NewUnauthorizedError("Missing authorization header"))
				return
			}

			// Check auth scheme
			if config.AuthScheme != "" {
				prefix := config.AuthScheme + " "
				if !strings.HasPrefix(auth, prefix) {
					handleAuthError(ctx, errors.NewUnauthorizedError("Invalid authorization header format"))
					return
				}
				token = auth[len(prefix):]
			} else {
				token = auth
			}

		case "query":
			token = ctx.Query(lookupName)
			if token == "" {
				handleAuthError(ctx, errors.NewUnauthorizedError("Missing token in query"))
				return
			}

		case "cookie":
			// Huma doesn't have direct cookie support, need to parse from header
			cookieHeader := ctx.Header("Cookie")
			token = extractCookie(cookieHeader, lookupName)
			if token == "" {
				handleAuthError(ctx, errors.NewUnauthorizedError("Missing token in cookie"))
				return
			}

		default:
			handleAuthError(ctx, errors.NewInternalServerError("Invalid token lookup configuration"))
			return
		}

		// Validate token
		claims, err := utils.ValidateJWT(token, config.JWTSecret)
		if err != nil {
			handleAuthError(ctx, errors.NewUnauthorizedError("Invalid or expired token"))
			return
		}

		// Create a new context with user info
		newCtx := context.WithValue(ctx.Context(), UserContextKey, claims)
		newCtx = context.WithValue(newCtx, TokenContextKey, token)

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
	config := DefaultAuthConfig(jwtSecret)
	
	return func(ctx huma.Context, next func(huma.Context)) {
		var token string

		// Try to extract token from Authorization header
		auth := ctx.Header("Authorization")
		if auth != "" && strings.HasPrefix(auth, "Bearer ") {
			token = auth[7:]
		}

		// If token exists, validate it
		if token != "" {
			claims, err := utils.ValidateJWT(token, config.JWTSecret)
			if err == nil {
				// Valid token, add to context
				newCtx := context.WithValue(ctx.Context(), UserContextKey, claims)
				newCtx = context.WithValue(newCtx, TokenContextKey, token)
				ctx = huma.WithContext(ctx, newCtx)
			}
			// If invalid, just continue without user info
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
		// Note: This assumes role is stored in JWT claims
		// You might need to fetch user details from database
		hasRole := false
		for _, requiredRole := range roles {
			// This is a simplified check - adapt based on your role structure
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

// Helper function to extract cookie value
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
func handleAuthError(ctx huma.Context, err *errors.AppError) {
	// Convert to Huma error
	humaErr := err.ToHumaError()
	
	// Write error response
	ctx.SetStatus(err.GetStatus())
	ctx.SetHeader("Content-Type", "application/problem+json")
	
	// Manually write the error as JSON
	// In a real implementation, you'd use huma.WriteErr
	errorJSON := `{"status":` + string(err.GetStatus()) + `,"title":"` + err.Code + `","detail":"` + err.Message + `"}`
	ctx.BodyWriter().Write([]byte(errorJSON))
}
