package middleware

import (
	"context"
	"net/http"
	"strings"

	"github.com/asakuno/huma-sample/auth/usecase"
	"github.com/danielgtaylor/huma/v2"
)

// JWTMiddleware provides JWT authentication middleware
type JWTMiddleware struct {
	authUsecase usecase.AuthUsecase
}

// NewJWTMiddleware creates a new JWT middleware
func NewJWTMiddleware(authUsecase usecase.AuthUsecase) *JWTMiddleware {
	return &JWTMiddleware{
		authUsecase: authUsecase,
	}
}

// Middleware returns the JWT authentication middleware function
func (m *JWTMiddleware) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// Extract access token from Authorization header
			accessToken := extractTokenFromHeader(r)
			if accessToken == "" {
				huma.WriteErr(w, r, huma.Error401Unauthorized("Authorization header required"))
				return
			}

			// Validate token
			user, err := m.authUsecase.ValidateToken(ctx, accessToken)
			if err != nil {
				huma.WriteErr(w, r, huma.Error401Unauthorized("Invalid or expired token"))
				return
			}

			// Check if user is active
			if !user.IsActive() {
				huma.WriteErr(w, r, huma.Error403Forbidden("User account is not active"))
				return
			}

			// Add user information to context
			ctx = context.WithValue(ctx, "user_id", user.ID)
			ctx = context.WithValue(ctx, "user", user)
			ctx = context.WithValue(ctx, "access_token", accessToken)

			// Continue to next handler
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// OptionalMiddleware returns an optional JWT authentication middleware
// that doesn't fail if no token is provided but sets user context if token is valid
func (m *JWTMiddleware) OptionalMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// Extract access token from Authorization header
			accessToken := extractTokenFromHeader(r)
			if accessToken != "" {
				// Validate token if present
				user, err := m.authUsecase.ValidateToken(ctx, accessToken)
				if err == nil && user.IsActive() {
					// Add user information to context if token is valid
					ctx = context.WithValue(ctx, "user_id", user.ID)
					ctx = context.WithValue(ctx, "user", user)
					ctx = context.WithValue(ctx, "access_token", accessToken)
				}
			}

			// Continue to next handler regardless of token validation result
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// AdminMiddleware returns middleware that requires admin privileges
func (m *JWTMiddleware) AdminMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := r.Context()

			// First, run JWT authentication
			accessToken := extractTokenFromHeader(r)
			if accessToken == "" {
				huma.WriteErr(w, r, huma.Error401Unauthorized("Authorization header required"))
				return
			}

			user, err := m.authUsecase.ValidateToken(ctx, accessToken)
			if err != nil {
				huma.WriteErr(w, r, huma.Error401Unauthorized("Invalid or expired token"))
				return
			}

			if !user.IsActive() {
				huma.WriteErr(w, r, huma.Error403Forbidden("User account is not active"))
				return
			}

			// Check admin privileges (this is a simple example - in practice you'd have role-based access)
			// For now, we'll check if the user has an admin email domain or specific username
			if !isAdminUser(user.Email, user.Username) {
				huma.WriteErr(w, r, huma.Error403Forbidden("Admin privileges required"))
				return
			}

			// Add user information to context
			ctx = context.WithValue(ctx, "user_id", user.ID)
			ctx = context.WithValue(ctx, "user", user)
			ctx = context.WithValue(ctx, "access_token", accessToken)
			ctx = context.WithValue(ctx, "is_admin", true)

			// Continue to next handler
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// CORS middleware for handling cross-origin requests
func CORSMiddleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Set CORS headers
			w.Header().Set("Access-Control-Allow-Origin", "*") // In production, specify actual origins
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
			w.Header().Set("Access-Control-Max-Age", "86400")

			// Handle preflight requests
			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// extractTokenFromHeader extracts the JWT token from the Authorization header
func extractTokenFromHeader(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if authHeader == "" {
		return ""
	}

	// Expected format: "Bearer <token>"
	parts := strings.SplitN(authHeader, " ", 2)
	if len(parts) != 2 || strings.ToLower(parts[0]) != "bearer" {
		return ""
	}

	return parts[1]
}

// isAdminUser checks if a user has admin privileges
// This is a simple implementation - in a real system you'd have proper role management
func isAdminUser(email, username string) bool {
	// Simple admin check - you should implement proper role-based access control
	adminEmails := []string{
		"admin@example.com",
		"root@example.com",
	}
	
	adminUsernames := []string{
		"admin",
		"root",
		"administrator",
	}

	// Check if email is in admin list
	for _, adminEmail := range adminEmails {
		if strings.EqualFold(email, adminEmail) {
			return true
		}
	}

	// Check if username is in admin list
	for _, adminUsername := range adminUsernames {
		if strings.EqualFold(username, adminUsername) {
			return true
		}
	}

	// Check if email has admin domain
	adminDomains := []string{
		"@admin.example.com",
		"@internal.example.com",
	}

	for _, domain := range adminDomains {
		if strings.HasSuffix(strings.ToLower(email), domain) {
			return true
		}
	}

	return false
}
