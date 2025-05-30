package middleware

import (
	"net/http"
	"strings"

	"github.com/danielgtaylor/huma/v2"
)

// CORSConfig holds CORS middleware configuration
type CORSConfig struct {
	// AllowedOrigins is a list of origins a cross-domain request can be executed from.
	// If the special "*" value is present in the list, all origins will be allowed.
	AllowedOrigins []string

	// AllowedMethods is a list of methods the client is allowed to use with
	// cross-domain requests.
	AllowedMethods []string

	// AllowedHeaders is list of non simple headers the client is allowed to use with
	// cross-domain requests.
	AllowedHeaders []string

	// ExposedHeaders indicates which headers are safe to expose to the API of a CORS
	// API specification
	ExposedHeaders []string

	// AllowCredentials indicates whether the request can include user credentials like
	// cookies, HTTP authentication or client side SSL certificates.
	AllowCredentials bool

	// MaxAge indicates how long (in seconds) the results of a preflight request
	// can be cached
	MaxAge int
}

// DefaultCORSConfig returns a default CORS configuration
func DefaultCORSConfig() CORSConfig {
	return CORSConfig{
		AllowedOrigins: []string{"*"},
		AllowedMethods: []string{
			http.MethodGet,
			http.MethodPost,
			http.MethodPut,
			http.MethodPatch,
			http.MethodDelete,
			http.MethodOptions,
			http.MethodHead,
		},
		AllowedHeaders: []string{
			"Accept",
			"Authorization",
			"Content-Type",
			"X-CSRF-Token",
			"X-Request-ID",
		},
		ExposedHeaders: []string{
			"Link",
			"X-Total-Count",
			"X-Request-ID",
		},
		AllowCredentials: true,
		MaxAge:          86400, // 24 hours
	}
}

// CORS returns a Huma middleware that handles CORS
func CORS(config CORSConfig) func(ctx huma.Context, next func(huma.Context)) {
	// Precompute some values for efficiency
	allowedOriginsAll := false
	for _, origin := range config.AllowedOrigins {
		if origin == "*" {
			allowedOriginsAll = true
			break
		}
	}

	allowedMethods := strings.Join(config.AllowedMethods, ", ")
	allowedHeaders := strings.Join(config.AllowedHeaders, ", ")
	exposedHeaders := strings.Join(config.ExposedHeaders, ", ")

	return func(ctx huma.Context, next func(huma.Context)) {
		origin := ctx.Header("Origin")

		// Check if origin is allowed
		originAllowed := allowedOriginsAll
		if !originAllowed && origin != "" {
			for _, allowed := range config.AllowedOrigins {
				if origin == allowed {
					originAllowed = true
					break
				}
			}
		}

		// Handle preflight request
		if ctx.Method() == http.MethodOptions {
			if originAllowed {
				ctx.SetHeader("Access-Control-Allow-Origin", origin)
				if config.AllowCredentials {
					ctx.SetHeader("Access-Control-Allow-Credentials", "true")
				}
			}

			ctx.SetHeader("Access-Control-Allow-Methods", allowedMethods)
			ctx.SetHeader("Access-Control-Allow-Headers", allowedHeaders)
			
			if config.MaxAge > 0 {
				ctx.SetHeader("Access-Control-Max-Age", string(config.MaxAge))
			}

			ctx.SetStatus(http.StatusNoContent)
			return
		}

		// Handle actual request
		if originAllowed {
			ctx.SetHeader("Access-Control-Allow-Origin", origin)
			if config.AllowCredentials {
				ctx.SetHeader("Access-Control-Allow-Credentials", "true")
			}
		}

		if exposedHeaders != "" {
			ctx.SetHeader("Access-Control-Expose-Headers", exposedHeaders)
		}

		next(ctx)
	}
}

// CORSWithConfig returns a CORS middleware with custom configuration
func CORSWithConfig(config CORSConfig) func(ctx huma.Context, next func(huma.Context)) {
	return CORS(config)
}

// SimpleCORS returns a CORS middleware with default configuration
func SimpleCORS() func(ctx huma.Context, next func(huma.Context)) {
	return CORS(DefaultCORSConfig())
}
