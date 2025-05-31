package auth

// SignUpRequest represents the sign up request payload
type SignUpRequest struct {
	Body struct {
		Email    string `json:"email" format:"email" doc:"User email address" example:"user@example.com"`
		Username string `json:"username" minLength:"3" maxLength:"50" pattern:"^[a-zA-Z0-9_-]+$" doc:"Username (alphanumeric, underscore, hyphen)" example:"john_doe"`
		Password string `json:"password" minLength:"8" maxLength:"128" doc:"Password (minimum 8 characters)" example:"MySecurePass123!"`
		Name     string `json:"name" minLength:"2" maxLength:"100" doc:"Full name" example:"John Doe"`
	}
}

// SignUpResponse represents the sign up response
type SignUpResponse struct {
	Body struct {
		Success bool   `json:"success" doc:"Whether the sign up was successful" example:"true"`
		Message string `json:"message" doc:"Response message" example:"User registered successfully. Please check your email for verification code."`
		UserID  string `json:"user_id,omitempty" doc:"Cognito user ID" example:"12345678-1234-1234-1234-123456789012"`
	}
}

// LoginRequest represents the login request payload
type LoginRequest struct {
	Body struct {
		Email    string `json:"email" format:"email" doc:"User email address" example:"user@example.com"`
		Password string `json:"password" minLength:"1" doc:"User password" example:"MySecurePass123!"`
	}
}

// LoginResponse represents the login response
type LoginResponse struct {
	Body struct {
		User   AuthUser  `json:"user" doc:"Authenticated user information"`
		Tokens TokenPair `json:"tokens" doc:"Access and refresh tokens"`
	}
}

// RefreshTokenRequest represents the refresh token request
type RefreshTokenRequest struct {
	Body struct {
		RefreshToken string `json:"refresh_token" minLength:"1" doc:"Refresh token" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
	}
}

// RefreshTokenResponse represents the refresh token response
type RefreshTokenResponse struct {
	Body struct {
		Tokens TokenPair `json:"tokens" doc:"New access and refresh tokens"`
	}
}

// ForgotPasswordRequest represents the forgot password request
type ForgotPasswordRequest struct {
	Body struct {
		Email string `json:"email" format:"email" doc:"User email address" example:"user@example.com"`
	}
}

// ForgotPasswordResponse represents the forgot password response
type ForgotPasswordResponse struct {
	Body struct {
		Success bool   `json:"success" doc:"Whether the request was successful" example:"true"`
		Message string `json:"message" doc:"Response message" example:"If the email exists, a password reset code has been sent."`
	}
}

// ResetPasswordRequest represents the reset password request
type ResetPasswordRequest struct {
	Body struct {
		Email            string `json:"email" format:"email" doc:"User email address" example:"user@example.com"`
		ConfirmationCode string `json:"confirmation_code" minLength:"1" maxLength:"10" pattern:"^[0-9]+$" doc:"Confirmation code from email (numeric)" example:"123456"`
		NewPassword      string `json:"new_password" minLength:"8" maxLength:"128" doc:"New password (minimum 8 characters)" example:"MyNewSecurePass123!"`
	}
}

// ResetPasswordResponse represents the reset password response
type ResetPasswordResponse struct {
	Body struct {
		Success bool   `json:"success" doc:"Whether the password reset was successful" example:"true"`
		Message string `json:"message" doc:"Response message" example:"Password reset successfully. You can now login with your new password."`
	}
}

// ChangePasswordRequest represents the change password request (for authenticated users)
type ChangePasswordRequest struct {
	Body struct {
		CurrentPassword string `json:"current_password" minLength:"1" doc:"Current password" example:"MyOldPassword123!"`
		NewPassword     string `json:"new_password" minLength:"8" maxLength:"128" doc:"New password (minimum 8 characters)" example:"MyNewPassword123!"`
	}
}

// ChangePasswordResponse represents the change password response
type ChangePasswordResponse struct {
	Body struct {
		Success bool   `json:"success" doc:"Whether the password change was successful" example:"true"`
		Message string `json:"message" doc:"Response message" example:"Password changed successfully."`
	}
}

// VerifyEmailRequest represents the email verification request
type VerifyEmailRequest struct {
	Body struct {
		Email            string `json:"email" format:"email" doc:"User email address" example:"user@example.com"`
		ConfirmationCode string `json:"confirmation_code" minLength:"1" maxLength:"10" pattern:"^[0-9]+$" doc:"Confirmation code from email (numeric)" example:"123456"`
	}
}

// VerifyEmailResponse represents the email verification response
type VerifyEmailResponse struct {
	Body struct {
		Success bool   `json:"success" doc:"Whether the email verification was successful" example:"true"`
		Message string `json:"message" doc:"Response message" example:"Email verified successfully. You can now login."`
	}
}

// LogoutRequest represents the logout request
type LogoutRequest struct {
	Body struct {
		RefreshToken string `json:"refresh_token,omitempty" doc:"Optional refresh token to invalidate" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
	}
}

// LogoutResponse represents the logout response
type LogoutResponse struct {
	Body struct {
		Success bool   `json:"success" doc:"Whether the logout was successful" example:"true"`
		Message string `json:"message" doc:"Response message" example:"Logged out successfully."`
	}
}

// PaginationQuery represents common pagination parameters
type PaginationQuery struct {
	Page     int `query:"page" minimum:"1" default:"1" doc:"Page number" example:"1"`
	PageSize int `query:"page_size" minimum:"1" maximum:"100" default:"20" doc:"Number of items per page" example:"20"`
}

// SortQuery represents common sorting parameters
type SortQuery struct {
	SortBy    string `query:"sort_by" enum:"created_at,updated_at,name,email" default:"created_at" doc:"Field to sort by" example:"created_at"`
	SortOrder string `query:"sort_order" enum:"asc,desc" default:"desc" doc:"Sort order" example:"desc"`
}

// FilterQuery represents common filtering parameters
type FilterQuery struct {
	Search   string `query:"search" maxLength:"100" doc:"Search term" example:"john"`
	IsActive *bool  `query:"is_active" doc:"Filter by active status" example:"true"`
}

// ListUsersQuery represents query parameters for listing users (for future admin functionality)
type ListUsersQuery struct {
	PaginationQuery
	SortQuery
	FilterQuery
}

// ErrorResponse represents a standardized error response (following RFC 7807)
type ErrorResponse struct {
	Body struct {
		Status int    `json:"status" doc:"HTTP status code" example:"400"`
		Title  string `json:"title" doc:"Error title" example:"Bad Request"`
		Detail string `json:"detail" doc:"Error description" example:"Validation failed"`
		Type   string `json:"type,omitempty" doc:"Error type URI" example:"https://example.com/errors/validation"`
		Errors []ErrorDetail `json:"errors,omitempty" doc:"Detailed error information"`
	}
}

// ErrorDetail represents detailed error information
type ErrorDetail struct {
	Message  string `json:"message" doc:"Error message" example:"Field is required"`
	Location string `json:"location,omitempty" doc:"Field location" example:"body.email"`
	Value    any    `json:"value,omitempty" doc:"Invalid value" example:"invalid-email"`
}

// UserProfileRequest represents a request to update user profile (for future functionality)
type UserProfileRequest struct {
	Body struct {
		Name  string `json:"name,omitempty" minLength:"2" maxLength:"100" doc:"Full name" example:"John Doe"`
		Email string `json:"email,omitempty" format:"email" doc:"Email address" example:"john.doe@example.com"`
	}
}

// UserProfileResponse represents a user profile response
type UserProfileResponse struct {
	Body struct {
		Success bool     `json:"success" doc:"Whether the update was successful" example:"true"`
		Message string   `json:"message" doc:"Response message" example:"Profile updated successfully."`
		User    AuthUser `json:"user" doc:"Updated user information"`
	}
}

// HealthCheckResponse represents a health check response
type HealthCheckResponse struct {
	Body struct {
		Status  string `json:"status" enum:"ok,degraded,down" doc:"Service status" example:"ok"`
		Service string `json:"service" doc:"Service name" example:"auth"`
		Checks  map[string]HealthCheckDetail `json:"checks,omitempty" doc:"Individual health checks"`
	}
}

// HealthCheckDetail represents details of a specific health check
type HealthCheckDetail struct {
	Status  string `json:"status" enum:"pass,fail,warn" doc:"Check status" example:"pass"`
	Message string `json:"message,omitempty" doc:"Additional information" example:"Database connection successful"`
}
