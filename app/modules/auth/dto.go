package auth

// SignUpRequest represents the sign up request payload
type SignUpRequest struct {
	Email    string `json:"email" validate:"required,email" doc:"User email address"`
	Username string `json:"username" validate:"required,min=3,max=50" doc:"Username"`
	Password string `json:"password" validate:"required,min=8" doc:"Password (min 8 characters)"`
	Name     string `json:"name" validate:"required,min=2,max=100" doc:"Full name"`
}

// SignUpResponse represents the sign up response
type SignUpResponse struct {
	Body struct {
		Success bool   `json:"success" doc:"Whether the sign up was successful"`
		Message string `json:"message" doc:"Response message"`
		UserID  string `json:"user_id,omitempty" doc:"Cognito user ID"`
	}
}

// LoginRequest represents the login request payload
type LoginRequest struct {
	Email    string `json:"email" validate:"required,email" doc:"User email address"`
	Password string `json:"password" validate:"required" doc:"User password"`
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
	RefreshToken string `json:"refresh_token" validate:"required" doc:"Refresh token"`
}

// RefreshTokenResponse represents the refresh token response
type RefreshTokenResponse struct {
	Body struct {
		Tokens TokenPair `json:"tokens" doc:"New access and refresh tokens"`
	}
}

// ForgotPasswordRequest represents the forgot password request
type ForgotPasswordRequest struct {
	Email string `json:"email" validate:"required,email" doc:"User email address"`
}

// ForgotPasswordResponse represents the forgot password response
type ForgotPasswordResponse struct {
	Body struct {
		Success bool   `json:"success" doc:"Whether the request was successful"`
		Message string `json:"message" doc:"Response message"`
	}
}

// ResetPasswordRequest represents the reset password request
type ResetPasswordRequest struct {
	Email            string `json:"email" validate:"required,email" doc:"User email address"`
	ConfirmationCode string `json:"confirmation_code" validate:"required" doc:"Confirmation code from email"`
	NewPassword      string `json:"new_password" validate:"required,min=8" doc:"New password (min 8 characters)"`
}

// ResetPasswordResponse represents the reset password response
type ResetPasswordResponse struct {
	Body struct {
		Success bool   `json:"success" doc:"Whether the password reset was successful"`
		Message string `json:"message" doc:"Response message"`
	}
}

// ChangePasswordRequest represents the change password request (for authenticated users)
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" validate:"required" doc:"Current password"`
	NewPassword     string `json:"new_password" validate:"required,min=8" doc:"New password (min 8 characters)"`
}

// ChangePasswordResponse represents the change password response
type ChangePasswordResponse struct {
	Body struct {
		Success bool   `json:"success" doc:"Whether the password change was successful"`
		Message string `json:"message" doc:"Response message"`
	}
}

// VerifyEmailRequest represents the email verification request
type VerifyEmailRequest struct {
	Email            string `json:"email" validate:"required,email" doc:"User email address"`
	ConfirmationCode string `json:"confirmation_code" validate:"required" doc:"Confirmation code from email"`
}

// VerifyEmailResponse represents the email verification response
type VerifyEmailResponse struct {
	Body struct {
		Success bool   `json:"success" doc:"Whether the email verification was successful"`
		Message string `json:"message" doc:"Response message"`
	}
}

// LogoutRequest represents the logout request
type LogoutRequest struct {
	RefreshToken string `json:"refresh_token,omitempty" doc:"Optional refresh token to invalidate"`
}

// LogoutResponse represents the logout response
type LogoutResponse struct {
	Body struct {
		Success bool   `json:"success" doc:"Whether the logout was successful"`
		Message string `json:"message" doc:"Response message"`
	}
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Body struct {
		Error   string `json:"error" doc:"Error type"`
		Message string `json:"message" doc:"Error message"`
		Details string `json:"details,omitempty" doc:"Additional error details"`
	}
}
