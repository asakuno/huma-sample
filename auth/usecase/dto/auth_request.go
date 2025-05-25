package dto

// LoginRequest represents a login request
type LoginRequest struct {
	Username string `json:"username" validate:"required,min=3,max=50" example:"johndoe"`
	Password string `json:"password" validate:"required,min=8,max=128" example:"SecurePass123!"`
}

// RefreshTokenRequest represents a refresh token request
type RefreshTokenRequest struct {
	RefreshToken string `json:"refresh_token" validate:"required" example:"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9..."`
}

// ForgotPasswordRequest represents a forgot password request
type ForgotPasswordRequest struct {
	Username string `json:"username" validate:"required,min=3,max=50" example:"johndoe"`
}

// ConfirmForgotPasswordRequest represents a confirm forgot password request
type ConfirmForgotPasswordRequest struct {
	Username         string `json:"username" validate:"required,min=3,max=50" example:"johndoe"`
	ConfirmationCode string `json:"confirmation_code" validate:"required,len=6" example:"123456"`
	NewPassword      string `json:"new_password" validate:"required,min=8,max=128" example:"NewSecurePass123!"`
}

// CreateUserRequest represents a create user request (admin only)
type CreateUserRequest struct {
	Username  string `json:"username" validate:"required,min=3,max=50" example:"johndoe"`
	Email     string `json:"email" validate:"required,email,max=255" example:"john.doe@example.com"`
	FirstName string `json:"first_name" validate:"required,min=1,max=50" example:"John"`
	LastName  string `json:"last_name" validate:"required,min=1,max=50" example:"Doe"`
}

// UpdateProfileRequest represents an update profile request
type UpdateProfileRequest struct {
	FirstName string `json:"first_name" validate:"required,min=1,max=50" example:"John"`
	LastName  string `json:"last_name" validate:"required,min=1,max=50" example:"Doe"`
}

// ChangePasswordRequest represents a change password request
type ChangePasswordRequest struct {
	CurrentPassword string `json:"current_password" validate:"required,min=8,max=128" example:"CurrentPass123!"`
	NewPassword     string `json:"new_password" validate:"required,min=8,max=128" example:"NewSecurePass123!"`
}
