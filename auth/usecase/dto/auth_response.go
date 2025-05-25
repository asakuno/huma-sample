package dto

import (
	"time"

	"github.com/asakuno/huma-sample/auth/domain/entity"
	"github.com/google/uuid"
)

// LoginResponse represents a login response
type LoginResponse struct {
	User         *UserResponse `json:"user"`
	AccessToken  string        `json:"access_token"`
	RefreshToken string        `json:"refresh_token"`
	TokenType    string        `json:"token_type"`
	ExpiresIn    int           `json:"expires_in"`
	ExpiresAt    time.Time     `json:"expires_at"`
}

// RefreshTokenResponse represents a refresh token response
type RefreshTokenResponse struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token"`
	TokenType    string    `json:"token_type"`
	ExpiresIn    int       `json:"expires_in"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// UserResponse represents a user response
type UserResponse struct {
	ID        uuid.UUID          `json:"id"`
	Username  string             `json:"username"`
	Email     string             `json:"email"`
	FirstName string             `json:"first_name"`
	LastName  string             `json:"last_name"`
	FullName  string             `json:"full_name"`
	Status    entity.UserStatus  `json:"status"`
	CreatedAt time.Time          `json:"created_at"`
	UpdatedAt time.Time          `json:"updated_at"`
}

// MessageResponse represents a simple message response
type MessageResponse struct {
	Message string `json:"message" example:"Operation completed successfully"`
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error   string            `json:"error" example:"Authentication failed"`
	Code    string            `json:"code,omitempty" example:"AUTH_001"`
	Details map[string]string `json:"details,omitempty"`
}

// ValidationErrorResponse represents a validation error response
type ValidationErrorResponse struct {
	Error  string                       `json:"error" example:"Validation failed"`
	Errors map[string][]string          `json:"errors"`
}

// NewUserResponse creates a UserResponse from a User entity
func NewUserResponse(user *entity.User) *UserResponse {
	return &UserResponse{
		ID:        user.ID,
		Username:  user.Username,
		Email:     user.Email,
		FirstName: user.FirstName,
		LastName:  user.LastName,
		FullName:  user.FullName(),
		Status:    user.Status,
		CreatedAt: user.CreatedAt,
		UpdatedAt: user.UpdatedAt,
	}
}

// NewLoginResponse creates a LoginResponse from user and auth token
func NewLoginResponse(user *entity.User, token *entity.AuthToken) *LoginResponse {
	return &LoginResponse{
		User:         NewUserResponse(user),
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		TokenType:    token.TokenType,
		ExpiresIn:    token.ExpiresIn,
		ExpiresAt:    token.ExpiresAt,
	}
}

// NewRefreshTokenResponse creates a RefreshTokenResponse from auth token
func NewRefreshTokenResponse(token *entity.AuthToken) *RefreshTokenResponse {
	return &RefreshTokenResponse{
		AccessToken:  token.AccessToken,
		RefreshToken: token.RefreshToken,
		TokenType:    token.TokenType,
		ExpiresIn:    token.ExpiresIn,
		ExpiresAt:    token.ExpiresAt,
	}
}
