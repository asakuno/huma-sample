package auth

import (
	"time"
)

// AuthUser represents a user in the authentication context
type AuthUser struct {
	ID              uint       `json:"id"`
	Email           string     `json:"email"`
	Username        string     `json:"username"`
	CognitoUserID   string     `json:"cognito_user_id"`
	EmailVerified   bool       `json:"email_verified"`
	LastLoginAt     *time.Time `json:"last_login_at,omitempty"`
	IsActive        bool       `json:"is_active"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

// TokenPair represents access and refresh tokens
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
}

// CognitoTokens represents tokens returned by AWS Cognito
type CognitoTokens struct {
	AccessToken  string
	IDToken      string
	RefreshToken string
	ExpiresIn    int32
}

// PasswordResetRequest represents a password reset request
type PasswordResetRequest struct {
	ID              uint      `json:"id"`
	UserID          uint      `json:"user_id"`
	Email           string    `json:"email"`
	Token           string    `json:"-"`
	ConfirmationCode string   `json:"-"`
	ExpiresAt       time.Time `json:"expires_at"`
	UsedAt          *time.Time `json:"used_at,omitempty"`
	CreatedAt       time.Time `json:"created_at"`
}

// Session represents an active user session
type Session struct {
	ID           string    `json:"id"`
	UserID       uint      `json:"user_id"`
	RefreshToken string    `json:"-"`
	UserAgent    string    `json:"user_agent"`
	IPAddress    string    `json:"ip_address"`
	ExpiresAt    time.Time `json:"expires_at"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// IsExpired checks if the password reset request has expired
func (p *PasswordResetRequest) IsExpired() bool {
	return time.Now().After(p.ExpiresAt)
}

// IsUsed checks if the password reset request has been used
func (p *PasswordResetRequest) IsUsed() bool {
	return p.UsedAt != nil
}

// IsExpired checks if the session has expired
func (s *Session) IsExpired() bool {
	return time.Now().After(s.ExpiresAt)
}

// CognitoUser represents a user from AWS Cognito
type CognitoUser struct {
	Username       string          `json:"username"`
	UserAttributes []*AttributeType `json:"user_attributes"`
}

// AttributeType represents an attribute in Cognito
type AttributeType struct {
	Name  *string `json:"name"`
	Value *string `json:"value"`
}
