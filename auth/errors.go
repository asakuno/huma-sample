package auth

import "errors"

// Domain errors
var (
	// Authentication errors
	ErrInvalidCredentials = errors.New("invalid username or password")
	ErrAccountLocked      = errors.New("account is locked")
	ErrAccountInactive    = errors.New("account is not active")
	ErrTokenExpired       = errors.New("token has expired")
	ErrTokenInvalid       = errors.New("token is invalid")
	ErrRefreshTokenInvalid = errors.New("refresh token is invalid")

	// User errors
	ErrUserNotFound      = errors.New("user not found")
	ErrUserAlreadyExists = errors.New("user already exists")
	ErrEmailAlreadyExists = errors.New("email already exists")
	ErrUsernameAlreadyExists = errors.New("username already exists")

	// Authorization errors
	ErrInsufficientPermissions = errors.New("insufficient permissions")
	ErrAdminRequired           = errors.New("admin privileges required")

	// Input validation errors
	ErrInvalidEmail    = errors.New("invalid email format")
	ErrInvalidUsername = errors.New("invalid username format")
	ErrPasswordTooWeak = errors.New("password does not meet requirements")
	ErrMissingRequired = errors.New("required field is missing")

	// System errors
	ErrDatabaseConnection = errors.New("database connection failed")
	ErrExternalService    = errors.New("external service error")
	ErrConfigurationError = errors.New("configuration error")
)

// ErrorCode represents an error code for API responses
type ErrorCode string

const (
	// Authentication error codes
	CodeInvalidCredentials ErrorCode = "AUTH_001"
	CodeAccountLocked      ErrorCode = "AUTH_002"
	CodeAccountInactive    ErrorCode = "AUTH_003"
	CodeTokenExpired       ErrorCode = "AUTH_004"
	CodeTokenInvalid       ErrorCode = "AUTH_005"
	CodeRefreshTokenInvalid ErrorCode = "AUTH_006"

	// User error codes
	CodeUserNotFound         ErrorCode = "USER_001"
	CodeUserAlreadyExists    ErrorCode = "USER_002"
	CodeEmailAlreadyExists   ErrorCode = "USER_003"
	CodeUsernameAlreadyExists ErrorCode = "USER_004"

	// Authorization error codes
	CodeInsufficientPermissions ErrorCode = "AUTHZ_001"
	CodeAdminRequired           ErrorCode = "AUTHZ_002"

	// Validation error codes
	CodeInvalidEmail    ErrorCode = "VALID_001"
	CodeInvalidUsername ErrorCode = "VALID_002"
	CodePasswordTooWeak ErrorCode = "VALID_003"
	CodeMissingRequired ErrorCode = "VALID_004"

	// System error codes
	CodeDatabaseConnection ErrorCode = "SYS_001"
	CodeExternalService    ErrorCode = "SYS_002"
	CodeConfigurationError ErrorCode = "SYS_003"
)

// ErrorWithCode represents an error with an associated error code
type ErrorWithCode struct {
	Err  error
	Code ErrorCode
}

// Error implements the error interface
func (e *ErrorWithCode) Error() string {
	return e.Err.Error()
}

// Unwrap implements the unwrap interface for error wrapping
func (e *ErrorWithCode) Unwrap() error {
	return e.Err
}

// NewErrorWithCode creates a new error with an associated code
func NewErrorWithCode(err error, code ErrorCode) *ErrorWithCode {
	return &ErrorWithCode{
		Err:  err,
		Code: code,
	}
}

// GetErrorCode extracts the error code from an error if it's an ErrorWithCode
func GetErrorCode(err error) ErrorCode {
	if errWithCode, ok := err.(*ErrorWithCode); ok {
		return errWithCode.Code
	}
	return ""
}
