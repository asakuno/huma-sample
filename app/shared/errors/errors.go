package errors

import (
	"fmt"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
)

// AppError is a custom error type that wraps huma.StatusError
type AppError struct {
	huma.StatusError
	Code    string
	Details []string
}

// NewAppError creates a new AppError with huma.StatusError
func NewAppError(status int, code, message string, details ...string) *AppError {
	return &AppError{
		StatusError: huma.NewError(status, message),
		Code:        code,
		Details:     details,
	}
}

// Error implements the error interface
func (e *AppError) Error() string {
	return e.StatusError.Error()
}

// GetStatus implements huma.StatusError interface
func (e *AppError) GetStatus() int {
	return e.StatusError.GetStatus()
}

// WithDetails adds additional error details
func (e *AppError) WithDetails(details ...string) *AppError {
	e.Details = append(e.Details, details...)
	return e
}

// Common error constructors using Huma's built-in functions

// NewBadRequestError creates a 400 error using Huma's function
func NewBadRequestError(message string, details ...string) error {
	if len(details) > 0 {
		errs := make([]error, len(details))
		for i, detail := range details {
			errs[i] = fmt.Errorf(detail)
		}
		return huma.Error400BadRequest(message, errs...)
	}
	return huma.Error400BadRequest(message)
}

// NewUnauthorizedError creates a 401 error using Huma's function
func NewUnauthorizedError(message string) error {
	return huma.Error401Unauthorized(message)
}

// NewForbiddenError creates a 403 error using Huma's function
func NewForbiddenError(message string) error {
	return huma.Error403Forbidden(message)
}

// NewNotFoundError creates a 404 error using Huma's function
func NewNotFoundError(resource string) error {
	return huma.Error404NotFound(fmt.Sprintf("%s not found", resource))
}

// NewConflictError creates a 409 error using Huma's function
func NewConflictError(message string) error {
	return huma.Error409Conflict(message)
}

// NewValidationError creates a 422 error with validation details using Huma's function
func NewValidationError(details ...string) error {
	errs := make([]error, len(details))
	for i, detail := range details {
		errs[i] = &huma.ErrorDetail{
			Message:  detail,
			Location: "body",
		}
	}
	return huma.Error422UnprocessableEntity("Validation failed", errs...)
}

// NewInternalServerError creates a 500 error using Huma's function
func NewInternalServerError(message string) error {
	return huma.Error500InternalServerError(message)
}

// Business logic errors using Huma's functions

// NewUserAlreadyExistsError creates a conflict error for existing users
func NewUserAlreadyExistsError(email string) error {
	return huma.Error409Conflict(fmt.Sprintf("User with email %s already exists", email))
}

// NewInvalidCredentialsError creates an unauthorized error for invalid login
func NewInvalidCredentialsError() error {
	return huma.Error401Unauthorized("Invalid email or password")
}

// NewTokenExpiredError creates an unauthorized error for expired tokens
func NewTokenExpiredError() error {
	return huma.Error401Unauthorized("Token has expired")
}

// NewInvalidTokenError creates an unauthorized error for invalid tokens
func NewInvalidTokenError() error {
	return huma.Error401Unauthorized("Invalid token")
}

// NewUserNotActiveError creates a forbidden error for inactive users
func NewUserNotActiveError() error {
	return huma.Error403Forbidden("User account is not active")
}

// NewPasswordTooWeakError creates a validation error for weak passwords
func NewPasswordTooWeakError() error {
	return huma.Error422UnprocessableEntity("Password does not meet strength requirements", 
		&huma.ErrorDetail{
			Message:  "Password must be at least 8 characters long",
			Location: "body.password",
		},
		&huma.ErrorDetail{
			Message:  "Password must contain at least one uppercase letter",
			Location: "body.password",
		},
		&huma.ErrorDetail{
			Message:  "Password must contain at least one lowercase letter",
			Location: "body.password",
		},
		&huma.ErrorDetail{
			Message:  "Password must contain at least one digit",
			Location: "body.password",
		},
		&huma.ErrorDetail{
			Message:  "Password must contain at least one special character",
			Location: "body.password",
		},
	)
}

// WrapError wraps a generic error with additional context
func WrapError(err error, status int, message string) error {
	if statusErr, ok := err.(huma.StatusError); ok {
		return statusErr
	}
	return huma.NewError(status, message, err)
}

// IsStatusError checks if an error is a huma.StatusError
func IsStatusError(err error) bool {
	_, ok := err.(huma.StatusError)
	return ok
}

// GetErrorStatus returns the HTTP status code from an error
func GetErrorStatus(err error) int {
	if statusErr, ok := err.(huma.StatusError); ok {
		return statusErr.GetStatus()
	}
	return http.StatusInternalServerError
}
