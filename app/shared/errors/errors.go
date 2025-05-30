package errors

import (
	"fmt"
	"net/http"

	"github.com/danielgtaylor/huma/v2"
)

// AppError is a custom error type that implements huma.StatusError
type AppError struct {
	Status  int
	Code    string
	Message string
	Details []string
}

// Error implements the error interface
func (e *AppError) Error() string {
	return e.Message
}

// GetStatus implements huma.StatusError interface
func (e *AppError) GetStatus() int {
	return e.Status
}

// ToHumaError converts AppError to huma error with details
func (e *AppError) ToHumaError() error {
	errs := make([]error, len(e.Details))
	for i, detail := range e.Details {
		errs[i] = &huma.ErrorDetail{
			Message: detail,
		}
	}
	return huma.NewError(e.Status, e.Message, errs...)
}

// Common error constructors

// NewBadRequestError creates a 400 error
func NewBadRequestError(message string, details ...string) *AppError {
	return &AppError{
		Status:  http.StatusBadRequest,
		Code:    "BAD_REQUEST",
		Message: message,
		Details: details,
	}
}

// NewUnauthorizedError creates a 401 error
func NewUnauthorizedError(message string) *AppError {
	return &AppError{
		Status:  http.StatusUnauthorized,
		Code:    "UNAUTHORIZED",
		Message: message,
	}
}

// NewForbiddenError creates a 403 error
func NewForbiddenError(message string) *AppError {
	return &AppError{
		Status:  http.StatusForbidden,
		Code:    "FORBIDDEN",
		Message: message,
	}
}

// NewNotFoundError creates a 404 error
func NewNotFoundError(resource string) *AppError {
	return &AppError{
		Status:  http.StatusNotFound,
		Code:    "NOT_FOUND",
		Message: fmt.Sprintf("%s not found", resource),
	}
}

// NewConflictError creates a 409 error
func NewConflictError(message string) *AppError {
	return &AppError{
		Status:  http.StatusConflict,
		Code:    "CONFLICT",
		Message: message,
	}
}

// NewValidationError creates a 422 error with validation details
func NewValidationError(details ...string) *AppError {
	return &AppError{
		Status:  http.StatusUnprocessableEntity,
		Code:    "VALIDATION_ERROR",
		Message: "Validation failed",
		Details: details,
	}
}

// NewInternalServerError creates a 500 error
func NewInternalServerError(message string) *AppError {
	return &AppError{
		Status:  http.StatusInternalServerError,
		Code:    "INTERNAL_SERVER_ERROR",
		Message: message,
	}
}

// Business logic errors

// NewUserAlreadyExistsError creates a conflict error for existing users
func NewUserAlreadyExistsError(email string) *AppError {
	return NewConflictError(fmt.Sprintf("User with email %s already exists", email))
}

// NewInvalidCredentialsError creates an unauthorized error for invalid login
func NewInvalidCredentialsError() *AppError {
	return NewUnauthorizedError("Invalid email or password")
}

// NewTokenExpiredError creates an unauthorized error for expired tokens
func NewTokenExpiredError() *AppError {
	return NewUnauthorizedError("Token has expired")
}

// NewInvalidTokenError creates an unauthorized error for invalid tokens
func NewInvalidTokenError() *AppError {
	return NewUnauthorizedError("Invalid token")
}

// NewUserNotActiveError creates a forbidden error for inactive users
func NewUserNotActiveError() *AppError {
	return NewForbiddenError("User account is not active")
}

// NewPasswordTooWeakError creates a validation error for weak passwords
func NewPasswordTooWeakError() *AppError {
	return NewValidationError(
		"Password must be at least 8 characters long",
		"Password must contain at least one uppercase letter",
		"Password must contain at least one lowercase letter",
		"Password must contain at least one digit",
		"Password must contain at least one special character",
	)
}
