package utils

import (
	"golang.org/x/crypto/bcrypt"
)

// HashPassword generates a bcrypt hash for the given password
func HashPassword(password string) (string, error) {
	hashedPassword, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return "", err
	}
	return string(hashedPassword), nil
}

// CheckPasswordHash compares a password with its hash
func CheckPasswordHash(password, hash string) bool {
	err := bcrypt.CompareHashAndPassword([]byte(hash), []byte(password))
	return err == nil
}

// ValidatePasswordStrength checks if the password meets the minimum requirements
func ValidatePasswordStrength(password string) bool {
	// At least 8 characters
	if len(password) < 8 {
		return false
	}

	// You can add more complex validation rules here
	// For example: require uppercase, lowercase, numbers, and special characters
	hasUpper := false
	hasLower := false
	hasDigit := false
	hasSpecial := false

	for _, char := range password {
		switch {
		case 'A' <= char && char <= 'Z':
			hasUpper = true
		case 'a' <= char && char <= 'z':
			hasLower = true
		case '0' <= char && char <= '9':
			hasDigit = true
		case isSpecialChar(char):
			hasSpecial = true
		}
	}

	return hasUpper && hasLower && hasDigit && hasSpecial
}

// isSpecialChar checks if a character is a special character
func isSpecialChar(char rune) bool {
	specialChars := "!@#$%^&*()_+-=[]{}|;':\",./<>?"
	for _, sc := range specialChars {
		if char == sc {
			return true
		}
	}
	return false
}
