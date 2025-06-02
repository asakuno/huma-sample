package utils

import (
	"fmt"
	"reflect"
	"regexp"
	"strings"

	"github.com/danielgtaylor/huma/v2"
)

// CustomValidator provides additional validation functions
type CustomValidator struct {
	registry huma.Registry
}

// NewCustomValidator creates a new custom validator
func NewCustomValidator() *CustomValidator {
	return &CustomValidator{
		registry: huma.NewMapRegistry("#/components/schemas/", huma.DefaultSchemaNamer),
	}
}

// ValidateStruct validates a struct using Huma's validation
func (v *CustomValidator) ValidateStruct(data interface{}) []error {
	// Get the type of the struct
	t := reflect.TypeOf(data)
	if t.Kind() == reflect.Ptr {
		t = t.Elem()
	}

	// Generate schema from type
	schema := huma.SchemaFromType(v.registry, t)
	
	// Create path buffer and result
	pb := huma.NewPathBuffer([]byte{}, 0)
	res := &huma.ValidateResult{}
	
	// Validate the data
	huma.Validate(v.registry, schema, pb, huma.ModeWriteToServer, data, res)
	
	return res.Errors
}

// Email validation regex
var emailRegex = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

// ValidateEmail validates email format
func ValidateEmail(email string) error {
	if !emailRegex.MatchString(email) {
		return fmt.Errorf("invalid email format")
	}
	return nil
}

// ValidatePassword validates password strength with detailed feedback
func ValidatePassword(password string) []string {
	var errors []string
	
	if len(password) < 8 {
		errors = append(errors, "Password must be at least 8 characters long")
	}
	
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
	
	if !hasUpper {
		errors = append(errors, "Password must contain at least one uppercase letter")
	}
	if !hasLower {
		errors = append(errors, "Password must contain at least one lowercase letter")
	}
	if !hasDigit {
		errors = append(errors, "Password must contain at least one digit")
	}
	if !hasSpecial {
		errors = append(errors, "Password must contain at least one special character")
	}
	
	return errors
}

// Username validation regex
var usernameRegex = regexp.MustCompile(`^[a-zA-Z0-9_-]{3,50}$`)

// ValidateUsername validates username format
func ValidateUsername(username string) error {
	if !usernameRegex.MatchString(username) {
		return fmt.Errorf("username must be 3-50 characters and contain only letters, numbers, underscores, and hyphens")
	}
	return nil
}

// Phone validation regex (international format)
var phoneRegex = regexp.MustCompile(`^\+?[1-9]\d{1,14}$`)

// ValidatePhone validates phone number format
func ValidatePhone(phone string) error {
	// Remove spaces and dashes
	phone = strings.ReplaceAll(phone, " ", "")
	phone = strings.ReplaceAll(phone, "-", "")
	
	if !phoneRegex.MatchString(phone) {
		return fmt.Errorf("invalid phone number format")
	}
	return nil
}

// ValidateURL validates URL format
func ValidateURL(url string) error {
	// Simple URL validation
	if !strings.HasPrefix(url, "http://") && !strings.HasPrefix(url, "https://") {
		return fmt.Errorf("URL must start with http:// or https://")
	}
	
	if len(url) < 10 { // Minimum viable URL length
		return fmt.Errorf("invalid URL format")
	}
	
	return nil
}

// ValidateUUID validates UUID format
var uuidRegex = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)

func ValidateUUID(uuid string) error {
	if !uuidRegex.MatchString(uuid) {
		return fmt.Errorf("invalid UUID format")
	}
	return nil
}

// ValidateDate validates date format (YYYY-MM-DD)
var dateRegex = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}$`)

func ValidateDate(date string) error {
	if !dateRegex.MatchString(date) {
		return fmt.Errorf("invalid date format, expected YYYY-MM-DD")
	}
	return nil
}

// ValidateDateTime validates datetime format (RFC3339)
var dateTimeRegex = regexp.MustCompile(`^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(Z|[+-]\d{2}:\d{2})$`)

func ValidateDateTime(datetime string) error {
	if !dateTimeRegex.MatchString(datetime) {
		return fmt.Errorf("invalid datetime format, expected RFC3339")
	}
	return nil
}

// ValidateIPAddress validates IP address format (v4 or v6)
func ValidateIPAddress(ip string) error {
	// Simple IPv4 validation
	ipv4Regex := regexp.MustCompile(`^(\d{1,3}\.){3}\d{1,3}$`)
	if ipv4Regex.MatchString(ip) {
		// Check each octet
		parts := strings.Split(ip, ".")
		for _, part := range parts {
			var num int
			fmt.Sscanf(part, "%d", &num)
			if num < 0 || num > 255 {
				return fmt.Errorf("invalid IPv4 address")
			}
		}
		return nil
	}
	
	// Simple IPv6 validation
	ipv6Regex := regexp.MustCompile(`^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|::)$`)
	if !ipv6Regex.MatchString(ip) {
		return fmt.Errorf("invalid IP address format")
	}
	
	return nil
}

// Note: isSpecialChar function is defined in password.go to avoid duplication
