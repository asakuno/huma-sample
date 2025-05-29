package utils

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestHashPassword(t *testing.T) {
	tests := []struct {
		name     string
		password string
		wantErr  bool
	}{
		{
			name:     "Valid password",
			password: "MySecureP@ssw0rd",
			wantErr:  false,
		},
		{
			name:     "Empty password",
			password: "",
			wantErr:  false, // bcrypt can hash empty passwords
		},
		{
			name:     "Very long password",
			password: "ThisIsAVeryLongPasswordThatShouldStillWorkWithBcryptHashingAlgorithm!123",
			wantErr:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			hash, err := HashPassword(tt.password)
			
			if tt.wantErr {
				assert.Error(t, err)
				assert.Empty(t, hash)
			} else {
				assert.NoError(t, err)
				assert.NotEmpty(t, hash)
				assert.NotEqual(t, tt.password, hash) // Hash should be different from password
				
				// Verify the hash is valid bcrypt format
				assert.True(t, len(hash) >= 60) // bcrypt hashes are at least 60 characters
			}
		})
	}
}

func TestCheckPasswordHash(t *testing.T) {
	// Pre-generate some hashes
	validPassword := "MySecureP@ssw0rd"
	validHash, _ := HashPassword(validPassword)
	
	tests := []struct {
		name     string
		password string
		hash     string
		want     bool
	}{
		{
			name:     "Correct password",
			password: validPassword,
			hash:     validHash,
			want:     true,
		},
		{
			name:     "Wrong password",
			password: "WrongPassword123!",
			hash:     validHash,
			want:     false,
		},
		{
			name:     "Empty password",
			password: "",
			hash:     validHash,
			want:     false,
		},
		{
			name:     "Invalid hash",
			password: validPassword,
			hash:     "invalid-hash",
			want:     false,
		},
		{
			name:     "Empty hash",
			password: validPassword,
			hash:     "",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := CheckPasswordHash(tt.password, tt.hash)
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestValidatePasswordStrength(t *testing.T) {
	tests := []struct {
		name     string
		password string
		want     bool
	}{
		{
			name:     "Strong password",
			password: "MySecure@Pass123",
			want:     true,
		},
		{
			name:     "All requirements met",
			password: "Password1!",
			want:     true,
		},
		{
			name:     "Too short",
			password: "Pass1!",
			want:     false,
		},
		{
			name:     "No uppercase",
			password: "password123!",
			want:     false,
		},
		{
			name:     "No lowercase",
			password: "PASSWORD123!",
			want:     false,
		},
		{
			name:     "No digit",
			password: "Password!",
			want:     false,
		},
		{
			name:     "No special character",
			password: "Password123",
			want:     false,
		},
		{
			name:     "Empty password",
			password: "",
			want:     false,
		},
		{
			name:     "Only numbers",
			password: "12345678",
			want:     false,
		},
		{
			name:     "Various special characters",
			password: "Pass@123",
			want:     true,
		},
		{
			name:     "Different special character",
			password: "Pass#123",
			want:     true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := ValidatePasswordStrength(tt.password)
			assert.Equal(t, tt.want, result)
		})
	}
}

func TestIsSpecialChar(t *testing.T) {
	tests := []struct {
		name string
		char rune
		want bool
	}{
		{"Exclamation", '!', true},
		{"At sign", '@', true},
		{"Hash", '#', true},
		{"Dollar", '$', true},
		{"Percent", '%', true},
		{"Letter A", 'A', false},
		{"Letter z", 'z', false},
		{"Number 0", '0', false},
		{"Number 9", '9', false},
		{"Space", ' ', false},
		{"Question mark", '?', true},
		{"Period", '.', true},
		{"Comma", ',', true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isSpecialChar(tt.char)
			assert.Equal(t, tt.want, result)
		})
	}
}

// Benchmark tests
func BenchmarkHashPassword(b *testing.B) {
	password := "MySecureP@ssw0rd"
	
	for i := 0; i < b.N; i++ {
		_, _ = HashPassword(password)
	}
}

func BenchmarkCheckPasswordHash(b *testing.B) {
	password := "MySecureP@ssw0rd"
	hash, _ := HashPassword(password)
	
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = CheckPasswordHash(password, hash)
	}
}

func BenchmarkValidatePasswordStrength(b *testing.B) {
	password := "MySecureP@ssw0rd"
	
	for i := 0; i < b.N; i++ {
		_ = ValidatePasswordStrength(password)
	}
}
