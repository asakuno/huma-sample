package tests

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/asakuno/huma-sample/app/modules/auth"
	"github.com/asakuno/huma-sample/app/modules/users"
	"github.com/asakuno/huma-sample/app/shared/utils"
)

// BenchmarkAuthService_SignUp tests the performance of user signup
func BenchmarkAuthService_SignUp(b *testing.B) {
	config := SetupTestConfig(&testing.T{})
	defer config.CleanupTestDB(&testing.T{})

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			email := fmt.Sprintf("bench-user-%d@example.com", i)
			username := fmt.Sprintf("benchuser%d", i)
			
			// Reset mock for each iteration
			mockRepo := config.Repository.(*MockRepository)
			mockRepo.SetFailure(false, "")
			
			_, err := config.Service.SignUp(
				context.Background(),
				email,
				username,
				"validpass123",
				"Benchmark User",
			)
			
			if err != nil {
				b.Errorf("Unexpected error during signup: %v", err)
			}
			i++
		}
	})
}

// BenchmarkAuthService_Login tests the performance of user login
func BenchmarkAuthService_Login(b *testing.B) {
	config := SetupTestConfig(&testing.T{})
	defer config.CleanupTestDB(&testing.T{})

	// Setup a test user
	mockRepo := config.Repository.(*MockRepository)
	user := &users.User{
		ID:       1,
		Email:    "bench@example.com",
		Name:     "Benchmark User",
		Password: "hashedpassword",
		IsActive: true,
	}
	mockRepo.AddMockUser(user)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, _, err := config.Service.Login(
				context.Background(),
				"bench@example.com",
				"validpass123",
			)
			
			if err != nil {
				b.Errorf("Unexpected error during login: %v", err)
			}
		}
	})
}

// BenchmarkPasswordHashing tests the performance of password hashing
func BenchmarkPasswordHashing(b *testing.B) {
	password := "testpassword123"
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := utils.HashPassword(password)
			if err != nil {
				b.Errorf("Unexpected error during password hashing: %v", err)
			}
		}
	})
}

// BenchmarkPasswordVerification tests the performance of password verification
func BenchmarkPasswordVerification(b *testing.B) {
	password := "testpassword123"
	hashedPassword, err := utils.HashPassword(password)
	if err != nil {
		b.Fatalf("Failed to hash password for benchmark: %v", err)
	}
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			result := utils.CheckPasswordHash(password, hashedPassword)
			if !result {
				b.Errorf("Password verification failed")
			}
		}
	})
}

// BenchmarkJWTTokenParsing tests the performance of JWT token parsing
func BenchmarkJWTTokenParsing(b *testing.B) {
	// Mock Cognito JWT token
	mockToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IkNvZ25pdG9Mb2NhbCJ9.eyJjb2duaXRvOnVzZXJuYW1lIjoibW9jay11c2VyIiwiZW1haWwiOiJtb2NrQGV4YW1wbGUuY29tIiwiaWF0IjoxNjk5MDAwMDAwLCJqdGkiOiJtb2NrLWp0aSIsImV4cCI6MTY5OTAwMzYwMCwiaXNzIjoiaHR0cDovL2xvY2FsaG9zdDo5MjI5L21vY2stcG9vbCJ9.mock-signature"
	
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := utils.ParseCognitoJWT(mockToken)
			if err != nil {
				b.Errorf("Unexpected error during JWT parsing: %v", err)
			}
		}
	})
}

// BenchmarkAuthService_GetUserByEmail tests the performance of user retrieval by email
func BenchmarkAuthService_GetUserByEmail(b *testing.B) {
	config := SetupTestConfig(&testing.T{})
	defer config.CleanupTestDB(&testing.T{})

	// Setup test users
	mockRepo := config.Repository.(*MockRepository)
	for i := 0; i < 1000; i++ {
		user := &users.User{
			ID:       uint(i + 1),
			Email:    fmt.Sprintf("bench-user-%d@example.com", i),
			Name:     fmt.Sprintf("Benchmark User %d", i),
			IsActive: true,
		}
		mockRepo.AddMockUser(user)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			email := fmt.Sprintf("bench-user-%d@example.com", i%1000)
			_, err := config.Service.GetUserByEmail(
				context.Background(),
				email,
			)
			
			if err != nil {
				b.Errorf("Unexpected error during user retrieval: %v", err)
			}
			i++
		}
	})
}

// BenchmarkAuthService_ChangePasswordByEmail tests the performance of password change
func BenchmarkAuthService_ChangePasswordByEmail(b *testing.B) {
	config := SetupTestConfig(&testing.T{})
	defer config.CleanupTestDB(&testing.T{})

	// Setup a test user with hashed password
	mockRepo := config.Repository.(*MockRepository)
	hashedPassword, _ := utils.HashPassword("currentpass123")
	user := &users.User{
		ID:       1,
		Email:    "bench@example.com",
		Name:     "Benchmark User",
		Password: hashedPassword,
		IsActive: true,
	}
	mockRepo.AddMockUser(user)

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			newPassword := fmt.Sprintf("newpass123-%d", i)
			err := config.Service.ChangePasswordByEmail(
				context.Background(),
				"bench@example.com",
				"mock-access-token",
				"currentpass123",
				newPassword,
			)
			
			if err != nil {
				b.Errorf("Unexpected error during password change: %v", err)
			}
			i++
		}
	})
}

// BenchmarkController_SignUp tests the performance of the signup controller
func BenchmarkController_SignUp(b *testing.B) {
	config := SetupTestConfig(&testing.T{})
	defer config.CleanupTestDB(&testing.T{})

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			request := &auth.SignUpRequest{
				Body: struct {
					Email    string `json:"email" format:"email" doc:"User email address" example:"user@example.com"`
					Username string `json:"username" minLength:"3" maxLength:"50" pattern:"^[a-zA-Z0-9_-]+$" doc:"Username (alphanumeric, underscore, hyphen)" example:"john_doe"`
					Password string `json:"password" minLength:"8" maxLength:"128" doc:"Password (minimum 8 characters)" example:"MySecurePass123!"`
					Name     string `json:"name" minLength:"2" maxLength:"100" doc:"Full name" example:"John Doe"`
				}{
					Email:    fmt.Sprintf("bench-ctrl-%d@example.com", i),
					Username: fmt.Sprintf("benchctrl%d", i),
					Password: "validpass123",
					Name:     "Benchmark Controller User",
				},
			}

			// Reset mock for each iteration
			mockRepo := config.Repository.(*MockRepository)
			mockRepo.SetFailure(false, "")

			_, err := config.Controller.SignUp(context.Background(), request)
			if err != nil {
				b.Errorf("Unexpected error during controller signup: %v", err)
			}
			i++
		}
	})
}

// BenchmarkController_Login tests the performance of the login controller
func BenchmarkController_Login(b *testing.B) {
	config := SetupTestConfig(&testing.T{})
	defer config.CleanupTestDB(&testing.T{})

	// Setup a test user
	mockRepo := config.Repository.(*MockRepository)
	user := &users.User{
		ID:       1,
		Email:    "bench-ctrl@example.com",
		Name:     "Benchmark Controller User",
		Password: "hashedpassword",
		IsActive: true,
	}
	mockRepo.AddMockUser(user)

	request := &auth.LoginRequest{
		Body: struct {
			Email    string `json:"email" format:"email" doc:"User email address" example:"user@example.com"`
			Password string `json:"password" minLength:"1" doc:"User password" example:"MySecurePass123!"`
		}{
			Email:    "bench-ctrl@example.com",
			Password: "validpass123",
		},
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			_, err := config.Controller.Login(context.Background(), request)
			if err != nil {
				b.Errorf("Unexpected error during controller login: %v", err)
			}
		}
	})
}

// BenchmarkMemoryUsage tests memory allocation patterns
func BenchmarkMemoryUsage_SignUp(b *testing.B) {
	config := SetupTestConfig(&testing.T{})
	defer config.CleanupTestDB(&testing.T{})

	b.ReportAllocs()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Reset mock for each iteration
		mockRepo := config.Repository.(*MockRepository)
		mockRepo.SetFailure(false, "")

		email := fmt.Sprintf("mem-test-%d@example.com", i)
		username := fmt.Sprintf("memtest%d", i)

		_, err := config.Service.SignUp(
			context.Background(),
			email,
			username,
			"validpass123",
			"Memory Test User",
		)

		if err != nil {
			b.Errorf("Unexpected error during memory test signup: %v", err)
		}
	}
}

// BenchmarkConcurrentOperations tests performance under concurrent load
func BenchmarkConcurrentOperations(b *testing.B) {
	config := SetupTestConfig(&testing.T{})
	defer config.CleanupTestDB(&testing.T{})

	// Setup test users
	mockRepo := config.Repository.(*MockRepository)
	for i := 0; i < 100; i++ {
		user := &users.User{
			ID:       uint(i + 1),
			Email:    fmt.Sprintf("concurrent-%d@example.com", i),
			Name:     fmt.Sprintf("Concurrent User %d", i),
			Password: "hashedpassword",
			IsActive: true,
		}
		mockRepo.AddMockUser(user)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			// Alternate between different operations
			switch i % 3 {
			case 0:
				// Login operation
				email := fmt.Sprintf("concurrent-%d@example.com", i%100)
				_, _, err := config.Service.Login(
					context.Background(),
					email,
					"validpass123",
				)
				if err != nil {
					b.Errorf("Unexpected error during concurrent login: %v", err)
				}

			case 1:
				// Get user operation
				email := fmt.Sprintf("concurrent-%d@example.com", i%100)
				_, err := config.Service.GetUserByEmail(
					context.Background(),
					email,
				)
				if err != nil {
					b.Errorf("Unexpected error during concurrent get user: %v", err)
				}

			case 2:
				// Refresh token operation
				_, err := config.Service.RefreshToken(
					context.Background(),
					"mock-refresh-token",
				)
				if err != nil {
					b.Errorf("Unexpected error during concurrent refresh token: %v", err)
				}
			}
			i++
		}
	})
}

// BenchmarkDatabaseOperations_Create tests database create performance
func BenchmarkDatabaseOperations_Create(b *testing.B) {
	// Use a dummy testing.T for SetupTestDB
	dummyT := &testing.T{}
	db := SetupTestDB(dummyT)
	defer func() {
		sqlDB, _ := db.DB()
		sqlDB.Close()
	}()

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			user := &users.User{
				Email:    fmt.Sprintf("db-bench-%d-%d@example.com", i, time.Now().UnixNano()),
				Name:     fmt.Sprintf("DB Benchmark User %d", i),
				Password: "hashedpassword",
				IsActive: true,
			}

			err := db.Create(user).Error
			if err != nil {
				b.Errorf("Unexpected error during database create: %v", err)
			}
			i++
		}
	})
}

// BenchmarkDatabaseOperations_Read tests database read performance
func BenchmarkDatabaseOperations_Read(b *testing.B) {
	// Use a dummy testing.T for SetupTestDB
	dummyT := &testing.T{}
	db := SetupTestDB(dummyT)
	defer func() {
		sqlDB, _ := db.DB()
		sqlDB.Close()
	}()

	// Create test users
	for i := 0; i < 1000; i++ {
		user := &users.User{
			Email:    fmt.Sprintf("db-read-%d@example.com", i),
			Name:     fmt.Sprintf("DB Read User %d", i),
			Password: "hashedpassword",
			IsActive: true,
		}
		db.Create(user)
	}

	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			var user users.User
			email := fmt.Sprintf("db-read-%d@example.com", i%1000)
			err := db.Where("email = ?", email).First(&user).Error
			if err != nil {
				b.Errorf("Unexpected error during database read: %v", err)
			}
			i++
		}
	})
}