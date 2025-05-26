package migration

import (
	"log"

	"github.com/asakuno/huma-sample/app/modules/users"
	"gorm.io/gorm"
)

// Migrate runs database migrations
func Migrate(db *gorm.DB) error {
	log.Println("Running database migrations...")

	// Auto migrate models
	if err := db.AutoMigrate(
		&users.User{},
	); err != nil {
		return err
	}

	log.Println("Database migrations completed successfully")
	return nil
}

// Rollback rolls back database migrations
func Rollback(db *gorm.DB) error {
	log.Println("Rolling back database migrations...")

	// Drop tables in reverse order
	if err := db.Migrator().DropTable(&users.User{}); err != nil {
		return err
	}

	log.Println("Database rollback completed successfully")
	return nil
}

// Seed seeds the database with initial data
func Seed(db *gorm.DB) error {
	log.Println("Seeding database with initial data...")

	// Create sample users
	sampleUsers := []users.User{
		{
			Name:     "Admin User",
			Email:    "admin@example.com",
			Password: "password123", // In production, this should be hashed
			Role:     "admin",
			IsActive: true,
		},
		{
			Name:     "Regular User",
			Email:    "user@example.com",
			Password: "password123", // In production, this should be hashed
			Role:     "user",
			IsActive: true,
		},
	}

	for _, user := range sampleUsers {
		// Check if user already exists
		var existingUser users.User
		if err := db.Where("email = ?", user.Email).First(&existingUser).Error; err == nil {
			log.Printf("User %s already exists, skipping...", user.Email)
			continue
		}

		if err := db.Create(&user).Error; err != nil {
			log.Printf("Failed to create user %s: %v", user.Email, err)
			return err
		}
		log.Printf("Created user: %s", user.Email)
	}

	log.Println("Database seeding completed successfully")
	return nil
}
