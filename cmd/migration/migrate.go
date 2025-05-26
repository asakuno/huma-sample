package migration

import (
	"log"

	"gorm.io/gorm"
)

// Migrate runs database migrations
func Migrate(db *gorm.DB) error {
	log.Println("Running database migrations...")

	// Add your model migrations here
	// Example:
	// if err := db.AutoMigrate(&models.User{}); err != nil {
	//     return err
	// }

	log.Println("Database migrations completed successfully")
	return nil
}

// Rollback rolls back database migrations
func Rollback(db *gorm.DB) error {
	log.Println("Rolling back database migrations...")

	// Add your rollback logic here
	// Example:
	// if err := db.Migrator().DropTable(&models.User{}); err != nil {
	//     return err
	// }

	log.Println("Database rollback completed successfully")
	return nil
}
