package users

import (
	"time"

	"gorm.io/gorm"
)

// User represents a user in the system
type User struct {
	ID        uint           `gorm:"primarykey" json:"id"`
	CreatedAt time.Time      `json:"created_at"`
	UpdatedAt time.Time      `json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"-"`
	
	Name     string `gorm:"type:varchar(100);not null" json:"name" validate:"required,min=2,max=100"`
	Email    string `gorm:"type:varchar(255);uniqueIndex;not null" json:"email" validate:"required,email"`
	Password string `gorm:"type:varchar(255);not null" json:"-" validate:"required,min=8"`
	Role     string `gorm:"type:varchar(50);default:'user'" json:"role"`
	IsActive bool   `gorm:"default:true" json:"is_active"`
}

// TableName returns the table name for the User model
func (User) TableName() string {
	return "users"
}

// BeforeCreate is a GORM hook that runs before creating a user
func (u *User) BeforeCreate(tx *gorm.DB) error {
	// You can add password hashing logic here
	return nil
}
