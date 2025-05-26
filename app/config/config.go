package config

import (
	"log"
	"os"
	"strconv"

	"github.com/joho/godotenv"
)

// Config holds all configuration for the application
type Config struct {
	AppName  string
	AppEnv   string
	Port     string
	Database DatabaseConfig
	JWT      JWTConfig
	SMTP     SMTPConfig
	Logger   LoggerConfig
}

// JWTConfig holds JWT configuration
type JWTConfig struct {
	Secret string
}

// SMTPConfig holds SMTP configuration
type SMTPConfig struct {
	Host         string
	Port         int
	SenderName   string
	AuthEmail    string
	AuthPassword string
}

// LoggerConfig holds logger configuration
type LoggerConfig struct {
	IsEnabled bool
}

var AppConfig *Config

// LoadConfig loads configuration from environment variables
func LoadConfig() *Config {
	// Load environment variables if not in production
	if os.Getenv("APP_ENV") != "production" {
		err := godotenv.Load(".env")
		if err != nil {
			log.Println("Warning: .env file not found")
		}
	}

	smtpPort, err := strconv.Atoi(getEnv("SMTP_PORT", "587"))
	if err != nil {
		log.Printf("Invalid SMTP_PORT value, using default: 587")
		smtpPort = 587
	}

	isLogger, err := strconv.ParseBool(getEnv("IS_LOGGER", "true"))
	if err != nil {
		log.Printf("Invalid IS_LOGGER value, using default: true")
		isLogger = true
	}

	config := &Config{
		AppName: getEnv("APP_NAME", "huma-sample"),
		AppEnv:  getEnv("APP_ENV", "development"),
		Port:    getEnv("GOLANG_PORT", "8888"),
		Database: DatabaseConfig{
			Host:     getEnv("DB_HOST", "localhost"),
			User:     getEnv("DB_USER", "root"),
			Password: getEnv("DB_PASS", ""),
			Name:     getEnv("DB_NAME", "huma_sample"),
			Port:     getEnv("DB_PORT", "3306"),
		},
		JWT: JWTConfig{
			Secret: getEnv("JWT_SECRET", "your-secret-key"),
		},
		SMTP: SMTPConfig{
			Host:         getEnv("SMTP_HOST", "smtp.gmail.com"),
			Port:         smtpPort,
			SenderName:   getEnv("SMTP_SENDER_NAME", "Huma Sample <no-reply@example.com>"),
			AuthEmail:    getEnv("SMTP_AUTH_EMAIL", ""),
			AuthPassword: getEnv("SMTP_AUTH_PASSWORD", ""),
		},
		Logger: LoggerConfig{
			IsEnabled: isLogger,
		},
	}

	AppConfig = config
	return config
}

// GetConfig returns the loaded configuration
func GetConfig() *Config {
	if AppConfig == nil {
		return LoadConfig()
	}
	return AppConfig
}

// IsProduction returns true if the app is running in production
func IsProduction() bool {
	return GetConfig().AppEnv == "production"
}

// IsDevelopment returns true if the app is running in development
func IsDevelopment() bool {
	return GetConfig().AppEnv == "development" || GetConfig().AppEnv == "localhost"
}
