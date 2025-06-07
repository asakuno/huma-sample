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
	Cognito  CognitoConfig
	AWS      AWSConfig
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

// CognitoConfig holds AWS Cognito configuration
type CognitoConfig struct {
	UserPoolID       string
	AppClientID      string
	AppClientSecret  string
	UseLocal         bool
	LocalEndpoint    string
}

// AWSConfig holds AWS configuration
type AWSConfig struct {
	Region string
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

	useCognitoLocal, err := strconv.ParseBool(getEnv("USE_COGNITO_LOCAL", "false"))
	if err != nil {
		log.Printf("Invalid USE_COGNITO_LOCAL value, using default: false")
		useCognitoLocal = false
	}

	// Determine Cognito configuration based on local/production mode
	userPoolID := getEnv("COGNITO_USER_POOL_ID", "")
	appClientID := getEnv("COGNITO_APP_CLIENT_ID", "")
	appClientSecret := getEnv("COGNITO_APP_CLIENT_SECRET", "")

	if useCognitoLocal {
		// Override with local values if using local Cognito
		userPoolID = getEnv("COGNITO_LOCAL_USER_POOL_ID", "local_4TQOZ5Ss")
		appClientID = getEnv("COGNITO_LOCAL_APP_CLIENT_ID", "auftpkafnyem0ag5ed84ivuvw")
		appClientSecret = "" // Local Cognito doesn't use client secret
		log.Println("Using local Cognito configuration")
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
		Cognito: CognitoConfig{
			UserPoolID:      userPoolID,
			AppClientID:     appClientID,
			AppClientSecret: appClientSecret,
			UseLocal:        useCognitoLocal,
			LocalEndpoint:   getEnv("COGNITO_LOCAL_ENDPOINT", "http://localhost:9229"),
		},
		AWS: AWSConfig{
			Region: getEnv("AWS_REGION", "ap-northeast-1"),
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
