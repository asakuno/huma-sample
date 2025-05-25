# Huma API Development Makefile

.PHONY: help dev-start dev-stop dev-restart dev-logs dev-test dev-clean build test

# Default target
help:
	@echo "🚀 Huma API Development Commands"
	@echo ""
	@echo "Development:"
	@echo "  make dev-start    - Start development environment"
	@echo "  make dev-stop     - Stop development environment"
	@echo "  make dev-restart  - Restart development environment"
	@echo "  make dev-logs     - Show application logs"
	@echo "  make dev-test     - Run API tests"
	@echo "  make dev-clean    - Clean up development environment"
	@echo ""
	@echo "Database:"
	@echo "  make db-connect   - Connect to database CLI"
	@echo "  make db-reset     - Reset database (WARNING: deletes data)"
	@echo "  make db-backup    - Create database backup"
	@echo "  make db-adminer   - Open database admin interface"
	@echo ""
	@echo "Building & Testing:"
	@echo "  make build        - Build the application"
	@echo "  make test         - Run unit tests"
	@echo "  make test-int     - Run integration tests"
	@echo ""

# Development commands
dev-start:
	@chmod +x scripts/dev-start.sh
	@./scripts/dev-start.sh

dev-stop:
	@echo "🛑 Stopping development environment..."
	@docker-compose down

dev-restart: dev-stop dev-start

dev-logs:
	@chmod +x scripts/dev-logs.sh
	@./scripts/dev-logs.sh

dev-test:
	@chmod +x scripts/dev-test.sh
	@./scripts/dev-test.sh

dev-clean:
	@echo "🧹 Cleaning up development environment..."
	@docker-compose down -v
	@docker system prune -f
	@echo "✅ Cleanup complete!"

# Database commands
db-connect:
	@chmod +x scripts/dev-db.sh
	@./scripts/dev-db.sh connect

db-reset:
	@chmod +x scripts/dev-db.sh
	@./scripts/dev-db.sh reset

db-backup:
	@chmod +x scripts/dev-db.sh
	@./scripts/dev-db.sh backup

db-adminer:
	@chmod +x scripts/dev-db.sh
	@./scripts/dev-db.sh adminer

# Build and test commands
build:
	@echo "🏗️  Building application..."
	@go mod tidy
	@go build -o bin/server cmd/server/main.go
	@echo "✅ Build complete!"

test:
	@echo "🧪 Running unit tests..."
	@go test ./auth/domain/... -v
	@go test ./auth/usecase/... -v

test-int:
	@echo "🔗 Running integration tests..."
	@go test ./auth/infrastructure/... -v
	@go test ./auth/presentation/... -v

# Quick development workflow
dev: dev-start dev-test

# Production build
prod-build:
	@echo "🏭 Building for production..."
	@CGO_ENABLED=0 GOOS=linux go build -a -installsuffix cgo -o bin/server cmd/server/main.go
	@echo "✅ Production build complete!"
