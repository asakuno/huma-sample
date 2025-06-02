# Makefile for huma-sample project

# Import .env file if it exists
ifneq (,$(wildcard ./.env))
	include .env
	export $(shell sed 's/=.*//' .env)
endif

# Variables
CONTAINER_NAME=huma-sample-app
MYSQL_CONTAINER_NAME=huma-sample-mysql
PROJECT_NAME=huma-sample

# Docker commands
.PHONY: build up down logs ps clean

build:
	docker compose build

up:
	docker compose up -d

down:
	docker compose down

logs:
	docker compose logs -f

ps:
	docker compose ps

clean:
	docker compose down -v
	docker system prune -f

# Development commands
.PHONY: dev dev-logs

dev: up
	@echo "Development environment started"
	@echo "API: http://localhost:8888"
	@echo "Health check: http://localhost:8888/health"
	@echo "API docs: http://localhost:8888/docs"

dev-logs:
	docker compose logs -f app

# Database commands
.PHONY: db-shell db-create migrate seed migrate-seed rollback

db-shell:
	docker exec -it $(MYSQL_CONTAINER_NAME) mysql -u$(DB_USER) -p$(DB_PASS) $(DB_NAME)

db-create:
	docker exec -it $(MYSQL_CONTAINER_NAME) mysql -u$(DB_USER) -p$(DB_PASS) -e "CREATE DATABASE IF NOT EXISTS $(DB_NAME);"

migrate:
	docker exec -it $(CONTAINER_NAME) /app/.docker/air/tmp/main --migrate

seed:
	docker exec -it $(CONTAINER_NAME) /app/.docker/air/tmp/main --seed

migrate-seed:
	docker exec -it $(CONTAINER_NAME) /app/.docker/air/tmp/main --migrate-seed

rollback:
	docker exec -it $(CONTAINER_NAME) /app/.docker/air/tmp/main --rollback

# Application commands
.PHONY: shell test build-app go-tidy

shell:
	docker exec -it $(CONTAINER_NAME) /bin/sh

test:
	docker exec -it $(CONTAINER_NAME) go test ./...

build-app:
	docker exec -it $(CONTAINER_NAME) go build -o bin/server ./cmd/server

go-tidy:
	docker exec -it $(CONTAINER_NAME) go mod tidy

# Quick setup commands
.PHONY: init fresh

init: build up
	@echo "Waiting for database to be ready..."
	@sleep 10
	$(MAKE) migrate-seed
	@echo "Project initialized successfully!"
	@echo "API: http://localhost:8888"
	@echo "Health check: http://localhost:8888/health"

fresh: clean init

# Help
.PHONY: help

help:
	@echo "Available commands:"
	@echo "  build         - Build Docker containers"
	@echo "  up            - Start containers"
	@echo "  down          - Stop containers"
	@echo "  logs          - Show all logs"
	@echo "  dev-logs      - Show app logs only"
	@echo "  ps            - Show running containers"
	@echo "  clean         - Stop containers and remove volumes"
	@echo ""
	@echo "  db-shell      - Connect to MySQL shell"
	@echo "  db-create     - Create database"
	@echo "  migrate       - Run database migrations"
	@echo "  seed          - Seed database with sample data"
	@echo "  migrate-seed  - Run migrations and seed data"
	@echo "  rollback      - Rollback database migrations"
	@echo ""
	@echo "  shell         - Access container shell"
	@echo "  test          - Run tests"
	@echo "  build-app     - Build application binary"
	@echo "  go-tidy       - Run go mod tidy"
	@echo ""
	@echo "  init          - Initialize project (build, up, migrate, seed)"
	@echo "  fresh         - Clean and initialize project"
	@echo "  dev           - Start development environment"
	@echo "  help          - Show this help message"
