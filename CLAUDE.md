# CLAUDE.md
必ず日本語で回答してください。
This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Key Commands

### Development Environment
- `make init` - Initialize project (build containers, run migrations, seed data)
- `make dev` - Start development environment (API: http://localhost:8888, Docs: http://localhost:8888/docs)
- `make fresh` - Clean and reinitialize project completely
- `make dev-logs` - Show application logs only
- `make shell` - Access application container shell

### Database Operations
- `make migrate` - Run database migrations
- `make seed` - Seed database with sample data  
- `make migrate-seed` - Run migrations and seed data together
- `make rollback` - Rollback database migrations
- `make db-shell` - Connect to MySQL shell

### Testing & Application Management
- `make test` - Run all tests via Docker (`go test ./...`)
- `go test -v ./app/modules/auth/tests` - Run auth module tests specifically
- `cd app/modules/auth/tests && go test -v` - Run tests from auth test directory
- `go test -v -run TestAuthService_SignUp ./app/modules/auth/tests` - Run single test
- `go test -v -bench=. -benchmem ./app/modules/auth/tests` - Run benchmark tests
- `make build-app` - Build application binary
- `make go-tidy` - Run `go mod tidy`
- `make up/down` - Start/stop containers
- `make clean` - Remove containers and volumes

## Project Architecture

### Framework Stack
- **Huma v2.32.0** - Primary REST API framework with OpenAPI 3.1 support
- **Chi v5** - HTTP router used with Huma
- **GORM v1.25.12** - ORM for MySQL database operations
- **AWS Cognito** - Authentication service (with local simulator for development)

### Module Structure
Each business domain follows a consistent layered pattern:
```
app/modules/{domain}/
├── controller.go    # HTTP handlers, request/response processing
├── service.go       # Business logic and validation
├── repository.go    # Data access (database + external services)
├── model.go         # Database entities and domain models
├── dto.go           # API request/response structures
├── routes.go        # Route registration and middleware setup
└── tests/           # Comprehensive test suite
    ├── test_utils.go      # Mock implementations and test utilities
    ├── service_test.go    # Service layer unit tests
    ├── controller_test.go # Controller layer unit tests
    ├── integration_test.go # End-to-end API tests
    ├── benchmark_test.go  # Performance tests
    └── README.md          # Test execution instructions
```

### Key Architecture Patterns
1. **Dependency Injection**: `Repository → Service → Controller` flow
2. **Group-based Routing**: Public vs protected route groups with middleware
3. **Unified Error Handling**: RFC 7807 compliant errors via Huma's built-in types
4. **Configuration Management**: Environment-based config in `app/config/`
5. **Comprehensive Testing**: Unit, integration, and benchmark tests with mock implementations

### Authentication Architecture
- **Development**: Cognito Local simulator at `http://localhost:9229` (automatically configured)
- **Production**: Real AWS Cognito with configurable User Pool
- **JWT Middleware**: Cognito token parsing and validation via `middleware.RequireAuth()`
- **Multi-layer Auth**: Registration, verification, login, password management
- **Email-based Authentication**: Dynamic user identification using email from Cognito JWT tokens
- **Local Setup**: Automatic user pool and client creation via initialization scripts

### API Documentation
- **Swagger UI**: http://localhost:8888/docs (auto-generated)
- **OpenAPI Spec**: http://localhost:8888/openapi.json
- All endpoints use Huma's type-safe validation and auto-documentation

### Database Patterns
- **GORM Models**: Located in `{module}/model.go` files
- **Migration System**: Command-line flags `--migrate`, `--seed`, `--rollback`
- **Connection Pooling**: Configured in `app/config/database.go`
- **Soft Deletes**: Standard GORM pattern with `DeletedAt` field

### Shared Utilities
- **Error Handling**: `app/shared/errors/` - Huma-compatible error types
- **Response Utils**: `app/shared/response/` - Standardized API responses  
- **JWT Utils**: `app/shared/utils/jwt.go` - Token validation/parsing
- **Password Utils**: `app/shared/utils/password.go` - bcrypt hashing
- **Validation**: `app/shared/utils/validate.go` - Input validation helpers

### Development Environment
- **Docker Compose**: Full stack with MySQL, Nginx, Cognito Local
- **Hot Reload**: Air for automatic recompilation
- **Environment Variables**: `.env` file for local development
- **Container Access**: Use `make shell` to access the app container

### Testing Architecture
- **Mock Repository Pattern**: Complete mock implementations of repository interfaces
- **SQLite In-Memory**: Fast, isolated test database using SQLite
- **Test Categories**: Unit tests (service/controller), integration tests (full API), benchmarks
- **Test Utilities**: Comprehensive helper functions for test setup and cleanup
- **Coverage Goals**: 90%+ unit test coverage, 100% critical business flow coverage

### Important Notes
- Always run migrations after code changes: `make migrate`
- Use `make dev-logs` to monitor application output during development
- Test authentication with Cognito Local endpoints in development
- The project uses Go 1.24.1 with module path `github.com/asakuno/huma-sample`
- All API validation is handled automatically by Huma framework
- Error responses follow RFC 7807 standard via Huma's built-in error types
- Run tests from proper directory: `cd app/modules/auth/tests` for auth module tests

### Cognito Local Development Setup
- User Pool ID: `local_4TQOZ5Ss` (auto-created)
- Client ID: `auftpkafnyem0ag5ed84ivuvw` (auto-created)
- Initialization script: `scripts/init-cognito-local.sh` (creates required resources)
- Password policy relaxed for development (minimum 8 characters, no complexity requirements)
- Users require email confirmation via `aws cognito-idp admin-confirm-sign-up` for testing

### Authentication Flow
- JWT tokens contain dynamic user information extracted from Cognito
- Profile and password change APIs use email-based user identification
- All authentication middleware supports both local Cognito and production AWS Cognito
- Token parsing handles Cognito JWT format without signature validation in development