package persistence

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/asakuno/huma-sample/auth/domain/entity"
	"github.com/asakuno/huma-sample/auth/domain/repository"
	"github.com/google/uuid"
)

// userRepository implements the UserRepository interface
type userRepository struct {
	db *sql.DB
}

// NewUserRepository creates a new UserRepository
func NewUserRepository(db *sql.DB) repository.UserRepository {
	return &userRepository{
		db: db,
	}
}

// Create creates a new user
func (r *userRepository) Create(ctx context.Context, user *entity.User) error {
	query := `
		INSERT INTO users (id, cognito_id, username, email, first_name, last_name, status, created_at, updated_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
	`

	_, err := r.db.ExecContext(ctx, query,
		user.ID,
		user.CognitoID,
		user.Username,
		user.Email,
		user.FirstName,
		user.LastName,
		user.Status,
		user.CreatedAt,
		user.UpdatedAt,
	)

	if err != nil {
		return fmt.Errorf("failed to create user: %w", err)
	}

	return nil
}

// GetByID retrieves a user by ID
func (r *userRepository) GetByID(ctx context.Context, id uuid.UUID) (*entity.User, error) {
	query := `
		SELECT id, cognito_id, username, email, first_name, last_name, status, created_at, updated_at
		FROM users
		WHERE id = ?
	`

	row := r.db.QueryRowContext(ctx, query, id)
	return r.scanUser(row)
}

// GetByCognitoID retrieves a user by Cognito ID
func (r *userRepository) GetByCognitoID(ctx context.Context, cognitoID string) (*entity.User, error) {
	query := `
		SELECT id, cognito_id, username, email, first_name, last_name, status, created_at, updated_at
		FROM users
		WHERE cognito_id = ?
	`

	row := r.db.QueryRowContext(ctx, query, cognitoID)
	return r.scanUser(row)
}

// GetByEmail retrieves a user by email
func (r *userRepository) GetByEmail(ctx context.Context, email string) (*entity.User, error) {
	query := `
		SELECT id, cognito_id, username, email, first_name, last_name, status, created_at, updated_at
		FROM users
		WHERE email = ?
	`

	row := r.db.QueryRowContext(ctx, query, email)
	return r.scanUser(row)
}

// GetByUsername retrieves a user by username
func (r *userRepository) GetByUsername(ctx context.Context, username string) (*entity.User, error) {
	query := `
		SELECT id, cognito_id, username, email, first_name, last_name, status, created_at, updated_at
		FROM users
		WHERE username = ?
	`

	row := r.db.QueryRowContext(ctx, query, username)
	return r.scanUser(row)
}

// Update updates an existing user
func (r *userRepository) Update(ctx context.Context, user *entity.User) error {
	query := `
		UPDATE users
		SET cognito_id = ?, username = ?, email = ?, first_name = ?, last_name = ?, status = ?, updated_at = ?
		WHERE id = ?
	`

	user.UpdatedAt = time.Now()

	_, err := r.db.ExecContext(ctx, query,
		user.CognitoID,
		user.Username,
		user.Email,
		user.FirstName,
		user.LastName,
		user.Status,
		user.UpdatedAt,
		user.ID,
	)

	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	return nil
}

// Delete deletes a user by ID
func (r *userRepository) Delete(ctx context.Context, id uuid.UUID) error {
	query := `DELETE FROM users WHERE id = ?`

	_, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	return nil
}

// List retrieves users with pagination
func (r *userRepository) List(ctx context.Context, limit, offset int) ([]*entity.User, error) {
	query := `
		SELECT id, cognito_id, username, email, first_name, last_name, status, created_at, updated_at
		FROM users
		ORDER BY created_at DESC
		LIMIT ? OFFSET ?
	`

	rows, err := r.db.QueryContext(ctx, query, limit, offset)
	if err != nil {
		return nil, fmt.Errorf("failed to list users: %w", err)
	}
	defer rows.Close()

	var users []*entity.User
	for rows.Next() {
		user := &entity.User{}
		err := rows.Scan(
			&user.ID,
			&user.CognitoID,
			&user.Username,
			&user.Email,
			&user.FirstName,
			&user.LastName,
			&user.Status,
			&user.CreatedAt,
			&user.UpdatedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to scan user: %w", err)
		}
		users = append(users, user)
	}

	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("error iterating users: %w", err)
	}

	return users, nil
}

// Count returns the total number of users
func (r *userRepository) Count(ctx context.Context) (int64, error) {
	query := `SELECT COUNT(*) FROM users`

	var count int64
	err := r.db.QueryRowContext(ctx, query).Scan(&count)
	if err != nil {
		return 0, fmt.Errorf("failed to count users: %w", err)
	}

	return count, nil
}

// ExistsByEmail checks if a user exists with the given email
func (r *userRepository) ExistsByEmail(ctx context.Context, email string) (bool, error) {
	query := `SELECT COUNT(*) FROM users WHERE email = ?`

	var count int
	err := r.db.QueryRowContext(ctx, query, email).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to check user existence by email: %w", err)
	}

	return count > 0, nil
}

// ExistsByUsername checks if a user exists with the given username
func (r *userRepository) ExistsByUsername(ctx context.Context, username string) (bool, error) {
	query := `SELECT COUNT(*) FROM users WHERE username = ?`

	var count int
	err := r.db.QueryRowContext(ctx, query, username).Scan(&count)
	if err != nil {
		return false, fmt.Errorf("failed to check user existence by username: %w", err)
	}

	return count > 0, nil
}

// scanUser scans a database row into a User entity
func (r *userRepository) scanUser(row *sql.Row) (*entity.User, error) {
	user := &entity.User{}
	err := row.Scan(
		&user.ID,
		&user.CognitoID,
		&user.Username,
		&user.Email,
		&user.FirstName,
		&user.LastName,
		&user.Status,
		&user.CreatedAt,
		&user.UpdatedAt,
	)

	if err != nil {
		if err == sql.ErrNoRows {
			return nil, fmt.Errorf("user not found")
		}
		return nil, fmt.Errorf("failed to scan user: %w", err)
	}

	return user, nil
}
