-- Create users table for storing user information
CREATE TABLE IF NOT EXISTS users (
    id CHAR(36) PRIMARY KEY,
    cognito_id VARCHAR(255) UNIQUE,
    username VARCHAR(255) NOT NULL UNIQUE,
    email VARCHAR(255) NOT NULL UNIQUE,
    first_name VARCHAR(100) NOT NULL,
    last_name VARCHAR(100) NOT NULL,
    status ENUM('active', 'inactive', 'suspended', 'pending') NOT NULL DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    
    INDEX idx_users_cognito_id (cognito_id),
    INDEX idx_users_email (email),
    INDEX idx_users_username (username),
    INDEX idx_users_status (status),
    INDEX idx_users_created_at (created_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Insert sample admin user for development
INSERT IGNORE INTO users (
    id, 
    cognito_id, 
    username, 
    email, 
    first_name, 
    last_name, 
    status, 
    created_at, 
    updated_at
) VALUES (
    '550e8400-e29b-41d4-a716-446655440000', 
    'dev_admin_cognito_id', 
    'admin', 
    'admin@example.com', 
    'Admin', 
    'User', 
    'active', 
    NOW(), 
    NOW()
);

-- Insert sample regular user for development
INSERT IGNORE INTO users (
    id, 
    cognito_id, 
    username, 
    email, 
    first_name, 
    last_name, 
    status, 
    created_at, 
    updated_at
) VALUES (
    '6ba7b810-9dad-11d1-80b4-00c04fd430c8', 
    'dev_user_cognito_id', 
    'testuser', 
    'test@example.com', 
    'Test', 
    'User', 
    'active', 
    NOW(), 
    NOW()
);

-- Insert sample developer user for development
INSERT IGNORE INTO users (
    id, 
    cognito_id, 
    username, 
    email, 
    first_name, 
    last_name, 
    status, 
    created_at, 
    updated_at
) VALUES (
    '6ba7b811-9dad-11d1-80b4-00c04fd430c8', 
    'dev_developer_cognito_id', 
    'developer', 
    'dev@example.com', 
    'Developer', 
    'User', 
    'active', 
    NOW(), 
    NOW()
);
