CREATE TABLE IF NOT EXISTS users (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    username VARCHAR(255) NOT NULL UNIQUE,
    hashed_password VARCHAR(255) NOT NULL,
    verified_email BOOLEAN DEFAULT FALSE,
    verification_token VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    -- Profile data
    avatar_url VARCHAR(255),
    bio VARCHAR(160),
    birth_location VARCHAR(255),
    birthdate DATE,
    current_location VARCHAR(255)
);

-- Create password reset tokens table
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    token VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    used BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(token)
); 

CREATE UNIQUE INDEX IF NOT EXISTS idx_email ON users (email);
CREATE UNIQUE INDEX IF NOT EXISTS idx_username ON users (username);
