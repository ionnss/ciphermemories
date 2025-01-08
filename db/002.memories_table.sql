CREATE TABLE IF NOT EXISTS memories (
    id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(id),
    hashed_content TEXT NOT NULL,
    hashed_key TEXT NOT NULL,
    status VARCHAR(255) DEFAULT 'private', -- private, public
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
)
