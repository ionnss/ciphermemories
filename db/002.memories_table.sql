CREATE TABLE IF NOT EXISTS memories (
    id SERIAL PRIMARY KEY,
    creator_id INT REFERENCES users(id),
    title VARCHAR(255) NOT NULL,
    hashed_content TEXT NOT NULL,
    hashed_key TEXT NOT NULL,
    encryption_iv TEXT NOT NULL,
    encryption_tag TEXT NOT NULL,
    status VARCHAR(255) DEFAULT 'private', -- private, public
    is_paid BOOLEAN DEFAULT FALSE, 
    price INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (creator_id) REFERENCES users(id)
);

CREATE TABLE IF NOT EXISTS memories_access (
    id SERIAL PRIMARY KEY,
    memory_id INT REFERENCES memories(id),
    buyer_id INT REFERENCES users(id),
    purchased_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    transaction_id VARCHAR(255) NOT NULL,
    FOREIGN KEY (memory_id) REFERENCES memories(id),
    FOREIGN KEY (buyer_id) REFERENCES users(id)
);

CREATE INDEX IF NOT EXISTS idx_memory_id ON memories_access (memory_id);
CREATE INDEX IF NOT EXISTS idx_buyer_id ON memories_access (buyer_id);


