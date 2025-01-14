-- First remove columns from memories table
ALTER TABLE memories 
DROP COLUMN IF EXISTS memories_password_hash,
DROP COLUMN IF EXISTS has_memories_manager;

-- Then add columns to users table where they belong
ALTER TABLE users 
ADD COLUMN IF NOT EXISTS memories_password_hash VARCHAR(255),
ADD COLUMN IF NOT EXISTS has_memories_manager BOOLEAN DEFAULT FALSE;

-- Add indexes for better query performance
CREATE INDEX IF NOT EXISTS idx_has_memories_manager ON users(has_memories_manager); 