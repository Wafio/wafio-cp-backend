-- Add tier to users: 'free' or 'pro'. Default 'free'.
ALTER TABLE users ADD COLUMN IF NOT EXISTS tier VARCHAR(32) NOT NULL DEFAULT 'free';
CREATE INDEX IF NOT EXISTS idx_users_tier ON users(tier);
