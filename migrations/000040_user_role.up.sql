-- Add system role to users. Default is 'user'; the earliest-created account
-- becomes 'admin' so an existing single-user installation keeps full access.
ALTER TABLE users ADD COLUMN role VARCHAR(50) NOT NULL DEFAULT 'user';

UPDATE users
SET role = 'admin'
WHERE created_at = (SELECT MIN(created_at) FROM users);
