CREATE TABLE IF NOT EXISTS login_attempts (
    attempt_key  TEXT PRIMARY KEY,
    fail_count   INT NOT NULL DEFAULT 0,
    locked_until TIMESTAMPTZ,
    updated_at   TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS idx_login_attempts_locked_until
    ON login_attempts (locked_until);
