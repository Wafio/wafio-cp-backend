-- Password recovery by email.
--
-- One row per outstanding reset link. Only the SHA-256 digest of the 32-byte
-- token is stored; the token itself exists only in the email. A row lives
-- until it is used, replaced by a newer request for the same user (older rows
-- of the user are deleted when a token is issued), deleted with the user, or
-- purged after expires_at. created_at drives the per-account throttle (one
-- email per account per five minutes).
CREATE TABLE IF NOT EXISTS password_reset_tokens (
    token_hash BYTEA PRIMARY KEY CHECK (octet_length(token_hash) = 32),
    user_id    UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ NOT NULL,
    CHECK (expires_at > created_at)
);

CREATE INDEX IF NOT EXISTS password_reset_tokens_user ON password_reset_tokens (user_id, created_at DESC);
CREATE INDEX IF NOT EXISTS password_reset_tokens_expires ON password_reset_tokens (expires_at);
