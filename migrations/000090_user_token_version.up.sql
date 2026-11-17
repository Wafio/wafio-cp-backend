-- Token revocation: a per-user token version.
--
-- token_version: every JWT carries it as the `tv` claim; RequireJWT rejects a
-- token whose tv is lower than the row's value. Bumped on role change, delete,
-- password change or reset, 2FA disable and POST /api/account/logout-all. A
-- token issued before this migration has no tv claim and reads as 0, so the
-- deploy logs nobody out.
--
-- totp_last_step: the last TOTP time step (unix seconds / 30) accepted for the
-- user; a code whose step is not greater is a replay and is refused.
--
-- Metadata-only ALTERs (constant defaults); lock_timeout bounds the wait for
-- the ACCESS EXCLUSIVE lock on users.
SET lock_timeout = '5s';

ALTER TABLE users ADD COLUMN IF NOT EXISTS token_version INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_last_step BIGINT NOT NULL DEFAULT 0;
