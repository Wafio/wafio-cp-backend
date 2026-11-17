-- The TOTP secret is issued by the server. GET /api/profile/2fa/setup
-- stores a freshly generated secret here (encrypted with totp.enc_key, like
-- totp_secret); POST /api/profile/2fa/enable verifies the code against it and
-- moves it into totp_secret. The client never chooses the secret.
-- Metadata-only ALTER (constant default); lock_timeout bounds the wait for
-- the ACCESS EXCLUSIVE lock on users.
SET lock_timeout = '5s';

ALTER TABLE users ADD COLUMN IF NOT EXISTS totp_pending_secret TEXT NOT NULL DEFAULT '';
