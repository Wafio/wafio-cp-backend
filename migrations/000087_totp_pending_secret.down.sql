SET lock_timeout = '5s';

ALTER TABLE users DROP COLUMN IF EXISTS totp_pending_secret;
