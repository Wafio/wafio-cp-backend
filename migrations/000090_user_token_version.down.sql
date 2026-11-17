SET lock_timeout = '5s';

ALTER TABLE users DROP COLUMN IF EXISTS totp_last_step;
ALTER TABLE users DROP COLUMN IF EXISTS token_version;
