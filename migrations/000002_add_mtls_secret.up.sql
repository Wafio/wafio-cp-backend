-- Secret untuk renew client mTLS dengan Basic Auth (id + secret)
ALTER TABLE mtls_credentials ADD COLUMN IF NOT EXISTS secret_hash VARCHAR(255);
