-- Secret to renew an mTLS client with Basic Auth (id + secret)
ALTER TABLE mtls_credentials ADD COLUMN IF NOT EXISTS secret_hash VARCHAR(255);
