-- 000031_schema_cleanup
--
-- Remove legacy columns and constraints left over from previous architecture:
--
-- 1. Drop backward-compat ebpf_agents view (no longer referenced by code).
-- 2. Remove agents.api_key_hash (legacy HMAC auth, replaced by mTLS + host key).
-- 3. Remove agents.callback_url (old pull model where server called back to agent;
--    replaced by bidirectional gRPC stream).
-- 4. Update agents.kind CHECK constraint: 'ebpf' → 'host'.
-- 5. Migrate existing kind='ebpf' rows to kind='host'.
-- 6. Update mtls_credentials.purpose default from tcp_analyze to agent_grpc.
-- 7. Delete stale tcp_analyze credentials (TCP server was removed).

-- 1. Drop backward-compat view
DROP VIEW IF EXISTS ebpf_agents;

-- 2. Remove legacy columns
ALTER TABLE agents DROP COLUMN IF EXISTS api_key_hash;
ALTER TABLE agents DROP COLUMN IF EXISTS callback_url;

-- 3+4. Update kind constraint: ebpf → host
ALTER TABLE agents DROP CONSTRAINT IF EXISTS agents_kind_check;
UPDATE agents SET kind = 'host' WHERE kind = 'ebpf';
ALTER TABLE agents ADD CONSTRAINT agents_kind_check CHECK (kind IN ('host', 'waf'));

-- 5. Update mtls_credentials default
ALTER TABLE mtls_credentials ALTER COLUMN purpose SET DEFAULT 'agent_grpc';

-- 6. Delete stale TCP analyze credentials
DELETE FROM mtls_credentials WHERE purpose = 'tcp_analyze';
