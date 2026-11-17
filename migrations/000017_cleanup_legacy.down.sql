-- 000017_cleanup_legacy (DOWN)
-- Restore the dropped schema exactly as it stood at 000016. Data is permanently
-- lost; this only re-adds the schema so the migration sequence can be reversed.
-- waf_paranoia / waf_body_limit are not restored: they did not exist at 000016,
-- so 000017's DROP of them was a no-op.

-- ── apps — PaaS deployment and WAF key columns ───────────────────────────

ALTER TABLE apps
    ADD COLUMN IF NOT EXISTS git_url                  VARCHAR(512),
    ADD COLUMN IF NOT EXISTS git_branch               VARCHAR(100) DEFAULT 'main' NOT NULL,
    ADD COLUMN IF NOT EXISTS fe_enabled               boolean DEFAULT false NOT NULL,
    ADD COLUMN IF NOT EXISTS fe_framework             VARCHAR(30),
    ADD COLUMN IF NOT EXISTS fe_build_cmd             VARCHAR(255),
    ADD COLUMN IF NOT EXISTS fe_output_dir            VARCHAR(255),
    ADD COLUMN IF NOT EXISTS fe_port                  integer DEFAULT 3000 NOT NULL,
    ADD COLUMN IF NOT EXISTS be_enabled               boolean DEFAULT false NOT NULL,
    ADD COLUMN IF NOT EXISTS be_runtime               VARCHAR(30),
    ADD COLUMN IF NOT EXISTS be_start_cmd             VARCHAR(255),
    ADD COLUMN IF NOT EXISTS be_port                  integer DEFAULT 4000 NOT NULL,
    ADD COLUMN IF NOT EXISTS db_enabled               boolean DEFAULT false NOT NULL,
    ADD COLUMN IF NOT EXISTS db_engine                VARCHAR(20),
    ADD COLUMN IF NOT EXISTS env_vars                 jsonb DEFAULT '{}' NOT NULL,
    ADD COLUMN IF NOT EXISTS memory_mb                integer DEFAULT 512 NOT NULL,
    ADD COLUMN IF NOT EXISTS cpu_milli                integer DEFAULT 500 NOT NULL,
    ADD COLUMN IF NOT EXISTS disk_mb                  integer DEFAULT 1024 NOT NULL,
    ADD COLUMN IF NOT EXISTS domain                   VARCHAR(255),
    ADD COLUMN IF NOT EXISTS container_id             VARCHAR(100),
    ADD COLUMN IF NOT EXISTS image_tag                VARCHAR(255),
    ADD COLUMN IF NOT EXISTS status                   VARCHAR(20) DEFAULT 'stopped' NOT NULL,
    ADD COLUMN IF NOT EXISTS internal_port            integer,
    ADD COLUMN IF NOT EXISTS waf_key_prefix           VARCHAR(16),
    ADD COLUMN IF NOT EXISTS waf_key_hash             text,
    ADD COLUMN IF NOT EXISTS waf_key_issued_at        TIMESTAMPTZ,
    ADD COLUMN IF NOT EXISTS prev_waf_key_prefix      VARCHAR(16),
    ADD COLUMN IF NOT EXISTS prev_waf_key_hash        text,
    ADD COLUMN IF NOT EXISTS prev_waf_key_expires_at  TIMESTAMPTZ;

CREATE INDEX IF NOT EXISTS idx_apps_domain ON apps (domain);
CREATE INDEX IF NOT EXISTS idx_apps_status ON apps (status);
CREATE INDEX IF NOT EXISTS idx_apps_waf_key_prefix ON apps (waf_key_prefix) WHERE waf_key_prefix IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_apps_prev_waf_key_prefix ON apps (prev_waf_key_prefix) WHERE prev_waf_key_prefix IS NOT NULL;

-- ── agents — legacy api_key_hash and the view that exposed it ────────────

DROP VIEW IF EXISTS ebpf_agents;

-- The original hashes are gone: give every existing row a unique placeholder
-- before restoring NOT NULL + UNIQUE. The constraint keeps its original name
-- (the table was called ebpf_agents when it was created). PostgreSQL has no
-- ADD CONSTRAINT IF NOT EXISTS, hence the catalog check.
ALTER TABLE agents ADD COLUMN IF NOT EXISTS api_key_hash VARCHAR(128);
UPDATE agents SET api_key_hash = md5(random()::text || id::text) WHERE api_key_hash IS NULL;
ALTER TABLE agents ALTER COLUMN api_key_hash SET NOT NULL;
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'ebpf_agents_api_key_hash_key') THEN
    ALTER TABLE agents ADD CONSTRAINT ebpf_agents_api_key_hash_key UNIQUE (api_key_hash);
  END IF;
END $$;

CREATE VIEW ebpf_agents AS
    SELECT id, user_id, name, api_key_hash, last_seen, created_at,
           project_id, callback_url, host_id,
           host_info, host_os, host_os_version, host_kernel, host_arch,
           host_cpu_count, host_memory, host_virt, host_boot_time, host_updated_at
    FROM agents
    WHERE kind = 'ebpf';

-- ── ebpf_enforcement_log — reverse enforcement mode columns ──────────────

DO $$
BEGIN
  IF EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'ebpf_enforcement_log') THEN
    ALTER TABLE ebpf_enforcement_log
      DROP COLUMN IF EXISTS mode,
      DROP COLUMN IF EXISTS failure_reason;
  END IF;
END $$;
