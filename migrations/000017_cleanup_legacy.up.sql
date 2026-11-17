-- 000017_cleanup_legacy
-- Remove legacy/deprecated columns that are no longer used:
--
--   agents.api_key_hash       — SHA-256 placeholder; host-key auth replaces it
--   apps.*_waf_key*           — per-app WAF key (mTLS proves identity now)
--   apps.PaaS fields           — git_url, fe_*, be_*, db_*, status, container_id, …
--   apps.waf_paranoia          — hardcoded to 1 in bundle queries
--   apps.waf_body_limit        — hardcoded to 1 MiB in bundle queries
--
-- The ebpf_agents view is re-created without api_key_hash.

-- ── agents ────────────────────────────────────────────────────────────────

DROP VIEW IF EXISTS ebpf_agents;

ALTER TABLE agents
    DROP CONSTRAINT IF EXISTS agents_api_key_hash_key,
    DROP COLUMN IF EXISTS api_key_hash;

-- Recreate ebpf_agents view without the dropped column.
CREATE VIEW ebpf_agents AS
    SELECT id, user_id, name, last_seen, created_at,
           project_id, callback_url, host_id,
           host_info, host_os, host_os_version, host_kernel, host_arch,
           host_cpu_count, host_memory, host_virt, host_boot_time, host_updated_at
    FROM agents
    WHERE kind = 'ebpf';

-- ── apps — WAF key columns ────────────────────────────────────────────────

DROP INDEX IF EXISTS idx_apps_waf_key_prefix;

ALTER TABLE apps
    DROP COLUMN IF EXISTS waf_key_prefix,
    DROP COLUMN IF EXISTS waf_key_hash,
    DROP COLUMN IF EXISTS waf_key_issued_at,
    DROP COLUMN IF EXISTS prev_waf_key_prefix,
    DROP COLUMN IF EXISTS prev_waf_key_hash,
    DROP COLUMN IF EXISTS prev_waf_key_expires_at;

-- ── apps — PaaS deployment columns ───────────────────────────────────────

ALTER TABLE apps
    DROP COLUMN IF EXISTS git_url,
    DROP COLUMN IF EXISTS git_branch,
    DROP COLUMN IF EXISTS fe_enabled,
    DROP COLUMN IF EXISTS fe_framework,
    DROP COLUMN IF EXISTS fe_build_cmd,
    DROP COLUMN IF EXISTS fe_output_dir,
    DROP COLUMN IF EXISTS fe_port,
    DROP COLUMN IF EXISTS be_enabled,
    DROP COLUMN IF EXISTS be_runtime,
    DROP COLUMN IF EXISTS be_start_cmd,
    DROP COLUMN IF EXISTS be_port,
    DROP COLUMN IF EXISTS db_enabled,
    DROP COLUMN IF EXISTS db_engine,
    DROP COLUMN IF EXISTS env_vars,
    DROP COLUMN IF EXISTS memory_mb,
    DROP COLUMN IF EXISTS cpu_milli,
    DROP COLUMN IF EXISTS disk_mb,
    DROP COLUMN IF EXISTS domain,
    DROP COLUMN IF EXISTS container_id,
    DROP COLUMN IF EXISTS image_tag,
    DROP COLUMN IF EXISTS status,
    DROP COLUMN IF EXISTS internal_port;

-- ── apps — per-app WAF tuning (now global in CRS config) ─────────────────

ALTER TABLE apps
    DROP COLUMN IF EXISTS waf_paranoia,
    DROP COLUMN IF EXISTS waf_body_limit;

-- ── ebpf_enforcement_log — enforcement mode columns ──────────────────────
-- (Previously a separate 000017_enforcement_mode migration; merged here to
--  keep a single version-17 file. The columns are needed by 000018+.
--  Using IF EXISTS on the table because migration 000030 drops this table;
--  DBs already past that point should skip these ALTER statements safely.)

DO $$
BEGIN
  IF EXISTS (SELECT FROM information_schema.tables WHERE table_name = 'ebpf_enforcement_log') THEN
    IF NOT EXISTS (SELECT FROM information_schema.columns WHERE table_name = 'ebpf_enforcement_log' AND column_name = 'mode') THEN
      ALTER TABLE ebpf_enforcement_log ADD COLUMN mode TEXT NOT NULL DEFAULT 'userspace';
    END IF;
    IF NOT EXISTS (SELECT FROM information_schema.columns WHERE table_name = 'ebpf_enforcement_log' AND column_name = 'failure_reason') THEN
      ALTER TABLE ebpf_enforcement_log ADD COLUMN failure_reason TEXT NOT NULL DEFAULT '';
    END IF;
  END IF;
END $$;
