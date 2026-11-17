-- 000018_mitre_enforcement.up.sql
-- Adds MITRE ATT&CK-style metadata to enforcement log rows.
--
-- Rationale
-- ─────────
-- The trace_manager pushes an enforcement log entry every time a policy
-- matches. Downstream security tooling (SIEM, XDR dashboards) needs the
-- triggering policy's MITRE technique so it can pivot into ATT&CK views
-- without having to look up the policy definition separately. We store
-- the metadata on every log row (denormalized) because:
--
--   1. Policies live *inside* the agent (see internal/ebpf/trace_policy.go).
--      They are push-delivered to agents but are not relationally joined to
--      log rows at query time — the agent writes a flat log record.
--   2. Policies can change between "event happened" and "event queried" →
--      we preserve a point-in-time snapshot of the MITRE attribution for
--      accurate historical reporting.
--
-- Fields
--   mitre_technique_id   — e.g. "T1059.004" (Bash sub-technique).
--   mitre_technique_name — human label, e.g. "Unix Shell".
--   mitre_tactic         — kill-chain tactic, e.g. "execution".
--   severity             — policy severity at log time (low|medium|high|critical).
--   tags                 — free-form tags array (JSONB for flexibility).
--
-- All fields are nullable and default empty so the change is fully
-- backward-compatible with existing log rows and older agents that do not
-- send the fields.

ALTER TABLE ebpf_enforcement_log
  ADD COLUMN IF NOT EXISTS mitre_technique_id   TEXT  NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS mitre_technique_name TEXT  NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS mitre_tactic         TEXT  NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS severity             TEXT  NOT NULL DEFAULT '',
  ADD COLUMN IF NOT EXISTS tags                 JSONB NOT NULL DEFAULT '[]'::jsonb;

-- Partial index to accelerate SIEM queries filtering by technique.
CREATE INDEX IF NOT EXISTS idx_enforcement_mitre_technique
  ON ebpf_enforcement_log (mitre_technique_id)
  WHERE mitre_technique_id <> '';

CREATE INDEX IF NOT EXISTS idx_enforcement_severity
  ON ebpf_enforcement_log (severity)
  WHERE severity <> '';
