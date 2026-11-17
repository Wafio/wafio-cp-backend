-- 000018_mitre_enforcement.down.sql
-- Reverses 000018_mitre_enforcement.up.sql.

DROP INDEX IF EXISTS idx_enforcement_mitre_technique;
DROP INDEX IF EXISTS idx_enforcement_severity;

ALTER TABLE ebpf_enforcement_log
  DROP COLUMN IF EXISTS mitre_technique_id,
  DROP COLUMN IF EXISTS mitre_technique_name,
  DROP COLUMN IF EXISTS mitre_tactic,
  DROP COLUMN IF EXISTS severity,
  DROP COLUMN IF EXISTS tags;
