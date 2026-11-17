-- Deduplicate enforcement log: collapse rows that share the same
-- (agent_id, policy_id, event_time) — these were created by agent push retries
-- (GetEnforcementLog was non-destructive so the same buffered entries were
-- re-pushed every tick), then add a unique index so future re-pushes become
-- idempotent.

-- 1) Collapse existing duplicates: keep only the smallest id per group.
DELETE FROM ebpf_enforcement_log a
USING ebpf_enforcement_log b
WHERE a.id > b.id
  AND a.agent_id  = b.agent_id
  AND a.policy_id = b.policy_id
  AND a.event_time = b.event_time;

-- 3) Prevent future duplicates. event_time has microsecond precision so
--    distinct syscalls (even back-to-back execve in the same ms) remain
--    distinct rows.
CREATE UNIQUE INDEX IF NOT EXISTS uq_enforcement_event
    ON ebpf_enforcement_log (agent_id, policy_id, event_time);
