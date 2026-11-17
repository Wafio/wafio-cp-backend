-- 000101_trace_policy_identity (UP)
-- A trace policy is identified on its agent by policy_id: the host agent
-- refuses the whole trace_policies bundle when two rows share one. 000027
-- declares the unique index uq_trace_policies_agent_pid, but it is created
-- IF NOT EXISTS after a non-unique index on the same columns, so a database
-- whose table predates it, or where it was dropped, may lack it. This
-- migration guarantees it.
--
-- 1. Remove duplicate (agent_id, policy_id) rows, keeping the newest
--    (updated_at, then created_at, then id). NOT REVERSIBLE: the removed rows
--    are gone; the agent could not run them anyway (it refused the bundle).
-- 2. Create the unique index where policy_id is set (no-op when present).

DELETE FROM ebpf_trace_policies p
 USING (
    SELECT id,
           row_number() OVER (PARTITION BY agent_id, policy_id
                              ORDER BY updated_at DESC, created_at DESC, id DESC) AS rn
      FROM ebpf_trace_policies
     WHERE policy_id IS NOT NULL
 ) d
 WHERE p.id = d.id AND d.rn > 1;

CREATE UNIQUE INDEX IF NOT EXISTS uq_trace_policies_agent_pid
    ON ebpf_trace_policies (agent_id, policy_id)
    WHERE policy_id IS NOT NULL;
