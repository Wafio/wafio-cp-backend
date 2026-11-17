-- 000101_trace_policy_identity (DOWN)
-- The duplicate rows removed by the up step are not restored (irreversible).
-- The unique index uq_trace_policies_agent_pid is declared by 000027, so
-- schema version 100 already has it: dropping it here would leave a database
-- at version 100 weaker than one migrated straight to 100. It stays; 000027
-- down drops it with the table. The statement keeps the file non-empty.
SELECT 1;
