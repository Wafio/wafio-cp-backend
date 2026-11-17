-- Drops the flagged-decision index of the feedback summary (built by 000109
-- on a plain table, or by the post-migration per-chunk step on a hypertable).
DROP INDEX IF EXISTS waf_decisions_flagged_agent_recorded_at;
