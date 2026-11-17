-- Drops the per-app index (built by 000089 on a plain table, or by the
-- post-migration per-chunk step on a hypertable).
DROP INDEX IF EXISTS waf_decisions_app_id_recorded_at;
