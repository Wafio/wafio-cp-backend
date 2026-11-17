-- Reverses 000112: stops the compression policies, decompresses every
-- compressed chunk (needs disk for the uncompressed rows: ±5-15x the
-- compressed size) and turns compression off. Rows are unchanged either way.
DO $cmp$
DECLARE
    t text;
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'timescaledb') THEN
        RETURN;
    END IF;
    FOREACH t IN ARRAY ARRAY['waf_decisions', 'host_security_events', 'host_fw_features', 'host_sec_features', 'host_enforcement_events']
    LOOP
        CONTINUE WHEN NOT EXISTS (
            SELECT 1 FROM timescaledb_information.hypertables
            WHERE hypertable_schema = current_schema() AND hypertable_name = t AND compression_enabled);
        PERFORM remove_compression_policy(t::regclass, if_exists => true);
        PERFORM decompress_chunk(c, true) FROM show_chunks(t::regclass) c;
        EXECUTE format('ALTER TABLE %I SET (timescaledb.compress = false)', t);
    END LOOP;
END
$cmp$;
