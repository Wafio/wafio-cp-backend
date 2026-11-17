ALTER TABLE apps
    DROP COLUMN IF EXISTS proxy_max_conns,
    DROP COLUMN IF EXISTS proxy_conn_wait_ms,
    DROP COLUMN IF EXISTS proxy_read_buf,
    DROP COLUMN IF EXISTS proxy_write_buf;
