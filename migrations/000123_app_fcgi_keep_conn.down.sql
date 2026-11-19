SET lock_timeout = '5s';

ALTER TABLE apps
    DROP COLUMN IF EXISTS fcgi_keep_conn;

RESET lock_timeout;
