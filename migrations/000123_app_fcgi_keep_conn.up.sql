-- Per-application FCGI_KEEP_CONN, the same choice as nginx fastcgi_keep_conn.
--
-- apps.fcgi_keep_conn   FALSE the WAF agent closes the FastCGI connection after
--                             each reply (the default);
--                       TRUE  it keeps the connection and reuses it for the next
--                             request.
--                       Read only for an fcgi: upstream, like fcgi_doc_root and
--                       fcgi_index (000044).
--
-- Why FALSE: PHP-FPM runs unread request body bytes on a kept connection as a
-- second FastCGI request (CVE-2026-129289). Turn it on only if PHP is at least
-- 8.2.36, 8.3.37, 8.4.28 or 8.5.13 for its 8.2, 8.3, 8.4 or 8.5 series; 8.1 and
-- older are not fixed. Operators on such a PHP turn it on per application.
--
-- The ALTER is metadata-only (a constant default needs no table rewrite).
-- lock_timeout bounds a wait behind a long reader the same way as 000116
-- (rerun is safe: IF NOT EXISTS).
SET lock_timeout = '5s';

ALTER TABLE apps
    ADD COLUMN IF NOT EXISTS fcgi_keep_conn BOOLEAN NOT NULL DEFAULT false;

RESET lock_timeout;
