-- 000044_app_fcgi_config
-- Add FastCGI-specific columns for apps that use a fcgi: upstream.
-- fcgi_doc_root: filesystem path served as DOCUMENT_ROOT / SCRIPT_FILENAME prefix.
-- fcgi_index:    default PHP file when the request path maps to a directory (e.g. index.php).
-- Both are optional — only relevant when upstream_url starts with "fcgi:".

ALTER TABLE apps
    ADD COLUMN IF NOT EXISTS fcgi_doc_root TEXT NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS fcgi_index    TEXT NOT NULL DEFAULT 'index.php';
