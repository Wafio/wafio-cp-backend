-- 000044_app_fcgi_config (rollback)
ALTER TABLE apps
    DROP COLUMN IF EXISTS fcgi_doc_root,
    DROP COLUMN IF EXISTS fcgi_index;
