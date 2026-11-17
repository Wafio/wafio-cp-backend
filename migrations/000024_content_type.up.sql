-- 000024_content_type: store request Content-Type on WAF decisions
ALTER TABLE waf_decisions ADD COLUMN IF NOT EXISTS content_type VARCHAR(128);
