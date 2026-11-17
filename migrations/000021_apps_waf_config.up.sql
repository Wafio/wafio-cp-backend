-- 000021_apps_waf_config
-- Add per-route WAF tuning knobs to the apps table so that each route
-- served by an inline-proxy WAF agent can carry its own threshold,
-- paranoia level, and maximum request body size.
--
-- Defaults match the previous hardcoded values in the Bundle handler so
-- existing routes keep their behaviour until an operator explicitly changes
-- them via the WAF Agent UI.

ALTER TABLE apps
    ADD COLUMN IF NOT EXISTS waf_threshold  INT NOT NULL DEFAULT 200,
    ADD COLUMN IF NOT EXISTS waf_paranoia   INT NOT NULL DEFAULT 1,
    ADD COLUMN IF NOT EXISTS waf_body_limit INT NOT NULL DEFAULT 1048576;
