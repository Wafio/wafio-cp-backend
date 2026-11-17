-- Rollback of 000091: remove only what the up step added.
--
-- Rows still carrying the "_trust_forwarded_backfill" marker lose the marker,
-- and lose trust_forwarded too while it is still the true the up step wrote
-- (the previous agent reads an absent key as true, so behaviour is kept). A
-- row whose trust_forwarded was changed through the API while the marker
-- survived keeps that value. Rows without the marker — never touched, or
-- saved again since — are left alone, and so is trusted_proxies, which the
-- previous agent ignores.

UPDATE apps
   SET proxy_config = CASE
           WHEN proxy_config -> 'trust_forwarded' = 'true'::jsonb
               THEN proxy_config - 'trust_forwarded' - '_trust_forwarded_backfill'
           ELSE proxy_config - '_trust_forwarded_backfill'
       END
 WHERE jsonb_typeof(proxy_config) = 'object'
   AND proxy_config -> '_trust_forwarded_backfill' IS NOT NULL;
