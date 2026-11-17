-- 000091_proxy_trust_forwarded_backfill
--
-- trust_forwarded used to default to TRUE when the key was absent from
-- apps.proxy_config. The WAF agent now reads an absent key as FALSE: the TCP
-- peer is the client unless the peer is a trusted proxy. Apps that relied on
-- the old default keep their behaviour: this migration writes an explicit
-- "trust_forwarded": true into every proxy_config that lacks the key.
--
-- With no trusted_proxies set, an explicit true means forwarded headers are
-- read only from loopback, RFC 1918 and RFC 4193 peers; the control plane
-- flags such apps with proxy_warnings TRUSTED_PROXIES_UNSET until the
-- operator lists the load balancer's addresses.
--
-- "_trust_forwarded_backfill" marks the rows this migration changed, so the
-- down step removes only what it added. Saving the proxy settings again
-- replaces the whole object and drops the marker; from then on the value is
-- the operator's own and the down step leaves it alone.
--
-- Data only; idempotent (a second run finds the key present). A key that is
-- present with a JSON null already meant false and is left alone. "->" is
-- used instead of the "?" operator so no driver mistakes it for a
-- placeholder.

UPDATE apps
   SET proxy_config = proxy_config
       || '{"trust_forwarded": true, "_trust_forwarded_backfill": "000091"}'::jsonb
 WHERE jsonb_typeof(proxy_config) = 'object'
   AND proxy_config -> 'trust_forwarded' IS NULL;

-- A JSON null proxy_config parsed as the all-default config, i.e. trusted.
UPDATE apps
   SET proxy_config = '{"trust_forwarded": true, "_trust_forwarded_backfill": "000091"}'::jsonb
 WHERE jsonb_typeof(proxy_config) = 'null';
