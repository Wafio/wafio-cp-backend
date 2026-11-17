-- The HTTP status the client received for a WAF decision. NULL = not recorded (a row from before the agent
-- filled it, or an event without a status, such as a WebSocket handshake log); the API shows NULL as 0.
-- Nullable, no default: a metadata-only ALTER that rewrites no chunk, compressed or not. lock_timeout bounds
-- the wait behind a long reader, as in 000086. A rerun is safe (IF NOT EXISTS).
SET lock_timeout = '5s';

ALTER TABLE waf_decisions ADD COLUMN IF NOT EXISTS status INTEGER;

RESET lock_timeout;
