-- Runtime Security kill-policy guard.
--
-- ebpf.ValidateEnforcementPolicy now rejects an action=kill policy that has no
-- narrowing match (comm, filename, uid, dest port, dest IP) unless the
-- operator set kill_acknowledged. Both columns must survive the DB round-trip:
-- the server replays these rows as the host bundle, and the agent validates
-- the whole bundle before applying it (one rejected policy rolls back all).
--
-- match_dest_ip was previously dropped on persistence, so a dest-IP-only
-- policy came back from the DB without its only narrowing field.
ALTER TABLE ebpf_trace_policies
    ADD COLUMN IF NOT EXISTS kill_acknowledged BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN IF NOT EXISTS match_dest_ip VARCHAR(64) NOT NULL DEFAULT '';

-- Backfill: broad kill policies that already exist were accepted by an
-- operator before the guard shipped. Mark them acknowledged so the next
-- bundle push does not reject the agent's entire policy set. New broad kill
-- policies must opt in explicitly.
UPDATE ebpf_trace_policies
   SET kill_acknowledged = TRUE
 WHERE lower(action) = 'kill'
   AND btrim(match_comm) = ''
   AND btrim(match_filename) = ''
   AND match_uid IS NULL
   AND btrim(match_dest_port) = '';
