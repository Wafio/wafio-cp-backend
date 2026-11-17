-- 000103_bump_desired_state_revision (bug hunt 2026-10-16)
--
-- Migrations 000098 (port-policy normalisation) and 000100 (port-scan
-- threshold clamp) rewrote agents.desired_state but kept its _revision,
-- which the control plane delivers as the ebpf_state bundle generation. A
-- host agent that had applied revision N before the upgrade received
-- generation N again with different content after reconnecting, refused it
-- ("conflicting ebpf_state bundle generation") and kept the old firewall
-- state.
--
-- Which rows those migrations changed can no longer be told apart, so every
-- desired state that carries a revision gets a new one, in the format and
-- scale EBPFRepo.CompareAndSwapDesiredState writes (decimal text, at least
-- the previous revision + 1, else the database clock in Unix nanoseconds).
-- Hosts whose content did not change receive the same policy under a newer
-- generation and re-apply it (apply is by diff; nothing is cleared first).
-- Rows without a revision are left alone: the control plane assigns one on
-- the first push.
--
-- Rule for later migrations: a statement that changes desired_state must
-- bump _revision in the same statement.

UPDATE agents
SET desired_state = jsonb_set(
        desired_state, '{_revision}',
        to_jsonb(GREATEST(
            COALESCE((desired_state ->> '_revision')::numeric, 0) + 1,
            (extract(epoch FROM clock_timestamp()) * 1000000000)::numeric
        )::bigint::text))
WHERE jsonb_typeof(desired_state) = 'object'
  AND desired_state ? '_revision'
  AND CASE WHEN (desired_state ->> '_revision') ~ '^[0-9]{1,19}$'
           THEN (desired_state ->> '_revision')::numeric < 9223372036854775807
           ELSE false END;
