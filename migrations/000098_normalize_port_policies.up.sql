-- 000098_normalize_port_policies
--
-- Host agents and the control plane now refuse a desired state whose port
-- rules carry values the dataplane cannot represent literally
-- (ebpf.ValidatePortPolicyRule): an unknown action used to become DROP, an
-- unknown protocol "any", an unknown direction "ingress". One such stored
-- rule would make every later bundle and every firewall write fail. This
-- rewrites agents.desired_state.port_policies once:
--   * action / proto / direction are trimmed and lower-cased; allow, drop,
--     log / tcp, udp, any / ingress, egress, both are kept ("Allow" means
--     allow, as the operator wrote it);
--   * anything else, empty included, becomes what the dataplane already
--     enforced: action drop, proto any, direction ingress;
--   * rules outside port 1-65535 are removed (they never matched a packet);
--   * of several rules for one map slot (port, proto, direction) the last
--     is kept, as the sequential map writes on the agent did.
-- Other fields (ttl_ms, expires_at, hit_count, added_at) are kept as they are.

WITH src AS (
    SELECT a.id, t.ord, t.r
    FROM agents a
    CROSS JOIN LATERAL jsonb_array_elements(a.desired_state -> 'port_policies') WITH ORDINALITY AS t(r, ord)
    WHERE jsonb_typeof(a.desired_state -> 'port_policies') = 'array'
),
norm AS (
    SELECT id, ord,
           r || jsonb_build_object(
               'action', CASE lower(btrim(COALESCE(r ->> 'action', '')))
                             WHEN 'allow' THEN 'allow' WHEN 'log' THEN 'log' ELSE 'drop' END,
               'proto', CASE lower(btrim(COALESCE(r ->> 'proto', '')))
                             WHEN 'tcp' THEN 'tcp' WHEN 'udp' THEN 'udp' ELSE 'any' END,
               'direction', CASE lower(btrim(COALESCE(r ->> 'direction', '')))
                             WHEN 'egress' THEN 'egress' WHEN 'both' THEN 'both' ELSE 'ingress' END
           ) AS r
    FROM src
    WHERE jsonb_typeof(r) = 'object'
      AND jsonb_typeof(r -> 'port') = 'number'
      AND (CASE WHEN (r ->> 'port') ~ '^[0-9]{1,5}$' THEN (r ->> 'port')::int ELSE 0 END) BETWEEN 1 AND 65535
),
last_per_slot AS (
    SELECT DISTINCT ON (id, (r ->> 'port')::int, r ->> 'proto', r ->> 'direction') id, ord, r
    FROM norm
    ORDER BY id, (r ->> 'port')::int, r ->> 'proto', r ->> 'direction', ord DESC
),
rebuilt AS (
    SELECT a.id,
           COALESCE(jsonb_agg(l.r ORDER BY l.ord) FILTER (WHERE l.id IS NOT NULL), '[]'::jsonb) AS rules
    FROM agents a
    LEFT JOIN last_per_slot l ON l.id = a.id
    WHERE jsonb_typeof(a.desired_state -> 'port_policies') = 'array'
    GROUP BY a.id
)
UPDATE agents a
SET desired_state = jsonb_set(a.desired_state, '{port_policies}', rebuilt.rules)
FROM rebuilt
WHERE a.id = rebuilt.id
  AND a.desired_state -> 'port_policies' IS DISTINCT FROM rebuilt.rules;
