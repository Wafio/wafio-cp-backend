-- Migration 000094: one enabled route per listen address on a WAF agent.
--
-- 000022 dropped the per-project Host-header index and nothing replaced it, so
-- two applications assigned to the same agent could share listen_host:
-- listen_port; the agent then failed to bind the second one. The address lives
-- on apps and the agent on waf_agent_apps, so the assignment row carries a
-- copy of the address (kept in step by triggers) and a partial unique index
-- covers enabled assignments that have a listen port.
--
-- listen_host is compared in canonical form: empty/NULL is 0.0.0.0 (what the
-- agent binds), IP literals are normalised through inet ("::0" = "::"),
-- anything else (legacy host names) is lower-cased.
--
-- If existing data already has duplicates this migration fails with the list
-- and changes nothing. Change the listen address of, or unassign, all but one
-- application per address, reset the dirty flag
-- (UPDATE schema_migrations SET version = <previous>, dirty = false) and run
-- `wafio migrate up` again.

CREATE OR REPLACE FUNCTION wafio_listen_host_key(h text) RETURNS text
LANGUAGE plpgsql IMMUTABLE AS $$
DECLARE
    v text := NULLIF(btrim(h), '');
BEGIN
    IF v IS NULL THEN
        RETURN '0.0.0.0';
    END IF;
    BEGIN
        RETURN host(v::inet);
    EXCEPTION WHEN invalid_text_representation THEN
        RETURN lower(v);
    END;
END;
$$;

-- 1. Refuse to continue while duplicates exist, naming every one of them.
DO $$
DECLARE
    dups text;
BEGIN
    SELECT string_agg(format('agent %s (%s) %s:%s used by %s', d.agent_id, d.agent_name, d.host_key, d.listen_port, d.app_list),
                      '; ' ORDER BY d.agent_id, d.host_key, d.listen_port)
      INTO dups
      FROM (
        SELECT waa.agent_id,
               COALESCE(ag.name, '?') AS agent_name,
               wafio_listen_host_key(a.listen_host) AS host_key,
               a.listen_port,
               string_agg(format('%s (%s)', a.name, a.id), ', ' ORDER BY a.name, a.id) AS app_list
          FROM waf_agent_apps waa
          JOIN apps a ON a.id = waa.app_id
          LEFT JOIN agents ag ON ag.id = waa.agent_id
         WHERE waa.enabled AND a.listen_port IS NOT NULL
         GROUP BY waa.agent_id, ag.name, wafio_listen_host_key(a.listen_host), a.listen_port
        HAVING count(*) > 1
      ) d;
    IF dups IS NOT NULL THEN
        RAISE EXCEPTION 'migration 000094: listen addresses used by more than one application on the same WAF agent: %. Change the listen address of, or unassign, all but one application per address, then reset schema_migrations (version = previous, dirty = false) and rerun migrate up.', dups;
    END IF;
END;
$$;

-- 2. The assignment row carries the address of its application.
ALTER TABLE waf_agent_apps
    ADD COLUMN listen_host_key TEXT,
    ADD COLUMN listen_port     INTEGER;

UPDATE waf_agent_apps waa
   SET listen_host_key = wafio_listen_host_key(a.listen_host),
       listen_port     = a.listen_port
  FROM apps a
 WHERE a.id = waa.app_id;

-- 3. Keep the copy in step. Assignment writes read the application row FOR
--    SHARE, so a concurrent address change on apps waits for (or is waited on
--    by) the assignment and the trigger below always sees the committed row.
CREATE OR REPLACE FUNCTION waf_agent_apps_copy_listen_addr() RETURNS trigger
LANGUAGE plpgsql AS $$
DECLARE
    h text;
    p integer;
BEGIN
    SELECT listen_host, listen_port INTO h, p FROM apps WHERE id = NEW.app_id FOR SHARE;
    NEW.listen_host_key := wafio_listen_host_key(h);
    NEW.listen_port := p;
    RETURN NEW;
END;
$$;

CREATE TRIGGER waf_agent_apps_listen_addr
    BEFORE INSERT OR UPDATE ON waf_agent_apps
    FOR EACH ROW EXECUTE FUNCTION waf_agent_apps_copy_listen_addr();

CREATE OR REPLACE FUNCTION apps_sync_listen_addr() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    -- The BEFORE trigger on waf_agent_apps recomputes the copy from the
    -- updated apps row; the unique index then rejects a clash, and the error
    -- surfaces from this UPDATE on apps.
    UPDATE waf_agent_apps SET updated_at = updated_at WHERE app_id = NEW.id;
    RETURN NULL;
END;
$$;

CREATE TRIGGER apps_listen_addr_sync
    AFTER UPDATE OF listen_host, listen_port ON apps
    FOR EACH ROW
    WHEN (OLD.listen_host IS DISTINCT FROM NEW.listen_host OR OLD.listen_port IS DISTINCT FROM NEW.listen_port)
    EXECUTE FUNCTION apps_sync_listen_addr();

-- 4. One enabled route per (agent, listen host, listen port).
CREATE UNIQUE INDEX uq_waf_agent_apps_listen_addr
    ON waf_agent_apps (agent_id, listen_host_key, listen_port)
    WHERE enabled AND listen_port IS NOT NULL;
