-- Reverse 000104: drop the FK. Deleted orphans are not restored.
ALTER TABLE correlation_rules
    DROP CONSTRAINT IF EXISTS correlation_rules_project_id_fkey;
