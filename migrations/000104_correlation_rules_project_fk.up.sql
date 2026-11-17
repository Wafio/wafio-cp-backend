-- correlation_rules.project_id had no foreign key (000083), so a deleted
-- project's chains stayed behind. Orphans are deleted (irreversible: they
-- belong to no project and no route can reach them), then the FK is added
-- with ON DELETE CASCADE like the other tenant tables. The table holds a
-- handful of rows per project, so validating in place is cheap.
DELETE FROM correlation_rules c
 WHERE NOT EXISTS (SELECT 1 FROM projects p WHERE p.id = c.project_id);

ALTER TABLE correlation_rules
    ADD CONSTRAINT correlation_rules_project_id_fkey
    FOREIGN KEY (project_id) REFERENCES projects(id) ON DELETE CASCADE;
