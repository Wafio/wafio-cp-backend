-- Constrain project_members.role to the vocabulary the code actually accepts.
--
-- roleLevel() in internal/adapter/http/middleware.go recognises viewer(1),
-- member(2) and owner(3), and maps anything else to 0 (denied). The column had
-- no CHECK, so the vocabulary lived only in Go: a direct database write, a
-- typo in a migration, or a future handler could store a value that silently
-- denies all access. The agents table already sets the precedent with
-- agents_kind_check.
--
-- Normalise first so the constraint can be added without failing on existing
-- rows. Anything unrecognised is demoted to the least-privileged role rather
-- than deleted, so access is reduced, never granted.
UPDATE project_members
   SET role = 'viewer'
 WHERE role NOT IN ('viewer', 'member', 'owner');

ALTER TABLE project_members
    ADD CONSTRAINT project_members_role_check
    CHECK (role IN ('viewer', 'member', 'owner'));
