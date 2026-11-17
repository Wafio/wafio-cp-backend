-- 000103_bump_desired_state_revision (DOWN)
-- A revision is never lowered: agents refuse a generation below the one
-- they applied. Data-only up step; nothing to undo. The statement keeps the
-- file non-empty.
SELECT 1;
