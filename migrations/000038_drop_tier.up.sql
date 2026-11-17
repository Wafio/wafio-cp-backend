-- Remove tier/plan column from users; WAFio no longer uses a plan-based model.
DROP INDEX IF EXISTS idx_users_tier;
ALTER TABLE users DROP COLUMN IF EXISTS tier;
