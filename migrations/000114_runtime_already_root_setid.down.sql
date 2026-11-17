-- Reverse 000114: remove the already-root built-in it added. The flag a user
-- can edit on the remaining rows is never written.

DELETE FROM trace_detection_rules WHERE built_in = true AND name = 'Downgrade already-root credential change';
