-- Reverse 000113: remove the JIT-runtime built-in it added. The flag a user
-- can edit on the remaining rows is never written.

DELETE FROM trace_detection_rules WHERE built_in = true AND name = 'Downgrade JIT runtime RWX memory';
