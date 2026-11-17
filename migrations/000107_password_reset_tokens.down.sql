-- Reverse 000107: outstanding password reset links stop working (their rows
-- are dropped); the control plane that issued them must be rolled back first.
DROP TABLE IF EXISTS password_reset_tokens;
