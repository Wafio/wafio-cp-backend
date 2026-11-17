CREATE TABLE waf_custom_rules (
    id               UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    app_id           UUID        NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    name             TEXT        NOT NULL,
    description      TEXT        NOT NULL DEFAULT '',
    enabled          BOOLEAN     NOT NULL DEFAULT true,
    priority         INT         NOT NULL DEFAULT 0,
    mode             TEXT        NOT NULL CHECK (mode IN ('gui', 'script')),
    conditions       JSONB,
    condition_logic  TEXT        NOT NULL DEFAULT 'and'
                                 CHECK (condition_logic IN ('and', 'or')),
    action           TEXT        NOT NULL DEFAULT 'block'
                                 CHECK (action IN ('block', 'allow', 'challenge', 'log')),
    script           TEXT,
    created_at       TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at       TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX waf_custom_rules_app_priority_idx ON waf_custom_rules (app_id, priority);
