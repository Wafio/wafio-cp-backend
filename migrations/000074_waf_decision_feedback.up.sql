CREATE TABLE waf_decision_feedback (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    project_id uuid NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    app_id uuid NOT NULL REFERENCES apps(id) ON DELETE CASCADE,
    decision_id bigint NOT NULL,
    decision_recorded_at timestamptz NOT NULL,
    actor_user_id uuid NOT NULL,
    verdict text NOT NULL CHECK (verdict IN ('true_positive', 'false_positive', 'unsure')),
    note text NOT NULL DEFAULT '' CHECK (char_length(note) <= 2000),
    created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX waf_decision_feedback_scope ON waf_decision_feedback(project_id, app_id, decision_id, decision_recorded_at, created_at DESC);
