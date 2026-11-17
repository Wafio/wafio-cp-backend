-- Global administrator actions have no project scope. Preserve their evidence
-- independently of project deletion and never expose it via project audit reads.
CREATE TABLE system_audit (
 id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
 actor_user_id uuid REFERENCES users(id) ON DELETE SET NULL,
 action varchar(64) NOT NULL,
 target_type varchar(32) NOT NULL,
 target_id varchar(64),
 outcome varchar(16) NOT NULL CHECK (outcome IN ('success','failure')),
 http_status integer NOT NULL,
 ip inet,
 user_agent varchar(512),
 created_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX system_audit_created_at ON system_audit(created_at DESC,id);
