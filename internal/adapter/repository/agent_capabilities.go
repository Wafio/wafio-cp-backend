package repository

import "context"

// AgentCapabilities is what one WAF agent reported in its last Hello: nil =
// unknown (never connected, or an agent built before Hello.features existed).
type AgentCapabilities struct {
	ScriptRules *bool // false: cannot run script rules
	Maintenance *bool // false: cannot answer with the maintenance page
}

// AppAgentCapabilities returns the capabilities of the WAF agent that serves
// the application (at most one: an application has one enabled assignment).
func (r *WAFRepo) AppAgentCapabilities(ctx context.Context, projectID, appID string) ([]AgentCapabilities, error) {
	return r.agentCapabilities(ctx,
		`SELECT a.script_rules, a.maintenance_mode
		 FROM waf_agent_apps waa
		 JOIN apps ap ON ap.id = waa.app_id AND ap.project_id = $1
		 JOIN agents a ON a.id = waa.agent_id AND a.project_id = ap.project_id AND a.deleted_at IS NULL
		 WHERE waa.app_id = $2 AND waa.enabled = TRUE`, projectID, appID)
}

func (r *WAFRepo) agentCapabilities(ctx context.Context, query string, args ...any) ([]AgentCapabilities, error) {
	rows, err := r.pool.Query(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []AgentCapabilities
	for rows.Next() {
		var c AgentCapabilities
		if err := rows.Scan(&c.ScriptRules, &c.Maintenance); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// AllReport reports whether at least one agent is listed and every one reports
// false for the capability pick selects. An agent that never said (nil) does
// not count as false.
func AllReport(caps []AgentCapabilities, pick func(AgentCapabilities) *bool) bool {
	for _, c := range caps {
		if v := pick(c); v == nil || *v {
			return false
		}
	}
	return len(caps) > 0
}
