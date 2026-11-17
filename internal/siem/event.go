package siem

import "time"

// Event is a single WAF security event (BLOCK or LOG), sent to webhook.
type Event struct {
	Action        string    `json:"action"`
	Score         int       `json:"score"`
	Categories    []string  `json:"categories,omitempty"`
	AnalyzeMethod string    `json:"analyze_method,omitempty"` // "semantic", "policy", "geo", "bot", ...
	Timestamp     time.Time `json:"timestamp"`
	Method        string    `json:"method,omitempty"`
	URI           string    `json:"uri,omitempty"`
	Host          string    `json:"host,omitempty"`
	RemoteAddr    string    `json:"remote_addr,omitempty"`
	UserAgent     string    `json:"user_agent,omitempty"`
	RequestID     string    `json:"request_id,omitempty"`
	MatchDetail   string    `json:"match_detail,omitempty"`
	MatchSource   string    `json:"match_source"`
	// Taxonomy for SIEM/audit (semantic scan block)
	CWE             string   `json:"cwe,omitempty"`              // e.g. CWE-89
	MITRETechniques []string `json:"mitre_techniques,omitempty"` // e.g. ["T1190"]
	// BodyInjectionFields: snippet of request body (POST/PUT/PATCH) that was detected, truncated and sanitized. Empty if GET or body empty.
	// Always included in JSON (no omitempty) for enterprise audit trail consistency.
	BodyInjectionFields string `json:"body_injection_fields"`
	// HeaderInjectionFields: snippet of header values that look suspicious; truncated; empty if none.
	// Always included in JSON (no omitempty) for enterprise audit trail consistency.
	HeaderInjectionFields string `json:"header_injection_fields"`
}
