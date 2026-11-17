package domain

import (
	"strings"
	"time"
)

// ProjectLogEntry is one dashboard log row (per request/decision) for a project.
// Used for dashboard: filter by project, time range, action, full-text search.
type ProjectLogEntry struct {
	ProjectID     string    `json:"project_id"`
	Timestamp     time.Time `json:"ts"`
	Action        string    `json:"action"` // allow, log, block
	Score         int       `json:"score"`
	Categories    []string  `json:"categories"`
	AnalyzeMethod string    `json:"analyze_method"` // semantic, policy, geo
	Message       string    `json:"message,omitempty"`
	BlockUntil    time.Time `json:"block_until,omitempty"`
	MatchDetail   string    `json:"match_detail,omitempty"`
	MatchSource   string    `json:"match_source"`
	// Request context
	Method      string `json:"method"`
	URI         string `json:"uri"`
	Host        string `json:"host,omitempty"`
	RemoteAddr  string `json:"remote_addr,omitempty"`
	CountryCode string `json:"country_code,omitempty"` // ISO 3166-1 alpha-2 from GeoIP (IP origin country)
	UserAgent   string `json:"user_agent,omitempty"`
	RequestID   string `json:"request_id,omitempty"`
	// BodyInjectionFields: snippet of body (POST/PUT/PATCH) that was detected, truncated; for log/dashboard. Empty if GET or body empty.
	BodyInjectionFields string `json:"body_injection_fields,omitempty"`
	// HeaderInjectionFields: snippet of header values that look suspicious; truncated; empty if none.
	HeaderInjectionFields string `json:"header_injection_fields,omitempty"`
}

// BodyInjectionFieldsMaxLen is the maximum length (bytes) of body_injection_fields in log/SIEM.
const BodyInjectionFieldsMaxLen = 512

// HeaderInjectionFieldsMaxLen is the maximum length (bytes) of header_injection_fields in log/SIEM.
const HeaderInjectionFieldsMaxLen = 512

func looksSuspiciousHeaderValue(v string) bool {
	if v == "" {
		return false
	}
	lower := strings.ToLower(v)

	// XSS indicators
	if strings.Contains(lower, "<") ||
		strings.Contains(lower, "%3c") ||
		strings.Contains(lower, "%3e") ||
		strings.Contains(lower, "script") ||
		strings.Contains(lower, "javascript:") ||
		strings.Contains(lower, "onerror=") ||
		strings.Contains(lower, "onload=") ||
		strings.Contains(lower, "onclick=") ||
		strings.Contains(lower, "alert(") ||
		strings.Contains(lower, "confirm(") {
		return true
	}

	// SQLi indicators (direct patterns + quotes)
	if strings.Contains(lower, "union ") ||
		strings.Contains(lower, "select ") ||
		strings.Contains(lower, "insert ") ||
		strings.Contains(lower, "delete ") ||
		strings.Contains(lower, "drop ") ||
		strings.Contains(lower, "sleep(") ||
		strings.Contains(lower, "benchmark(") ||
		strings.Contains(lower, "--") || // SQL comment
		strings.Contains(lower, "/*") || // SQL comment
		strings.Contains(lower, "*/") { // SQL comment end
		return true
	}

	// Quote injection indicators: ' or " with SQL-like context
	if (strings.Contains(v, "'") || strings.Contains(v, "\"")) &&
		(strings.Contains(lower, " or ") || strings.Contains(lower, " and ") ||
			strings.Contains(lower, "=") || strings.Contains(lower, ";")) {
		return true
	}

	// Encoding bypass patterns
	if strings.Contains(v, "%25") || strings.Contains(v, "&#") {
		return true
	}

	return false
}

// ProjectLogger writes per-project log entries asynchronously (non-blocking).
// Implementations should buffer and batch for performance.
// Safe for concurrent use.
type ProjectLogger interface {
	// Log enqueues the entry for writing; must not block the caller.
	Log(projectID string, entry *ProjectLogEntry)
}
