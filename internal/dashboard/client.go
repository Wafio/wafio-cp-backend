// Package dashboard provides shared types for the WAF log dashboard.
// All queries go directly to PostgreSQL/TimescaleDB.
package dashboard

// LogEntry is one row from waf_decisions for list response.
type LogEntry struct {
	ID        int64  `json:"id"`
	ProjectID string `json:"project_id"`
	Ts        int64  `json:"ts"`
	Action    string `json:"action"`
	Score     int    `json:"score"`
	// Strength: "block", "weak" or null, as on a decision row.
	Strength              *string `json:"strength"`
	RuleIDs               string  `json:"rule_ids,omitempty"`
	Categories            string  `json:"categories,omitempty"`
	AnalyzeMethod         string  `json:"analyze_method,omitempty"`
	Message               string  `json:"message,omitempty"`
	BlockUntilTs          int64   `json:"block_until_ts,omitempty"`
	MatchDetail           string  `json:"match_detail,omitempty"`
	MatchSource           string  `json:"match_source"`
	Method                string  `json:"method,omitempty"`
	URI                   string  `json:"uri,omitempty"`
	Host                  string  `json:"host,omitempty"`
	RemoteAddr            string  `json:"remote_addr,omitempty"`
	CountryCode           string  `json:"country_code,omitempty"`
	UserAgent             string  `json:"user_agent,omitempty"`
	RequestID             string  `json:"request_id,omitempty"`
	BodyInjectionFields   string  `json:"body_injection_fields"`
	HeaderInjectionFields string  `json:"header_injection_fields"`
}

// LogsFilter for listing logs.
type LogsFilter struct {
	FromTS    int64  // unix sec, 0 = no lower bound
	ToTS      int64  // unix sec, 0 = no upper bound
	Action    string // allow, log, block; empty = all
	Limit     int
	Offset    int
	URISearch string // optional: substring match in uri (LIKE)
}

// LogsResult is the response for list logs.
type LogsResult struct {
	Total int        `json:"total"`
	Logs  []LogEntry `json:"logs"`
}

// Summary holds aggregate counts for a time range.
type Summary struct {
	Total     int `json:"total"`
	Allow     int `json:"allow"`
	Log       int `json:"log"`
	Block     int `json:"block"`
	Challenge int `json:"challenge"`
}

// Bucket is one group (e.g. by action or time bucket).
type Bucket struct {
	Key   string `json:"key"`
	Count int    `json:"count"`
}

// TimeBucket is count per time interval.
type TimeBucket struct {
	Bucket int64 `json:"bucket"` // unix sec start of interval
	Count  int   `json:"count"`
}

// GeoLocation is one (remote_addr, country_code) aggregate with per-action counts.
type GeoLocation struct {
	RemoteAddr  string  `json:"remote_addr"`
	CountryCode string  `json:"country_code"`
	CountryName string  `json:"country_name"`
	Count       int     `json:"count"`
	Allow       int     `json:"allow"`
	Log         int     `json:"log"`
	Block       int     `json:"block"`
	City        string  `json:"city"`
	Lat         float64 `json:"lat,omitempty"`
	Lon         float64 `json:"lon,omitempty"`
	ISP         string  `json:"isp,omitempty"`
}
