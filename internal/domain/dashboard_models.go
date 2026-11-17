package domain

// Dashboard read models returned by the overview ports. The
// PostgreSQL adapter aliases these types.

import (
	"encoding/json"
	"time"
)

// AgentWithHostInfo is the read-model used by the UI for the Agents pages.
type AgentWithHostInfo struct {
	ID            string          `json:"id"`
	Name          string          `json:"name"`
	Kind          string          `json:"kind"`
	ProjectID     string          `json:"project_id,omitempty"`
	HostID        string          `json:"host_id,omitempty"`
	CallbackURL   string          `json:"callback_url,omitempty"`
	LastSeen      *time.Time      `json:"last_seen,omitempty"`
	IsOnline      bool            `json:"is_online"`
	CreatedAt     time.Time       `json:"created_at"`
	Hostname      string          `json:"hostname,omitempty"`
	Version       string          `json:"version,omitempty"`
	HostOS        string          `json:"host_os,omitempty"`
	HostOSVersion string          `json:"host_os_version,omitempty"`
	HostKernel    string          `json:"host_kernel,omitempty"`
	HostArch      string          `json:"host_arch,omitempty"`
	HostCPUCount  int             `json:"host_cpu_count,omitempty"`
	HostMemory    int64           `json:"host_memory,omitempty"`
	HostVirt      string          `json:"host_virt,omitempty"`
	HostBootTime  *time.Time      `json:"host_boot_time,omitempty"`
	HostUpdatedAt *time.Time      `json:"host_updated_at,omitempty"`
	HostInfo      json.RawMessage `json:"host_info,omitempty"`
	// Process and installation metadata
	BinaryPath  string `json:"binary_path,omitempty"`
	InstallDir  string `json:"install_dir,omitempty"`
	ServiceName string `json:"service_name,omitempty"`
	ServiceUser string `json:"service_user,omitempty"`
	// ProxyListenPort is the WAF agent's inline-proxy listen port override.
	// Nil = no override (agent uses startup --proxy-listen).
	ProxyListenPort *int `json:"proxy_listen_port,omitempty"`
	// WAF inspection-health counters from the latest heartbeat (WAF agents
	// only; cumulative since agent start). Omitted when never reported.
	AnalyzePanicsTotal        *int64 `json:"analyze_panics_total,omitempty"`
	EnginePanicsTotal         *int64 `json:"engine_panics_total,omitempty"`
	PartialCoverageTotal      *int64 `json:"partial_coverage_total,omitempty"`
	ParseBudgetExhaustedTotal *int64 `json:"parse_budget_exhausted_total,omitempty"`
	// Heartbeat fields 11-19 (migration 000096): script-rule and
	// recovered-panic counters, and the analyze latency of the agent's last
	// 5 minutes in microseconds (percentiles omitted with no analyses).
	ScriptIncompleteTotal    *int64 `json:"script_incomplete_total,omitempty"`
	ScriptErrorsTotal        *int64 `json:"script_errors_total,omitempty"`
	ScriptRulesRejectedTotal *int64 `json:"script_rules_rejected_total,omitempty"`
	ScriptRunsInFlight       *int64 `json:"script_runs_in_flight,omitempty"`
	AgentPanicsTotal         *int64 `json:"agent_panics_total,omitempty"`
	AnalyzeLatencyP50Us      *int64 `json:"analyze_latency_p50_us,omitempty"`
	AnalyzeLatencyP95Us      *int64 `json:"analyze_latency_p95_us,omitempty"`
	AnalyzeLatencyP99Us      *int64 `json:"analyze_latency_p99_us,omitempty"`
	AnalyzeLatencySamples    *int64 `json:"analyze_latency_samples,omitempty"`
	// Heartbeat field 20 (migration 000097): custom rules dropped at
	// bundle load for an invalid or oversized regex.
	RegexRulesDroppedTotal *int64 `json:"regex_rules_dropped_total,omitempty"`
	// Heartbeat fields 9-10 (migration 000099): where the WAF config
	// in force came from — "live", "cache", "cache_stale", "" (no bundle
	// yet) or "unknown" — and its generation. Omitted when never reported.
	BundleSource       *string    `json:"bundle_source,omitempty"`
	BundleGeneration   *int64     `json:"bundle_generation,omitempty"`
	WAFHealthUpdatedAt *time.Time `json:"waf_health_updated_at,omitempty"`
	// ScriptRules (migration 000116): whether the WAF agent can run script
	// rules, from its last Hello. Always present in the JSON: true, false
	// (Hello feature no_script_rules), or null when unknown or for a host agent.
	ScriptRules *bool `json:"script_rules"`
}

// Host represents a customer machine registered under a project. Exactly one
// Host Key lives per host row; it is shared across the eBPF agent and any WAF
// agent processes that run on the host. Only the short prefix + argon2id hash
// are persisted — the raw secret is shown once at creation time.
type Host struct {
	ID        string `json:"id"`
	ProjectID string `json:"project_id"`
	UserID    string `json:"user_id"`

	Name   string            `json:"name"`
	Labels map[string]string `json:"labels,omitempty"`

	HostKeyPrefix string `json:"host_key_prefix"` // e.g. "wafh_abcd"

	Status string `json:"status"` // pending|online|offline|revoked

	HostInfoRaw json.RawMessage `json:"host_info,omitempty"`
	HostOS      string          `json:"host_os,omitempty"`
	HostOSVer   string          `json:"host_os_version,omitempty"`
	HostKernel  string          `json:"host_kernel,omitempty"`
	HostArch    string          `json:"host_arch,omitempty"`
	HostCPUs    int             `json:"host_cpu_count,omitempty"`
	HostMemory  int64           `json:"host_memory,omitempty"`
	HostVirt    string          `json:"host_virt,omitempty"`
	HostBoot    *time.Time      `json:"host_boot_time,omitempty"`

	LastSeen  *time.Time `json:"last_seen,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
	// EnrollExpiresAt ends the host key's enrollment window (HostEnrollWindow
	// after create or rotation); nil = closed (hosts from before migration
	// 000108 until their key is rotated).
	EnrollExpiresAt *time.Time `json:"enroll_expires_at,omitempty"`
}

// ProjectWAFSummary is the header KPI set for the new Overview dashboard.
type ProjectWAFSummary struct {
	Window   string `json:"window"`
	Requests int64  `json:"requests"`
	Blocks   int64  `json:"blocks"`
	Allows   int64  `json:"allows"`
	Monitors int64  `json:"monitors"`
	Logs     int64  `json:"logs"`
	Errors   int64  `json:"errors"`
	// Challenges counts action = 'challenge' (see AppWAFSummary).
	Challenges       int64   `json:"challenges"`
	BlockRate        float64 `json:"block_rate"`
	AvgLatencyUS     int     `json:"avg_latency_us"`
	UniqueIPs        int64   `json:"unique_ips"`
	UniqueHosts      int64   `json:"unique_hosts"`
	AgentsActive     int64   `json:"agents_active"`
	SemanticTriggers int64   `json:"semantic_triggers"`
	OtherTriggers    int64   `json:"other_triggers"`
	// WebSocket breakdown (see AppWAFSummary).
	WSMessagesBlocked   int64 `json:"ws_messages_blocked"`
	WSMessagesLogged    int64 `json:"ws_messages_logged"`
	WSHandshakeRejected int64 `json:"ws_handshake_rejected"`
}

// WAFTimelineBucket is one point in the requests-over-time chart.
type WAFTimelineBucket struct {
	BucketStart time.Time `json:"bucket_start"`
	Requests    int64     `json:"requests"`
	Blocks      int64     `json:"blocks"`
	Allows      int64     `json:"allows"`
	Monitors    int64     `json:"monitors"`
	Errors      int64     `json:"errors"`
	// Logs (action = 'log') and Challenges (action = 'challenge') complete
	// the buckets: Requests = Blocks + Allows + Monitors + Logs + Challenges
	// + Errors for every action the agents emit.
	Logs       int64 `json:"logs"`
	Challenges int64 `json:"challenges"`
}

// FirewallTopIPRow represents aggregated drop counts for a source IP.
type FirewallTopIPRow struct {
	SrcIP       string `json:"src_ip"`
	CountryCode string `json:"country_code"`
	CountryName string `json:"country_name"`
	Blocklist   int    `json:"blocklist"`
	RateLimit   int    `json:"rate_limit"`
	SynFlood    int    `json:"syn_flood"`
	GeoBlock    int    `json:"geo_block"`
	PortScan    int    `json:"port_scan"`
	PortPolicy  int    `json:"port_policy"`
	Other       int    `json:"other"`
	Total       int    `json:"total"`
}
