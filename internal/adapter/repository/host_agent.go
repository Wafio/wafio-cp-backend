package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/wafio/wafio-cp-backend/internal/domain"
	"github.com/wafio/wafio-cp-backend/internal/fairshare"
)

// ──────────────────────────────────────────────────────────────────────────────
// EBPFRepo — Repository for all eBPF telemetry data persisted in PostgreSQL.
// Agent pushes data → server ingests via this repo → frontend reads via this repo.
// ──────────────────────────────────────────────────────────────────────────────

type EBPFRepo struct {
	retryMu   sync.Mutex
	retryPool *fairshare.Pool[telemetryRetryEntry]
	// retryNow and retryCapacity override the clock and
	// telemetryRetryCapacity (tests).
	retryNow      func() time.Time
	retryCapacity int
	pool          *pgxpool.Pool
	store         *HostEventStore
	eventCache    *traceEventCache
	// projects resolves a project's owning account for the per-account
	// fair share of the retry pool and the live views; nil charges
	// each project to itself.
	projects *ProjectRepo
	// agentTenants caches agent -> (owner, project) for the live views;
	// tenantOf replaces that lookup (tests only).
	agentTenants agentTenantCache
	tenantOf     func(agentID string) liveTenant
	// enfLive holds each agent's newest enforcement rows for the live host
	// stream (live_feed.go).
	enfLive liveFeed[EnforcementLogRow]
}

// SetHostEventStore attaches a HostEventStore for TimescaleDB-backed host telemetry.
func (r *EBPFRepo) SetHostEventStore(s *HostEventStore) { r.store = s }

// ── Agent Registration ──────────────────────────────────────────────────────

// EBPFAgent is defined in domain; the alias keeps this package's API.
type EBPFAgent = domain.EBPFAgent

// AgentLivenessWindow is the one "online" rule for agents: a heartbeat or
// telemetry push within the window. Agents heartbeat every 30 s, so this is
// three missed beats. Every list, stream and delete guard uses it, so the
// dashboard and the API agree on what online means.
const AgentLivenessWindow = domain.AgentLivenessWindow

// AgentIsOnline applies AgentLivenessWindow to a last_seen timestamp.
func AgentIsOnline(lastSeen *time.Time) bool {
	return lastSeen != nil && time.Since(*lastSeen) <= AgentLivenessWindow
}

// NormalizeAgentKind maps a requested agent kind onto the agents.kind CHECK
// constraint (host|waf, migration 000031). "ebpf" is the pre-000031 name of
// "host" and is still accepted; empty means host. ok is false for anything
// else.
func NormalizeAgentKind(kind string) (normalized string, ok bool) {
	switch kind {
	case "", "host", "ebpf":
		return "host", true
	case "waf":
		return "waf", true
	default:
		return "", false
	}
}

// RegisterAgent creates a new host agent entry. Kept for backward
// compatibility with older callers; new code should call RegisterAgentKind.
func (r *EBPFRepo) RegisterAgent(ctx context.Context, userID, projectID, name, apiKey string) (*EBPFAgent, error) {
	return r.RegisterAgentKind(ctx, userID, projectID, name, apiKey, "host")
}

// RegisterAgentKind creates a new agent of the given kind ("host" | "waf";
// the legacy "ebpf" is stored as "host").
func (r *EBPFRepo) RegisterAgentKind(ctx context.Context, userID, projectID, name, apiKey, kind string) (*EBPFAgent, error) {
	normalized, ok := NormalizeAgentKind(kind)
	if !ok {
		return nil, fmt.Errorf("unsupported agent kind %q", kind)
	}
	kind = normalized
	agent := &EBPFAgent{Kind: kind}
	err := r.pool.QueryRow(ctx,
		`INSERT INTO agents (user_id, project_id, name, kind)
		 SELECT $1, $2, $3, $4
		  WHERE (SELECT count(*) FROM agents WHERE project_id = $2 AND deleted_at IS NULL) < $5
		 RETURNING id, user_id, project_id, name, created_at`,
		userID, projectID, name, kind, agentsPerProjectLimit,
	).Scan(&agent.ID, &agent.UserID, &agent.ProjectID, &agent.Name, &agent.CreatedAt)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrAgentLimit
	}
	return agent, err
}

// MaxAgentsPerProject bounds the live agent rows of one project:
// agents connecting over gRPC or the host-key ingest under a name the
// project does not know yet are registered automatically, so one credential
// could otherwise create agent rows without end. Every insert path checks
// it; existing agents always reconnect.
const MaxAgentsPerProject = 20000

// agentsPerProjectLimit is the cap the inserts use (tests lower it).
var agentsPerProjectLimit = MaxAgentsPerProject

// ErrAgentLimit is returned when a new agent row would exceed
// MaxAgentsPerProject. Count and insert are one statement, so concurrent
// inserts at the limit can pass together; the overshoot is bounded by that
// concurrency.
var ErrAgentLimit = errors.New("agent limit reached for the project")

// TouchAgentLastSeen updates the last_seen timestamp for an agent.
// Scoped by project_id as the mandatory second isolation layer.
func (r *EBPFRepo) TouchAgentLastSeen(ctx context.Context, projectID, agentID string) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE agents SET last_seen = NOW() WHERE deleted_at IS NULL AND id = $1 AND project_id = $2`,
		agentID, projectID)
	return err
}

// TouchAgentLastSeenByName updates last_seen for the agent row matching
// (project_id, name). Used by the gRPC stream where the agent identity is
// resolved via mTLS credential rather than host-key, so we don't have an
// agent_id directly. Returns nil if no row matched.
func (r *EBPFRepo) TouchAgentLastSeenByName(ctx context.Context, projectID, name string) error {
	if projectID == "" || name == "" {
		return nil
	}
	_, err := r.pool.Exec(ctx,
		`UPDATE agents SET last_seen = NOW() WHERE deleted_at IS NULL AND project_id = $1 AND name = $2`,
		projectID, name)
	return err
}

// LookupAgentIDByName returns the agent_id for a (project_id, name) pair.
// Used by the gRPC stream to attribute live WAF decisions to a row in
// agents — needed for the waf_decisions.agent_id foreign key.
func (r *EBPFRepo) LookupAgentIDByName(ctx context.Context, projectID, name string) (string, error) {
	if projectID == "" || name == "" {
		return "", nil
	}
	var id string
	err := r.pool.QueryRow(ctx,
		`SELECT id FROM agents WHERE deleted_at IS NULL AND project_id = $1 AND name = $2 ORDER BY last_seen DESC NULLS LAST LIMIT 1`,
		projectID, name,
	).Scan(&id)
	return id, err
}

// LookupAgentByName returns the agent_id and kind for a (project_id, name)
// pair. Returns ("", "", nil) when no row is found (pgx returns pgx.ErrNoRows
// which is mapped to empty strings here for convenience).
// WAF-kind rows are preferred over eBPF rows when duplicates exist (e.g. after
// a botched migration created both).
func (r *EBPFRepo) LookupAgentByName(ctx context.Context, projectID, name string) (id, kind string, err error) {
	if projectID == "" || name == "" {
		return "", "", nil
	}
	e := r.pool.QueryRow(ctx,
		`SELECT id, COALESCE(kind, 'waf') FROM agents
		 WHERE deleted_at IS NULL AND project_id = $1 AND name = $2
		 ORDER BY CASE WHEN COALESCE(kind,'waf') = 'waf' THEN 0 ELSE 1 END,
		          last_seen DESC NULLS LAST
		 LIMIT 1`,
		projectID, name,
	).Scan(&id, &kind)
	if e != nil {
		// pgx.ErrNoRows or other error — return empty, not an error
		return "", "", nil
	}
	return id, kind, nil
}

// UpsertUnattachedAgent returns the id of an existing unattached agent row
// for (project_id, name, kind), or creates one. Used when an eBPF agent
// connects via mTLS without a host_key — the host_id column stays NULL and
// the mTLS cert already proves project membership, so no second credential
// is required.
func (r *EBPFRepo) UpsertUnattachedAgent(ctx context.Context, projectID, name, kind string) (string, error) {
	if name == "" {
		name = kind
	}
	// Fast path: existing unattached row.
	var id string
	err := r.pool.QueryRow(ctx,
		`SELECT id FROM agents
		  WHERE deleted_at IS NULL AND project_id = $1 AND name = $2 AND kind = $3 AND host_id IS NULL
		  ORDER BY last_seen DESC NULLS LAST LIMIT 1`,
		projectID, name, kind,
	).Scan(&id)
	if err == nil {
		return id, nil
	}
	// Resolve user_id from the owning project.
	var userID string
	if e := r.pool.QueryRow(ctx,
		`SELECT user_id FROM projects WHERE id = $1`, projectID,
	).Scan(&userID); e != nil {
		return "", fmt.Errorf("resolve project user: %w", e)
	}
	// Insert (capped per project); tolerate a race by re-reading on
	// any error.
	e := r.pool.QueryRow(ctx,
		`INSERT INTO agents (user_id, project_id, name, kind)
		 SELECT $1, $2, $3, $4
		  WHERE (SELECT count(*) FROM agents WHERE project_id = $2 AND deleted_at IS NULL) < $5
		 RETURNING id`,
		userID, projectID, name, kind, agentsPerProjectLimit,
	).Scan(&id)
	if e == nil {
		return id, nil
	}
	err = e
	if errors.Is(e, pgx.ErrNoRows) {
		err = ErrAgentLimit
	}
	// Race: another goroutine inserted concurrently — re-read.
	if e := r.pool.QueryRow(ctx,
		`SELECT id FROM agents
		  WHERE deleted_at IS NULL AND project_id = $1 AND name = $2 AND kind = $3 AND host_id IS NULL
		  ORDER BY last_seen DESC NULLS LAST LIMIT 1`,
		projectID, name, kind,
	).Scan(&id); e == nil {
		return id, nil
	}
	return "", err
}

// UpdateAgentCallbackURL is a no-op retained for backward compatibility.
// The callback_url column was dropped in migration 000031; agents now communicate
// via the bidirectional gRPC stream instead of the old HTTP callback model.
func (r *EBPFRepo) UpdateAgentCallbackURL(ctx context.Context, projectID, agentID, callbackURL string) error {
	// Only update last_seen; callback_url column no longer exists.
	// Scoped by project_id as the mandatory second isolation layer.
	_, err := r.pool.Exec(ctx,
		`UPDATE agents SET last_seen = NOW() WHERE deleted_at IS NULL AND id = $1 AND project_id = $2`,
		agentID, projectID)
	return err
}

// ── Agent host info ────────────────────────────────────────────────────────

// AgentHostInfoRow is defined in domain; the alias keeps this package's API.
type AgentHostInfoRow = domain.AgentHostInfoRow

// UpdateAgentHostInfo stores the full JSON snapshot plus the denormalised
// columns used for filtering in the UI. Also keeps last_seen fresh.
func (r *EBPFRepo) UpdateAgentHostInfo(ctx context.Context, projectID, agentID string, h AgentHostInfoRow) error {
	var bootTS *time.Time
	if h.BootUnix > 0 {
		t := time.Unix(h.BootUnix, 0).UTC()
		bootTS = &t
	}
	// Scoped by project_id as the mandatory second isolation layer.
	_, err := r.pool.Exec(ctx, `
		UPDATE agents
		   SET host_info       = $2::jsonb,
		       host_os         = NULLIF($3,''),
		       host_os_version = NULLIF($4,''),
		       host_kernel     = NULLIF($5,''),
		       host_arch       = NULLIF($6,''),
		       host_cpu_count  = NULLIF($7::int,0),
		       host_memory     = NULLIF($8::bigint,0),
		       host_virt       = NULLIF($9,''),
		       host_boot_time  = $10,
		       host_updated_at = NOW(),
		       hostname        = COALESCE(NULLIF($11,''), hostname),
		       version         = COALESCE(NULLIF($12,''), version),
		       last_seen       = NOW()
		 WHERE deleted_at IS NULL AND id = $1 AND project_id = $13`,
		agentID, string(h.Raw), h.OS, h.OSVersion, h.Kernel, h.Arch,
		h.CPUCount, h.MemoryTotal, h.VirtType, bootTS, h.Hostname, h.Version,
		projectID,
	)
	return err
}

// AgentWAFHealth is the latest inspection-health set a WAF agent reported on
// its heartbeat (proto Heartbeat fields 5-8 and 11-19). Counters are
// cumulative since the agent process started; ScriptRunsInFlight is a gauge;
// AnalyzeLatency* summarise the agent's last 5 minutes in microseconds. A nil
// field was not reported (agent predates the field, or no analyses in the
// latency window).
type AgentWAFHealth struct {
	AnalyzePanicsTotal        *int64
	EnginePanicsTotal         *int64
	PartialCoverageTotal      *int64
	ParseBudgetExhaustedTotal *int64

	ScriptIncompleteTotal    *int64
	ScriptErrorsTotal        *int64
	ScriptRulesRejectedTotal *int64
	ScriptRunsInFlight       *int64
	AgentPanicsTotal         *int64
	AnalyzeLatencyP50Us      *int64
	AnalyzeLatencyP95Us      *int64
	AnalyzeLatencyP99Us      *int64
	AnalyzeLatencySamples    *int64
	// Field 20 (migration 000097): custom rules dropped at bundle
	// load for an invalid or oversized regex, cumulative since agent start.
	RegexRulesDroppedTotal *int64
	// Fields 9-10 (migration 000099): where the WAF config in force
	// came from (live|cache|cache_stale|"" none|unknown) and its generation.
	BundleSource     *string
	BundleGeneration *int64
}

// Reported is true when at least one field is present.
func (h AgentWAFHealth) Reported() bool {
	for _, v := range []*int64{
		h.AnalyzePanicsTotal, h.EnginePanicsTotal, h.PartialCoverageTotal, h.ParseBudgetExhaustedTotal,
		h.ScriptIncompleteTotal, h.ScriptErrorsTotal, h.ScriptRulesRejectedTotal, h.ScriptRunsInFlight,
		h.AgentPanicsTotal, h.AnalyzeLatencyP50Us, h.AnalyzeLatencyP95Us, h.AnalyzeLatencyP99Us,
		h.AnalyzeLatencySamples, h.RegexRulesDroppedTotal, h.BundleGeneration,
	} {
		if v != nil {
			return true
		}
	}
	return h.BundleSource != nil
}

// UpdateAgentWAFHealth stores the latest heartbeat counters for one agent.
// A heartbeat with no counters (old agent) leaves the stored values alone.
// Scoped by project_id as the mandatory second isolation layer.
func (r *EBPFRepo) UpdateAgentWAFHealth(ctx context.Context, projectID, agentID string, h AgentWAFHealth) error {
	if projectID == "" || agentID == "" || !h.Reported() {
		return nil
	}
	_, err := r.pool.Exec(ctx, `
		UPDATE agents
		   SET analyze_panics_total         = $3,
		       engine_panics_total          = $4,
		       partial_coverage_total       = $5,
		       parse_budget_exhausted_total = $6,
		       script_incomplete_total      = $7,
		       script_errors_total          = $8,
		       script_rules_rejected_total  = $9,
		       script_runs_in_flight        = $10,
		       agent_panics_total           = $11,
		       analyze_latency_p50_us       = $12,
		       analyze_latency_p95_us       = $13,
		       analyze_latency_p99_us       = $14,
		       analyze_latency_samples      = $15,
		       waf_regex_rules_dropped_total = $16,
		       waf_bundle_source            = $17,
		       waf_bundle_generation        = $18,
		       waf_health_updated_at        = NOW()
		 WHERE deleted_at IS NULL AND id = $1 AND project_id = $2`,
		agentID, projectID,
		h.AnalyzePanicsTotal, h.EnginePanicsTotal, h.PartialCoverageTotal, h.ParseBudgetExhaustedTotal,
		h.ScriptIncompleteTotal, h.ScriptErrorsTotal, h.ScriptRulesRejectedTotal, h.ScriptRunsInFlight,
		h.AgentPanicsTotal, h.AnalyzeLatencyP50Us, h.AnalyzeLatencyP95Us, h.AnalyzeLatencyP99Us,
		h.AnalyzeLatencySamples, h.RegexRulesDroppedTotal,
		h.BundleSource, h.BundleGeneration,
	)
	return err
}

// UpdateAgentScriptRules stores whether the WAF agent can run script rules, as
// it reported in Hello (engine.AgentScriptRules); nil = unknown. Written on
// every connect, so an agent replaced by an older build goes back to unknown.
func (r *EBPFRepo) UpdateAgentScriptRules(ctx context.Context, projectID, agentID string, scriptRules *bool) error {
	if r == nil || r.pool == nil {
		return nil
	}
	_, err := r.pool.Exec(ctx,
		`UPDATE agents SET script_rules = $3 WHERE deleted_at IS NULL AND id = $1 AND project_id = $2`,
		agentID, projectID, scriptRules)
	return err
}

// AgentScriptRules returns what UpdateAgentScriptRules stored for the agent:
// nil when unknown, when the agent is a host agent, or when it does not exist.
func (r *EBPFRepo) AgentScriptRules(ctx context.Context, agentID string) (*bool, error) {
	var scriptRules *bool
	err := r.pool.QueryRow(ctx,
		`SELECT script_rules FROM agents WHERE deleted_at IS NULL AND id = $1`, agentID).Scan(&scriptRules)
	if errors.Is(err, pgx.ErrNoRows) {
		err = nil
	}
	return scriptRules, err
}

// AgentWithHostInfo is defined in domain; the alias keeps this package's API.
type AgentWithHostInfo = domain.AgentWithHostInfo

// healthColumns is the SELECT list scanned by scanHealth, in order.
const healthColumns = `analyze_panics_total, engine_panics_total, partial_coverage_total,
	             parse_budget_exhausted_total, script_incomplete_total, script_errors_total,
	             script_rules_rejected_total, script_runs_in_flight, agent_panics_total,
	             analyze_latency_p50_us, analyze_latency_p95_us, analyze_latency_p99_us,
	             analyze_latency_samples, waf_regex_rules_dropped_total, waf_bundle_source,
	             waf_bundle_generation, waf_health_updated_at, script_rules`

// agentHealthDest returns the scan destinations matching healthColumns.
func agentHealthDest(a *AgentWithHostInfo) []any {
	return []any{&a.AnalyzePanicsTotal, &a.EnginePanicsTotal, &a.PartialCoverageTotal,
		&a.ParseBudgetExhaustedTotal, &a.ScriptIncompleteTotal, &a.ScriptErrorsTotal,
		&a.ScriptRulesRejectedTotal, &a.ScriptRunsInFlight, &a.AgentPanicsTotal,
		&a.AnalyzeLatencyP50Us, &a.AnalyzeLatencyP95Us, &a.AnalyzeLatencyP99Us,
		&a.AnalyzeLatencySamples, &a.RegexRulesDroppedTotal, &a.BundleSource,
		&a.BundleGeneration, &a.WAFHealthUpdatedAt, &a.ScriptRules}
}

// ListAgentsForUser returns all agents (any kind) visible to the user,
// optionally scoped to a project. Used by the fleet UI.
// Visibility is current project membership, never agents.user_id (the
// registrant): a member removed from a project stops seeing its agents. When userID is
// empty the membership filter is skipped (caller must
// verify project access first).
func (r *EBPFRepo) ListAgentsForUser(ctx context.Context, userID, projectID, kind string) ([]AgentWithHostInfo, error) {
	args := []any{}
	q := `SELECT id, name, kind, COALESCE(project_id::text,''), COALESCE(host_id::text,''),
	             last_seen, created_at,
	             COALESCE(hostname,''), COALESCE(version,''),
	             COALESCE(host_os,''), COALESCE(host_os_version,''), COALESCE(host_kernel,''),
	             COALESCE(host_arch,''), COALESCE(host_cpu_count,0), COALESCE(host_memory,0),
	             COALESCE(host_virt,''), host_boot_time, host_updated_at, host_info,
	             proxy_listen_port,
	             ` + healthColumns + `
	        FROM agents WHERE deleted_at IS NULL AND 1=1`
	if userID != "" {
		args = append(args, userID)
		q += ` AND project_id IN (SELECT pm.project_id FROM project_members pm WHERE pm.user_id = $` + itoa(len(args)) + `::uuid)`
	}
	if projectID != "" {
		args = append(args, projectID)
		q += ` AND project_id = $` + itoa(len(args))
	}
	if kind != "" {
		args = append(args, kind)
		q += ` AND kind = $` + itoa(len(args))
	}
	q += ` ORDER BY created_at DESC`

	rows, err := r.pool.Query(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := make([]AgentWithHostInfo, 0, 16)
	for rows.Next() {
		var a AgentWithHostInfo
		var hi []byte
		dest := []any{&a.ID, &a.Name, &a.Kind, &a.ProjectID, &a.HostID,
			&a.LastSeen, &a.CreatedAt,
			&a.Hostname, &a.Version,
			&a.HostOS, &a.HostOSVersion, &a.HostKernel,
			&a.HostArch, &a.HostCPUCount, &a.HostMemory,
			&a.HostVirt, &a.HostBootTime, &a.HostUpdatedAt, &hi,
			&a.ProxyListenPort}
		err := rows.Scan(append(dest, agentHealthDest(&a)...)...)
		if err != nil {
			return nil, err
		}
		if len(hi) > 0 {
			a.HostInfo = hi
		}
		a.IsOnline = AgentIsOnline(a.LastSeen)
		out = append(out, a)
	}
	return out, rows.Err()
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := false
	if n < 0 {
		neg = true
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

// GetAgentHostInfo returns the latest host_info JSON blob for an agent.
// If the given agentID has no host_info (e.g. it's a WAF agent), it falls back
// to the most recently seen host-kind agent in the same project.
func (r *EBPFRepo) GetAgentHostInfo(ctx context.Context, agentID string) (json.RawMessage, error) {
	var raw json.RawMessage
	// First: try the requested agent directly
	err := r.pool.QueryRow(ctx,
		`SELECT host_info FROM agents WHERE deleted_at IS NULL AND id = $1 AND host_info IS NOT NULL`, agentID,
	).Scan(&raw)
	if err == nil && len(raw) > 0 {
		return raw, nil
	}
	// Fallback: find the host agent in the same project with the freshest host_info
	err = r.pool.QueryRow(ctx,
		`SELECT host_info FROM agents
		  WHERE deleted_at IS NULL AND project_id = (SELECT project_id FROM agents WHERE deleted_at IS NULL AND id = $1)
		    AND kind = 'host'
		    AND host_info IS NOT NULL
		  ORDER BY last_seen DESC NULLS LAST
		  LIMIT 1`, agentID,
	).Scan(&raw)
	if err != nil {
		return nil, err
	}
	return raw, nil
}

// GetDesiredState returns the stored desired_state JSON blob for an agent.
func (r *EBPFRepo) GetDesiredState(ctx context.Context, agentID string) (json.RawMessage, error) {
	var raw json.RawMessage
	err := r.pool.QueryRow(ctx,
		`SELECT COALESCE(desired_state, '{}') FROM agents WHERE deleted_at IS NULL AND id = $1`, agentID,
	).Scan(&raw)
	if err != nil {
		return json.RawMessage("{}"), err
	}
	return raw, nil
}

// SetDesiredState updates telemetry hit-count bookkeeping only. The caller must
// preserve _revision; a concurrent configuration commit prevents stale overwrite.
func (r *EBPFRepo) SetDesiredState(ctx context.Context, projectID, agentID string, state json.RawMessage) error {
	revision, err := DesiredStateRevision(state)
	if err != nil {
		return err
	}
	result, err := r.pool.Exec(ctx, `UPDATE agents SET desired_state=$1 WHERE deleted_at IS NULL AND id=$2 AND project_id=$3 AND COALESCE((desired_state->>'_revision')::bigint,0)=$4`, state, agentID, projectID, revision)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return ErrDesiredStateConflict
	}
	return nil
}

// GetAgentByID returns a single agent by id including its last_seen timestamp.
// Useful for liveness checks where we need to tell "agent offline" apart from
// "agent online but no data yet". Looks up the unified `agents` table so it
// returns WAF agents as well as eBPF agents (the `ebpf_agents` view filters
// to kind='ebpf' only).
func (r *EBPFRepo) GetAgentByID(ctx context.Context, agentID string) (*EBPFAgent, error) {
	agent := &EBPFAgent{}
	err := r.pool.QueryRow(ctx,
		`SELECT id, user_id, COALESCE(project_id::text,''), name, COALESCE(kind::text,'ebpf'), last_seen, created_at
		 FROM agents WHERE deleted_at IS NULL AND id = $1`, agentID,
	).Scan(&agent.ID, &agent.UserID, &agent.ProjectID, &agent.Name, &agent.Kind, &agent.LastSeen, &agent.CreatedAt)
	if err != nil {
		return nil, err
	}
	return agent, nil
}

// GetAgentSSHPorts returns the sshd listener ports the host agent last
// reported (host_info.ssh_ports). Nil when the agent never reported them;
// the firewall lockout guard then assumes 22.
func (r *EBPFRepo) GetAgentSSHPorts(ctx context.Context, projectID, agentID string) ([]uint16, error) {
	var raw []byte
	err := r.pool.QueryRow(ctx,
		`SELECT host_info->'ssh_ports' FROM agents WHERE deleted_at IS NULL AND id = $1 AND project_id = $2`,
		agentID, projectID,
	).Scan(&raw)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var ports []uint16
	if err := json.Unmarshal(raw, &ports); err != nil {
		return nil, err
	}
	return ports, nil
}

// GetAgentFirewallFeatures returns the optional firewall capabilities the
// host agent last reported (host_info.firewall_features, e.g. "geo_allow").
// Nil when the agent never reported them (agents older than geo allow mode).
func (r *EBPFRepo) GetAgentFirewallFeatures(ctx context.Context, projectID, agentID string) ([]string, error) {
	var raw []byte
	err := r.pool.QueryRow(ctx,
		`SELECT host_info->'firewall_features' FROM agents WHERE deleted_at IS NULL AND id = $1 AND project_id = $2`,
		agentID, projectID,
	).Scan(&raw)
	if err != nil {
		return nil, err
	}
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var features []string
	if err := json.Unmarshal(raw, &features); err != nil {
		return nil, err
	}
	return features, nil
}

// ListAgentsByProject returns all host agents for a project (excludes WAF agents).
func (r *EBPFRepo) ListAgentsByProject(ctx context.Context, projectID string) ([]EBPFAgent, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, user_id, COALESCE(project_id::text,''), name, last_seen, created_at
		 FROM agents WHERE deleted_at IS NULL AND project_id = $1 AND kind != 'waf' ORDER BY last_seen DESC NULLS LAST`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	agents := []EBPFAgent{}
	for rows.Next() {
		var a EBPFAgent
		if err := rows.Scan(&a.ID, &a.UserID, &a.ProjectID, &a.Name, &a.LastSeen, &a.CreatedAt); err != nil {
			return nil, err
		}
		agents = append(agents, a)
	}
	return agents, rows.Err()
}

// ListNonWAFAgentsByHostInProject returns non-WAF agents for a host, restricted
// to one project.
//
// The unscoped variant below takes a host id and nothing else, and every HTTP
// caller was handing it a value straight out of a query string. A host id from
// another tenant resolved to that tenant's agent, which is a cross-tenant leak.
// Callers that serve a request must use this one; project_id is not optional
// context here, it is the authorisation.
func (r *EBPFRepo) ListNonWAFAgentsByHostInProject(ctx context.Context, hostID, projectID string) ([]EBPFAgent, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, user_id, COALESCE(project_id::text,''), name, last_seen, created_at
		 FROM agents WHERE deleted_at IS NULL AND host_id = $1 AND project_id = $2 AND kind != 'waf'
		 ORDER BY last_seen DESC NULLS LAST`, hostID, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	agents := []EBPFAgent{}
	for rows.Next() {
		var a EBPFAgent
		if err := rows.Scan(&a.ID, &a.UserID, &a.ProjectID, &a.Name, &a.LastSeen, &a.CreatedAt); err != nil {
			return nil, err
		}
		agents = append(agents, a)
	}
	return agents, rows.Err()
}

// ListNonWAFAgentsByHost returns non-WAF agents for a specific host, across all
// projects. Only for callers that have already established the tenant, such as
// internal aggregation; anything serving an HTTP request wants the InProject
// variant above.
func (r *EBPFRepo) ListNonWAFAgentsByHost(ctx context.Context, hostID string) ([]EBPFAgent, error) {
	rows, err := r.pool.Query(ctx,
		`SELECT id, user_id, COALESCE(project_id::text,''), name, last_seen, created_at
		 FROM agents WHERE deleted_at IS NULL AND host_id = $1 AND kind != 'waf'
		 ORDER BY last_seen DESC NULLS LAST`, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	agents := []EBPFAgent{}
	for rows.Next() {
		var a EBPFAgent
		if err := rows.Scan(&a.ID, &a.UserID, &a.ProjectID, &a.Name, &a.LastSeen, &a.CreatedAt); err != nil {
			return nil, err
		}
		agents = append(agents, a)
	}
	return agents, rows.Err()
}

// ListAgentsByHost returns all agents attached to a specific host (both
// eBPF and WAF kinds). Used by the Host detail page so operators can see
// which processes are currently reporting from a given machine.
func (r *EBPFRepo) ListAgentsByHost(ctx context.Context, hostID string) ([]AgentWithHostInfo, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, name, COALESCE(kind,'host'), COALESCE(project_id::text,''), COALESCE(host_id::text,''),
		       last_seen, created_at,
		       COALESCE(hostname,''), COALESCE(version,''),
		       COALESCE(host_os,''), COALESCE(host_os_version,''), COALESCE(host_kernel,''),
		       COALESCE(host_arch,''), COALESCE(host_cpu_count,0), COALESCE(host_memory,0),
		       COALESCE(host_virt,''), host_boot_time, host_updated_at, host_info,
		       `+healthColumns+`
		  FROM agents
		 WHERE deleted_at IS NULL AND host_id = $1
		 ORDER BY kind, created_at DESC`, hostID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make([]AgentWithHostInfo, 0, 4)
	for rows.Next() {
		var a AgentWithHostInfo
		var hi []byte
		dest := []any{&a.ID, &a.Name, &a.Kind, &a.ProjectID, &a.HostID,
			&a.LastSeen, &a.CreatedAt,
			&a.Hostname, &a.Version,
			&a.HostOS, &a.HostOSVersion, &a.HostKernel,
			&a.HostArch, &a.HostCPUCount, &a.HostMemory,
			&a.HostVirt, &a.HostBootTime, &a.HostUpdatedAt, &hi}
		if err := rows.Scan(append(dest, agentHealthDest(&a)...)...); err != nil {
			return nil, err
		}
		if len(hi) > 0 {
			a.HostInfo = hi
		}
		a.BinaryPath, a.InstallDir, a.ServiceName, a.ServiceUser = parseAgentProcessMeta(hi, a.Kind)
		a.IsOnline = AgentIsOnline(a.LastSeen)
		out = append(out, a)
	}
	return out, rows.Err()
}

func parseAgentProcessMeta(hi []byte, kind string) (binaryPath, installDir, serviceName, serviceUser string) {
	if len(hi) > 0 {
		var meta struct {
			BinaryPath  string `json:"binary_path"`
			InstallDir  string `json:"install_dir"`
			ServiceName string `json:"service_name"`
			ServiceUser string `json:"service_user"`
		}
		if err := json.Unmarshal(hi, &meta); err == nil {
			binaryPath = meta.BinaryPath
			installDir = meta.InstallDir
			serviceName = meta.ServiceName
			serviceUser = meta.ServiceUser
		}
	}
	if binaryPath == "" {
		if kind == "waf" {
			binaryPath = "/usr/local/bin/wafio-waf-agent"
		} else {
			binaryPath = "/usr/local/bin/wafio-host-agent"
		}
	}
	if installDir == "" && binaryPath != "" {
		installDir = filepath.Dir(binaryPath)
	}
	if serviceName == "" {
		if kind == "waf" {
			serviceName = "wafio-waf-agent.service"
		} else {
			serviceName = "wafio-host-agent.service"
		}
	}
	if serviceUser == "" {
		serviceUser = "root"
	}
	return binaryPath, installDir, serviceName, serviceUser
}

// GetHostIDByHostname returns the host_id of any existing agent in the same project
// with the matching hostname that has an attached host_id.
func (r *EBPFRepo) GetHostIDByHostname(ctx context.Context, projectID, hostname string) string {
	if projectID == "" || hostname == "" {
		return ""
	}
	var hostID string
	_ = r.pool.QueryRow(ctx, `
		SELECT host_id::text
		  FROM agents
		 WHERE deleted_at IS NULL AND project_id = $1 AND hostname = $2 AND host_id IS NOT NULL
		 LIMIT 1`, projectID, hostname).Scan(&hostID)
	return hostID
}

// UpsertAgentForHost returns the (id) of the agent row matching
// (host_id, kind, name); creates one on first sight. This is the hook the
// agent-auth middleware calls after validating a Host Key so the rest of
// the pipeline can keep working with a stable agent_id.
//
// Notes:
//   - `name` distinguishes multiple WAF agent processes on the same host;
//     for eBPF it is always "host-firewall".
//   - The row carries project_id + user_id denormalised from the owning
//     host so project-scoping queries stay cheap.
func (r *EBPFRepo) UpsertAgentForHost(ctx context.Context, hostID, userID, projectID, kind, name string) (string, error) {
	if name == "" {
		name = kind
	}
	// Fast path: fetch existing.
	var id string
	err := r.pool.QueryRow(ctx, `
		SELECT id FROM agents
		 WHERE deleted_at IS NULL AND host_id = $1 AND kind = $2 AND name = $3`,
		hostID, kind, name,
	).Scan(&id)
	if err == nil {
		return id, nil
	}

	// Insert (capped per project). The (host_id, kind, name) partial
	// unique index `uq_agents_host_kind_name` from migration 000014 is the
	// conflict target.
	err = r.pool.QueryRow(ctx, `
		INSERT INTO agents (user_id, project_id, host_id, name, kind)
		SELECT $1, $2, $3, $4, $5
		 WHERE (SELECT count(*) FROM agents WHERE project_id = $2 AND deleted_at IS NULL) < $6
		ON CONFLICT (host_id, kind, name) WHERE host_id IS NOT NULL AND deleted_at IS NULL
		    DO UPDATE SET name = EXCLUDED.name
		RETURNING id`,
		userID, projectID, hostID, name, kind, agentsPerProjectLimit,
	).Scan(&id)
	if err == nil {
		return id, nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		err = ErrAgentLimit
	}
	// Last-resort re-read in case the conflict target index isn't yet
	// present (first run before migration 000014 applied).
	reErr := r.pool.QueryRow(ctx, `
		SELECT id FROM agents
		 WHERE deleted_at IS NULL AND host_id = $1 AND kind = $2 AND name = $3`,
		hostID, kind, name,
	).Scan(&id)
	if reErr == nil {
		return id, nil
	}
	return "", err
}

// LinkAgentToHost sets host_id on an unattached agent so that ON DELETE
// CASCADE removes it when the host row is deleted.
// Scoped by project_id as the mandatory second isolation layer.
func (r *EBPFRepo) LinkAgentToHost(ctx context.Context, projectID, agentID, hostID string) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE agents SET host_id = $1 WHERE deleted_at IS NULL AND id = $2 AND host_id IS NULL AND project_id = $3`,
		hostID, agentID, projectID)
	return err
}

// SetAgentHostID unconditionally sets host_id on an agent row. Used when an
// agent (any kind) presents a host_key on connect — ensures ON DELETE CASCADE
// cleans up the agent if the host is later deleted.
// Scoped by project_id as the mandatory second isolation layer.
func (r *EBPFRepo) SetAgentHostID(ctx context.Context, projectID, agentID, hostID string) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE agents SET host_id = $1 WHERE deleted_at IS NULL AND id = $2 AND project_id = $3`,
		hostID, agentID, projectID)
	return err
}

// DeleteUnattachedAgentsByHostname removes any agent rows in the project that
// still have host_id IS NULL but whose hostname column matches the supplied
// name. Called when a host is deleted to clean up agents that registered via
// gRPC mTLS before being linked (or when linking was never done).
func (r *EBPFRepo) DeleteUnattachedAgentsByHostname(ctx context.Context, projectID, hostname string) error {
	if projectID == "" || hostname == "" {
		return nil
	}
	_, err := r.pool.Exec(ctx,
		`DELETE FROM agents WHERE deleted_at IS NULL AND project_id = $1 AND hostname = $2 AND host_id IS NULL`,
		projectID, hostname)
	return err
}

// DeleteAgent soft-deletes an agent: it sets agents.deleted_at and
// removes the agent's configuration rows (app assignments, bundle
// generation, trace policies) in one transaction. Its telemetry --
// waf_decisions and the host event hypertables -- is left to retention
// instead of being deleted in the request: the old ON DELETE CASCADE removed
// up to 30 days of rows inside one HTTP call. Every read of agents filters
// deleted_at IS NULL, and so does every tenant join through agents, so the
// agent and its retained telemetry disappear from the dashboard at once,
// exactly as with the hard delete. Its name is free for a new agent (the
// unique indexes cover live rows only, migration 000095).
//
// Scoped by project_id (mandatory second isolation layer). Who may
// delete is decided by the caller: any project member with at least the
// "member" role, the same rule the routes enforce for every other agent
// mutation. pgx.ErrNoRows when there is no live agent to delete.
func (r *EBPFRepo) DeleteAgent(ctx context.Context, projectID, agentID string) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	tag, err := tx.Exec(ctx,
		`UPDATE agents SET deleted_at = NOW() WHERE deleted_at IS NULL AND id = $1 AND project_id = $2`,
		agentID, projectID)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return pgx.ErrNoRows
	}
	for _, q := range []string{
		`DELETE FROM waf_agent_apps WHERE agent_id = $1`,
		`DELETE FROM waf_agent_bundles WHERE agent_id = $1`,
		`DELETE FROM ebpf_trace_policies WHERE agent_id = $1`,
	} {
		if _, err := tx.Exec(ctx, q, agentID); err != nil {
			return err
		}
	}
	return tx.Commit(ctx)
}

// ── Status ──────────────────────────────────────────────────────────────────

func (r *EBPFRepo) InsertStatus(ctx context.Context, projectID, agentID string, payload json.RawMessage) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE agents SET last_status_json=$1, last_state_at=NOW() WHERE deleted_at IS NULL AND id=$2 AND project_id=$3`,
		[]byte(payload), agentID, projectID,
	)
	if err != nil && r.store != nil {
		r.store.writeFailed(agentID)
	}
	return err
}

func (r *EBPFRepo) LatestStatus(ctx context.Context, agentID string) (json.RawMessage, time.Time, error) {
	var payload []byte
	var stateAt time.Time
	err := r.pool.QueryRow(ctx,
		`SELECT last_status_json, COALESCE(last_state_at, NOW()) FROM agents WHERE deleted_at IS NULL AND id=$1`, agentID,
	).Scan(&payload, &stateAt)
	if err != nil {
		return nil, time.Time{}, err
	}
	return json.RawMessage(payload), stateAt, nil
}

// BatchLatestStatus fetches the most-recent status payload for each agent in
// one query instead of N round-trips. Reads from PostgreSQL agents.last_status_json
// for O(1) PK lookup.
func (r *EBPFRepo) BatchLatestStatus(ctx context.Context, agentIDs []string) (map[string]json.RawMessage, error) {
	if len(agentIDs) == 0 {
		return map[string]json.RawMessage{}, nil
	}
	rows, err := r.pool.Query(ctx,
		`SELECT id, last_status_json FROM agents WHERE deleted_at IS NULL AND id = ANY($1) AND last_status_json IS NOT NULL`,
		agentIDs,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]json.RawMessage, len(agentIDs))
	for rows.Next() {
		var id string
		var payload []byte
		if e := rows.Scan(&id, &payload); e == nil && len(payload) > 0 {
			out[id] = json.RawMessage(payload)
		}
	}
	return out, rows.Err()
}

// ── Metrics ─────────────────────────────────────────────────────────────────

// EBPFMetricsRow is defined in domain; the alias keeps this package's API.
type EBPFMetricsRow = domain.EBPFMetricsRow

func (r *EBPFRepo) InsertMetrics(ctx context.Context, projectID, agentID string, m *EBPFMetricsRow) error {
	if m.RecordedAt.IsZero() {
		m.RecordedAt = time.Now()
	}
	raw, err := json.Marshal(m)
	if err != nil {
		return err
	}
	if _, err = r.pool.Exec(ctx, `UPDATE agents SET last_metrics_json=$1,last_state_at=NOW() WHERE deleted_at IS NULL AND id=$2 AND project_id=$3`, raw, agentID, projectID); err != nil {
		if r.store != nil {
			r.store.writeFailed(agentID)
		}
		return err
	}
	if r.store != nil {
		r.store.setLatestMetrics(r.projectTenant(ctx, projectID), agentID, m)
	}
	return nil
}

func (r *EBPFRepo) LatestMetrics(ctx context.Context, agentID string) (*EBPFMetricsRow, error) {
	// Hot path: in-memory cache (no DB round-trip).
	if r.store != nil {
		if m, ok := r.store.GetLatestMetrics(agentID); ok {
			return m, nil
		}
	}
	// Cold start fallback: read from PostgreSQL.
	var raw []byte
	if err := r.pool.QueryRow(ctx,
		`SELECT last_metrics_json FROM agents WHERE deleted_at IS NULL AND id=$1`, agentID,
	).Scan(&raw); err != nil || len(raw) == 0 {
		return nil, pgx.ErrNoRows
	}
	var m EBPFMetricsRow
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// ── Events ──────────────────────────────────────────────────────────────────

// EBPFEventRow is defined in domain; the alias keeps this package's API.
type EBPFEventRow = domain.EBPFEventRow

func (r *EBPFRepo) InsertEvents(ctx context.Context, agentID string, events []EBPFEventRow) error {
	if len(events) == 0 || r.store == nil {
		return nil
	}
	docs := make([]fwEventInMem, len(events))
	for i, e := range events {
		ts := e.EventTime.Unix()
		if ts <= 0 {
			ts = time.Now().Unix()
		}
		docs[i] = fwEventInMem{
			Ts:       ts,
			SrcIP:    e.SrcIP,
			DstIP:    e.DstIP,
			SrcPort:  e.SrcPort,
			DstPort:  e.DstPort,
			Proto:    e.Proto,
			Action:   e.Action,
			Reason:   e.Reason,
			TCPFlags: e.TCPFlags,
			PktLen:   e.PktLen,
			RuleID:   e.RuleID,
		}
	}
	r.store.insertFirewallEvents(r.agentTenant(ctx, agentID), agentID, docs)
	return nil
}

func (r *EBPFRepo) RecentEvents(ctx context.Context, agentID string, limit int) ([]EBPFEventRow, error) {
	if r.store == nil {
		return nil, nil
	}
	docs := r.store.RecentFirewallEventsAll(agentID, limit)
	out := make([]EBPFEventRow, len(docs))
	for i, d := range docs {
		out[i] = EBPFEventRow{
			SrcIP:     d.SrcIP,
			DstIP:     d.DstIP,
			SrcPort:   d.SrcPort,
			DstPort:   d.DstPort,
			Proto:     d.Proto,
			Action:    d.Action,
			Reason:    d.Reason,
			TCPFlags:  d.TCPFlags,
			PktLen:    d.PktLen,
			RuleID:    d.RuleID,
			EventTime: time.Unix(d.Ts, 0).UTC(),
		}
	}
	return out, nil
}

// RecentEventsSince returns events newer than the given time (for SSE delta streaming).
// Uses the in-memory ring buffer — the hot SSE path never queries the database.
func (r *EBPFRepo) RecentEventsSince(ctx context.Context, agentID string, since time.Time, limit int) ([]EBPFEventRow, error) {
	if r.store == nil {
		return nil, nil
	}
	docs := r.store.RecentFirewallEventsSince(agentID, since.Unix(), limit)
	out := make([]EBPFEventRow, len(docs))
	for i, d := range docs {
		out[i] = EBPFEventRow{
			SrcIP:     d.SrcIP,
			DstIP:     d.DstIP,
			SrcPort:   d.SrcPort,
			DstPort:   d.DstPort,
			Proto:     d.Proto,
			Action:    d.Action,
			Reason:    d.Reason,
			TCPFlags:  d.TCPFlags,
			PktLen:    d.PktLen,
			RuleID:    d.RuleID,
			EventTime: time.Unix(d.Ts, 0).UTC(),
		}
	}
	return out, nil
}

// ── Connections ─────────────────────────────────────────────────────────────

// EBPFConnectionRow is defined in domain; the alias keeps this package's API.
type EBPFConnectionRow = domain.EBPFConnectionRow

func (r *EBPFRepo) InsertConnections(ctx context.Context, agentID string, conns []EBPFConnectionRow) error {
	if len(conns) == 0 || r.store == nil {
		return nil
	}
	// Returning nil regardless meant a failed write was reported to the caller
	// as a success. The same shape as the swallowed error in AggregateMetrics:
	// the data is gone and nothing upstream can tell.
	return r.store.SaveConnectionsSnapshot(ctx, agentID, conns)
}

func (r *EBPFRepo) ListConnections(ctx context.Context, agentID string, limit int) ([]EBPFConnectionRow, error) {
	if r.store == nil {
		return nil, nil
	}
	return r.store.LoadConnectionsSnapshot(ctx, agentID)
}

// ── Bandwidth ───────────────────────────────────────────────────────────────

// EBPFBandwidthRow is defined in domain; the alias keeps this package's API.
type EBPFBandwidthRow = domain.EBPFBandwidthRow

func (r *EBPFRepo) InsertBandwidth(ctx context.Context, agentID string, entries []EBPFBandwidthRow) error {
	if len(entries) == 0 || r.store == nil {
		return nil
	}
	return r.store.SaveBandwidthSnapshot(ctx, agentID, entries)
}

func (r *EBPFRepo) ListBandwidth(ctx context.Context, agentID string, limit int) ([]EBPFBandwidthRow, error) {
	if r.store == nil {
		return nil, nil
	}
	return r.store.LoadBandwidthSnapshot(ctx, agentID)
}

// ── Trace Events ────────────────────────────────────────────────────────────

// TraceEventRow is defined in domain; the alias keeps this package's API.
type TraceEventRow = domain.TraceEventRow

func (r *EBPFRepo) InsertTraceEvents(ctx context.Context, agentID string, events []TraceEventRow) error {
	if len(events) == 0 {
		return nil
	}
	if r.store != nil {
		if err := r.store.InsertSecurityEvents(agentID, events); err != nil {
			return err
		}
	}
	if r.eventCache != nil {
		r.eventCache.push(r.agentTenant(ctx, agentID), agentID, events)
	}
	return nil
}

func (r *EBPFRepo) RecentTraceEvents(ctx context.Context, agentID string, limit int) ([]TraceEventRow, error) {
	if r.eventCache != nil {
		if rows, ok := r.eventCache.recent(agentID, limit); ok {
			return rows, nil
		}
	}
	if r.store != nil {
		return r.store.QuerySecurityEvents(ctx, agentID, limit)
	}
	return nil, nil
}

// RecentTraceEventsByCategory returns recent events filtered by a specific category.
func (r *EBPFRepo) RecentTraceEventsByCategory(ctx context.Context, agentID, category string, limit int) ([]TraceEventRow, error) {
	if r.store == nil {
		return nil, nil
	}
	return r.store.QuerySecurityEventsByCategory(ctx, agentID, category, limit)
}

func (r *EBPFRepo) RecentTraceEventsSince(ctx context.Context, agentID string, since time.Time, limit int, minSeverity ...int) ([]TraceEventRow, error) {
	minSev := 0
	if len(minSeverity) > 0 {
		minSev = minSeverity[0]
	}
	if r.eventCache != nil && minSev == 0 {
		// Unfiltered queries: use the in-memory cache for hot-path SSE reads.
		if rows, ok := r.eventCache.since(agentID, since, limit); ok {
			return rows, nil
		}
	}
	if r.store != nil {
		return r.store.QuerySecurityEventsSince(ctx, agentID, since, limit, minSev)
	}
	return nil, nil
}

// ── Trace Stats ─────────────────────────────────────────────────────────────

func (r *EBPFRepo) InsertTraceStats(ctx context.Context, projectID, agentID string, payload json.RawMessage) error {
	_, err := r.pool.Exec(ctx,
		`UPDATE agents SET last_trace_stats_json=$1, last_state_at=NOW() WHERE deleted_at IS NULL AND id=$2 AND project_id=$3`,
		[]byte(payload), agentID, projectID,
	)
	if err != nil && r.store != nil {
		r.store.writeFailed(agentID)
	}
	return err
}

func (r *EBPFRepo) LatestTraceStats(ctx context.Context, agentID string) (json.RawMessage, time.Time, error) {
	var raw []byte
	var stateAt time.Time
	err := r.pool.QueryRow(ctx,
		`SELECT last_trace_stats_json, COALESCE(last_state_at, NOW()) FROM agents WHERE deleted_at IS NULL AND id=$1`, agentID,
	).Scan(&raw, &stateAt)
	if err != nil {
		return nil, time.Time{}, err
	}
	return json.RawMessage(raw), stateAt, nil
}

// BatchLatestTraceStats fetches the most-recent trace-stats payload for each
// agent in one query. Reads from PostgreSQL agents.last_trace_stats_json
// for O(1) PK lookup.
func (r *EBPFRepo) BatchLatestTraceStats(ctx context.Context, agentIDs []string) (map[string]json.RawMessage, error) {
	if len(agentIDs) == 0 {
		return map[string]json.RawMessage{}, nil
	}
	rows, err := r.pool.Query(ctx,
		`SELECT id, last_trace_stats_json FROM agents WHERE deleted_at IS NULL AND id = ANY($1) AND last_trace_stats_json IS NOT NULL`,
		agentIDs,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]json.RawMessage, len(agentIDs))
	for rows.Next() {
		var id string
		var payload []byte
		if e := rows.Scan(&id, &payload); e == nil && len(payload) > 0 {
			out[id] = json.RawMessage(payload)
		}
	}
	return out, rows.Err()
}

// AdjustedSeverityStats returns severity counts from host_sec_features for the
// given agent over the specified window. sinceMinutes=0 means all time.
func (r *EBPFRepo) AdjustedSeverityStats(ctx context.Context, agentID string, sinceMinutes int) (map[string]int64, int64, error) {
	if r.store == nil {
		return map[string]int64{}, 0, nil
	}
	return r.store.QuerySecFeatureSeverityCounts(ctx, agentID, sinceMinutes)
}

// ── Enforcement Log ─────────────────────────────────────────────────────────

// EnforcementLogRow is defined in domain; the alias keeps this package's API.
type EnforcementLogRow = domain.EnforcementLogRow

func (r *EBPFRepo) InsertEnforcementLog(ctx context.Context, agentID string, entries []EnforcementLogRow) error {
	if len(entries) == 0 || r.store == nil {
		return nil
	}
	if err := r.store.InsertEnforcementEntries(agentID, entries); err != nil {
		return err
	}
	r.enfLive.push(r.agentTenant(ctx, agentID), agentID, entries, enforcementRowBytes)
	return nil
}

func (r *EBPFRepo) RecentEnforcementLog(ctx context.Context, agentID string, limit int) ([]EnforcementLogRow, error) {
	if r.store == nil {
		return nil, nil
	}
	return r.store.QueryEnforcementLog(ctx, agentID, limit)
}

func (r *EBPFRepo) RecentEnforcementLogSince(ctx context.Context, agentID string, since time.Time, limit int) ([]EnforcementLogRow, error) {
	if r.store == nil {
		return nil, nil
	}
	return r.store.QueryEnforcementLogSince(ctx, agentID, since, limit)
}

// ClearEnforcementLog deletes all enforcement log entries for an agent.
func (r *EBPFRepo) ClearEnforcementLog(ctx context.Context, agentID string) error {
	if r.store == nil {
		return nil
	}
	return r.store.DeleteEnforcementLog(ctx, agentID)
}

// ── Trace Policies (Runtime Security) ───────────────────────────────────────
//
// Persisted runtime-security policies. The agent owns the live in-memory
// PolicyEngine (it must, since it is what evaluates kernel events in
// real-time), but the server is the source of truth. After a successful
// agent CRUD operation, the server stores the policy here so it can be
// replayed when the agent reconnects with an empty engine.
//
// TracePolicyRow mirrors shared/hostpolicy.EnforcementPolicy.

type TracePolicyRow struct {
	ID                     string // server-side UUID
	AgentID                string
	PolicyID               *int // agent-assigned uint32, may be nil before first sync
	Name                   string
	Description            string
	Enabled                bool
	EventTypes             []string
	MinSeverity            string
	MatchComm              string
	MatchCommMode          string // exact | word | substring (migration 000093); "" is stored as substring
	MatchFilename          string
	MatchUID               *uint32
	MatchDestPort          string
	MatchDestIP            string
	Action                 string
	KillAcknowledged       bool // operator confirmed a kill policy with no narrowing match
	KernelEnforce          bool
	KernelEnforceRequested bool
	AutoDowngraded         bool
	EnforcementMode        string
	MITRETechniqueID       string
	MITRETechniqueName     string
	MITRETactic            string
	Severity               string
	Tags                   []string
	HitCount               int64
	CreatedAt              time.Time
	UpdatedAt              time.Time
}

// UpsertTracePolicy stores a policy that has been accepted by the agent.
// If a row exists for (agent_id, policy_id) it is overwritten. Otherwise
// a new row is created. Returns the surrogate UUID.
func (r *EBPFRepo) UpsertTracePolicy(ctx context.Context, row *TracePolicyRow) (string, error) {
	if row.EventTypes == nil {
		row.EventTypes = []string{}
	}
	if row.Tags == nil {
		row.Tags = []string{}
	}
	eventTypesJSON, _ := json.Marshal(row.EventTypes)
	tagsJSON, _ := json.Marshal(row.Tags)

	var matchUID *int64
	if row.MatchUID != nil {
		v := int64(*row.MatchUID)
		matchUID = &v
	}
	// An agent that predates match_comm_mode reports none; it matches
	// substrings, so that is what the row records.
	commMode := row.MatchCommMode
	if commMode == "" {
		commMode = "substring"
	}

	// Try to update an existing row first (matched by agent_id + policy_id).
	if row.PolicyID != nil {
		var id string
		err := r.pool.QueryRow(ctx, `
			UPDATE ebpf_trace_policies
			   SET name = $3, description = $4, enabled = $5,
			       event_types = $6::jsonb, min_severity = $7,
			       match_comm = $8, match_filename = $9, match_uid = $10,
			       match_dest_port = $11, action = $12,
			       kernel_enforce = $13, kernel_enforce_requested = $14,
			       auto_downgraded = $15, enforcement_mode = $16,
			       mitre_technique_id = $17, mitre_technique_name = $18,
			       mitre_tactic = $19, severity = $20, tags = $21::jsonb,
			       match_dest_ip = $22, kill_acknowledged = $23,
			       match_comm_mode = $24,
			       updated_at = NOW()
			 WHERE agent_id = $1 AND policy_id = $2
		 RETURNING id`,
			row.AgentID, *row.PolicyID,
			row.Name, row.Description, row.Enabled,
			string(eventTypesJSON), row.MinSeverity,
			row.MatchComm, row.MatchFilename, matchUID,
			row.MatchDestPort, row.Action,
			row.KernelEnforce, row.KernelEnforceRequested,
			row.AutoDowngraded, row.EnforcementMode,
			row.MITRETechniqueID, row.MITRETechniqueName,
			row.MITRETactic, row.Severity, string(tagsJSON),
			row.MatchDestIP, row.KillAcknowledged,
			commMode,
		).Scan(&id)
		if err == nil {
			return id, nil
		}
		if err != pgx.ErrNoRows {
			return "", err
		}
	}

	var id string
	err := r.pool.QueryRow(ctx, `
		INSERT INTO ebpf_trace_policies (
		    agent_id, policy_id, name, description, enabled,
		    event_types, min_severity,
		    match_comm, match_filename, match_uid, match_dest_port, action,
		    kernel_enforce, kernel_enforce_requested, auto_downgraded, enforcement_mode,
		    mitre_technique_id, mitre_technique_name, mitre_tactic, severity, tags,
		    match_dest_ip, kill_acknowledged, match_comm_mode
		) VALUES (
		    $1, $2, $3, $4, $5,
		    $6::jsonb, $7,
		    $8, $9, $10, $11, $12,
		    $13, $14, $15, $16,
		    $17, $18, $19, $20, $21::jsonb,
		    $22, $23, $24
		) RETURNING id`,
		row.AgentID, row.PolicyID,
		row.Name, row.Description, row.Enabled,
		string(eventTypesJSON), row.MinSeverity,
		row.MatchComm, row.MatchFilename, matchUID, row.MatchDestPort, row.Action,
		row.KernelEnforce, row.KernelEnforceRequested, row.AutoDowngraded, row.EnforcementMode,
		row.MITRETechniqueID, row.MITRETechniqueName, row.MITRETactic, row.Severity, string(tagsJSON),
		row.MatchDestIP, row.KillAcknowledged, commMode,
	).Scan(&id)
	return id, err
}

// ListTracePoliciesByAgent returns every persisted policy for an agent,
// ordered by policy_id NULLS LAST so the UI shows a stable order.
func (r *EBPFRepo) ListTracePoliciesByAgent(ctx context.Context, agentID string) ([]TracePolicyRow, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, agent_id, policy_id, name, description, enabled,
		       event_types, min_severity,
		       match_comm, match_filename, match_uid, match_dest_port, action,
		       kernel_enforce, kernel_enforce_requested, auto_downgraded, enforcement_mode,
		       mitre_technique_id, mitre_technique_name, mitre_tactic, severity, tags,
		       match_dest_ip, kill_acknowledged, match_comm_mode,
		       hit_count, created_at, updated_at
		  FROM ebpf_trace_policies
		 WHERE agent_id = $1
		 ORDER BY policy_id NULLS LAST, created_at`, agentID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	out := []TracePolicyRow{}
	for rows.Next() {
		var row TracePolicyRow
		var eventTypesRaw, tagsRaw []byte
		var matchUID *int64
		var policyID *int32
		if err := rows.Scan(
			&row.ID, &row.AgentID, &policyID, &row.Name, &row.Description, &row.Enabled,
			&eventTypesRaw, &row.MinSeverity,
			&row.MatchComm, &row.MatchFilename, &matchUID, &row.MatchDestPort, &row.Action,
			&row.KernelEnforce, &row.KernelEnforceRequested, &row.AutoDowngraded, &row.EnforcementMode,
			&row.MITRETechniqueID, &row.MITRETechniqueName, &row.MITRETactic, &row.Severity, &tagsRaw,
			&row.MatchDestIP, &row.KillAcknowledged, &row.MatchCommMode,
			&row.HitCount, &row.CreatedAt, &row.UpdatedAt,
		); err != nil {
			return nil, err
		}
		if policyID != nil {
			v := int(*policyID)
			row.PolicyID = &v
		}
		if matchUID != nil {
			v := clampUint32FromInt64(*matchUID)
			row.MatchUID = &v
		}
		_ = json.Unmarshal(eventTypesRaw, &row.EventTypes)
		_ = json.Unmarshal(tagsRaw, &row.Tags)
		if row.EventTypes == nil {
			row.EventTypes = []string{}
		}
		if row.Tags == nil {
			row.Tags = []string{}
		}
		out = append(out, row)
	}
	return out, rows.Err()
}

// GetAgentHostID returns the host_id linked to an agent, or "" if none.
// Used by the gRPC stream to propagate host online/offline status without
// requiring the agent to supply a host key on the command line.
func (r *EBPFRepo) GetAgentHostID(ctx context.Context, agentID string) string {
	var hostID string
	_ = r.pool.QueryRow(ctx,
		`SELECT COALESCE(host_id::text, '') FROM agents WHERE deleted_at IS NULL AND id = $1`, agentID,
	).Scan(&hostID)
	return hostID
}

// GetAgentProjectID returns the project_id for an agent, or "" if not found.
func (r *EBPFRepo) GetAgentProjectID(ctx context.Context, agentID string) string {
	var projectID string
	_ = r.pool.QueryRow(ctx,
		`SELECT COALESCE(project_id::text, '') FROM agents WHERE deleted_at IS NULL AND id = $1`, agentID,
	).Scan(&projectID)
	return projectID
}

// traceArgs are a TracePolicyRow's column values as stored (JSON lists,
// signed uid, "" comm mode stored as substring), shared by the writes.
type traceArgs struct {
	name, description, minSeverity, matchComm, matchFilename, matchDestPort, action  string
	enforcementMode, mitreTechniqueID, mitreTechniqueName, mitreTactic, severity     string
	matchDestIP, commMode, eventTypes, tags                                          string
	enabled, kernelEnforce, kernelEnforceRequested, autoDowngraded, killAcknowledged bool
	matchUID                                                                         *int64
}

func traceRowArgs(row *TracePolicyRow) traceArgs {
	eventTypes, tags := row.EventTypes, row.Tags
	if eventTypes == nil {
		eventTypes = []string{}
	}
	if tags == nil {
		tags = []string{}
	}
	eventTypesJSON, _ := json.Marshal(eventTypes)
	tagsJSON, _ := json.Marshal(tags)
	var matchUID *int64
	if row.MatchUID != nil {
		v := int64(*row.MatchUID)
		matchUID = &v
	}
	commMode := row.MatchCommMode
	if commMode == "" {
		commMode = "substring" // as UpsertTracePolicy
	}
	return traceArgs{
		name: row.Name, description: row.Description, minSeverity: row.MinSeverity,
		matchComm: row.MatchComm, matchFilename: row.MatchFilename, matchDestPort: row.MatchDestPort, action: row.Action,
		enforcementMode: row.EnforcementMode, mitreTechniqueID: row.MITRETechniqueID, mitreTechniqueName: row.MITRETechniqueName,
		mitreTactic: row.MITRETactic, severity: row.Severity, matchDestIP: row.MatchDestIP, commMode: commMode,
		eventTypes: string(eventTypesJSON), tags: string(tagsJSON),
		enabled: row.Enabled, kernelEnforce: row.KernelEnforce, kernelEnforceRequested: row.KernelEnforceRequested,
		autoDowngraded: row.AutoDowngraded, killAcknowledged: row.KillAcknowledged, matchUID: matchUID,
	}
}

// ErrTracePolicyIDExhausted: no free policy id could be allocated (the agent
// numbers policies as uint32; the column is a signed int).
var ErrTracePolicyIDExhausted = errors.New("no trace policy id available for this agent")

// CreateTracePolicy inserts a new policy row with the next free policy_id of
// its agent (MAX+1) and returns the row's surrogate id and the policy id. The
// id is allocated and inserted in one statement under a per-agent advisory
// transaction lock, and the unique index on (agent_id, policy_id) (migration
// 000101) makes a clash a no-op that is retried — a create never updates an
// existing row. row.PolicyID is ignored and set on success.
func (r *EBPFRepo) CreateTracePolicy(ctx context.Context, row *TracePolicyRow) (string, int, error) {
	a := traceRowArgs(row)
	for attempt := 0; attempt < 3; attempt++ {
		id, policyID, err := r.createTracePolicyOnce(ctx, row.AgentID, a)
		if err != nil {
			return "", 0, err
		}
		if id != "" {
			row.PolicyID = &policyID
			return id, policyID, nil
		}
	}
	return "", 0, errors.New("trace policy id allocation kept conflicting")
}

func (r *EBPFRepo) createTracePolicyOnce(ctx context.Context, agentID string, a traceArgs) (string, int, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return "", 0, err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if _, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "trace-policy-id:"+agentID); err != nil {
		return "", 0, err
	}
	var (
		id       string
		policyID int
	)
	err = tx.QueryRow(ctx, `
		INSERT INTO ebpf_trace_policies (
		    agent_id, policy_id, name, description, enabled,
		    event_types, min_severity,
		    match_comm, match_filename, match_uid, match_dest_port, action,
		    kernel_enforce, kernel_enforce_requested, auto_downgraded, enforcement_mode,
		    mitre_technique_id, mitre_technique_name, mitre_tactic, severity, tags,
		    match_dest_ip, kill_acknowledged, match_comm_mode
		)
		SELECT $1, n.next, $2, $3, $4,
		       $5::jsonb, $6,
		       $7, $8, $9, $10, $11,
		       $12, $13, $14, $15,
		       $16, $17, $18, $19, $20::jsonb,
		       $21, $22, $23
		  FROM (SELECT COALESCE(MAX(policy_id), 0) + 1 AS next
		          FROM ebpf_trace_policies WHERE agent_id = $1) n
		 WHERE n.next <= 2147483647
		ON CONFLICT (agent_id, policy_id) WHERE policy_id IS NOT NULL DO NOTHING
		RETURNING id, policy_id`,
		agentID,
		a.name, a.description, a.enabled,
		a.eventTypes, a.minSeverity,
		a.matchComm, a.matchFilename, a.matchUID, a.matchDestPort, a.action,
		a.kernelEnforce, a.kernelEnforceRequested, a.autoDowngraded, a.enforcementMode,
		a.mitreTechniqueID, a.mitreTechniqueName, a.mitreTactic, a.severity, a.tags,
		a.matchDestIP, a.killAcknowledged, a.commMode,
	).Scan(&id, &policyID)
	if errors.Is(err, pgx.ErrNoRows) {
		// A clash (DO NOTHING) or an exhausted id space: tell them apart.
		var maxID *int
		if qerr := tx.QueryRow(ctx, `SELECT MAX(policy_id) FROM ebpf_trace_policies WHERE agent_id = $1`, agentID).Scan(&maxID); qerr != nil {
			return "", 0, qerr
		}
		if maxID != nil && *maxID >= 2147483647 {
			return "", 0, ErrTracePolicyIDExhausted
		}
		return "", 0, nil
	}
	if err != nil {
		return "", 0, err
	}
	if err := tx.Commit(ctx); err != nil {
		return "", 0, err
	}
	return id, policyID, nil
}

// DeleteTracePolicyByPolicyID removes a single persisted policy identified
// by its agent-assigned numeric id.
func (r *EBPFRepo) DeleteTracePolicyByPolicyID(ctx context.Context, agentID string, policyID int) error {
	_, err := r.pool.Exec(ctx,
		`DELETE FROM ebpf_trace_policies WHERE agent_id = $1 AND policy_id = $2`,
		agentID, policyID)
	return err
}

// CountTracePolicies returns how many persisted policies an agent has.
// Used by the ingest path to decide whether to auto-resync after an agent
// restart wiped its in-memory PolicyEngine.
func (r *EBPFRepo) CountTracePolicies(ctx context.Context, agentID string) (int, error) {
	var n int
	err := r.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM ebpf_trace_policies WHERE agent_id = $1`,
		agentID).Scan(&n)
	return n, err
}

// UpdateTracePolicyHitCounts merges live hit counts from the agent into
// ebpf_trace_policies. Only rows that match agent_id + policy_id are updated.
// Rows with no new hits (hit_count = 0) are intentionally excluded from the
// hitCounts map by the caller to avoid unnecessary writes.
func (r *EBPFRepo) UpdateTracePolicyHitCounts(ctx context.Context, agentID string, hitCounts map[uint32]uint64) error {
	for pid, hc := range hitCounts {
		_, err := r.pool.Exec(ctx,
			`UPDATE ebpf_trace_policies SET hit_count = $3, updated_at = NOW()
			  WHERE agent_id = $1 AND policy_id = $2`,
			agentID, clampInt32FromUint32(pid), clampInt64FromUint64(hc))
		if err != nil {
			return err
		}
	}
	return nil
}

// IncrementTracePolicyHitCount adds delta to the hit_count for the given
// (agent_id, policy_id) row. Because agent-assigned policy IDs can change
// across agent restarts, it first tries to match by policy_id and, if that
// affects 0 rows and policyName is non-empty, falls back to matching by name
// (also resyncing policy_id so future lookups by ID succeed).
func (r *EBPFRepo) IncrementTracePolicyHitCount(ctx context.Context, agentID string, policyID int, policyName string, delta int64) error {
	tag, err := r.pool.Exec(ctx,
		`UPDATE ebpf_trace_policies SET hit_count = hit_count + $3, updated_at = NOW()
		  WHERE agent_id = $1 AND policy_id = $2`,
		agentID, policyID, delta)
	if err != nil {
		return err
	}
	if tag.RowsAffected() > 0 || policyName == "" {
		return nil
	}
	// policy_id changed (agent restarted) — match by name and resync the ID.
	_, err = r.pool.Exec(ctx,
		`UPDATE ebpf_trace_policies SET hit_count = hit_count + $3, policy_id = $4, updated_at = NOW()
		  WHERE agent_id = $1 AND name = $2`,
		agentID, policyName, delta, policyID)
	return err
}

// ── Multi-agent / aggregate queries ─────────────────────────────────────────

// RecentEventsMulti returns merged firewall events from multiple agents, ordered by time DESC.
// Reads from the in-memory ring buffer — no database round-trip.
func (r *EBPFRepo) RecentEventsMulti(ctx context.Context, agentIDs []string, limit int) ([]EBPFEventRow, error) {
	if len(agentIDs) == 0 || r.store == nil {
		return nil, nil
	}
	docs := r.store.RecentFirewallEventsMultiRing(agentIDs, limit)
	out := make([]EBPFEventRow, len(docs))
	for i, d := range docs {
		out[i] = EBPFEventRow{
			SrcIP:     d.SrcIP,
			DstIP:     d.DstIP,
			SrcPort:   d.SrcPort,
			DstPort:   d.DstPort,
			Proto:     d.Proto,
			Action:    d.Action,
			Reason:    d.Reason,
			TCPFlags:  d.TCPFlags,
			PktLen:    d.PktLen,
			RuleID:    d.RuleID,
			EventTime: time.Unix(d.Ts, 0).UTC(),
		}
	}
	return out, nil
}

// RecentTraceEventsMulti returns merged trace events from multiple agents, ordered by time DESC.
// minSeverity is numeric (0=info, 1=low, 2=medium, 3=high, 4=critical).
func (r *EBPFRepo) RecentTraceEventsMulti(ctx context.Context, agentIDs []string, minSeverity int, limit int) ([]TraceEventRow, error) {
	if len(agentIDs) == 0 || r.store == nil {
		return nil, nil
	}
	return r.store.QuerySecurityEventsMulti(ctx, agentIDs, minSeverity, limit)
}

// AggregateMetrics sums the latest metrics snapshots across multiple agents.
// Reads from PostgreSQL agents.last_metrics_json for O(1) PK lookup.
// Returns nil if no agent has metrics yet.
func (r *EBPFRepo) AggregateMetrics(ctx context.Context, agentIDs []string) (*EBPFMetricsRow, error) {
	if len(agentIDs) == 0 {
		return nil, nil
	}
	rows, err := r.pool.Query(ctx,
		`SELECT id, last_metrics_json FROM agents WHERE deleted_at IS NULL AND id = ANY($1) AND last_metrics_json IS NOT NULL`,
		agentIDs,
	)
	if err != nil {
		// Was `if err != nil || rows == nil { return nil, nil }`, which
		// swallowed every query failure and reported it as "no metrics yet".
		// The rows == nil half was dead: pgx never returns a nil Rows with a
		// nil error.
		return nil, err
	}
	defer rows.Close()
	var agg EBPFMetricsRow
	found := false
	for rows.Next() {
		var id string
		var payload []byte
		if e := rows.Scan(&id, &payload); e != nil || len(payload) == 0 {
			continue
		}
		var m EBPFMetricsRow
		if e := json.Unmarshal(payload, &m); e != nil {
			continue
		}
		found = true
		agg.RxPackets += m.RxPackets
		agg.RxBytes += m.RxBytes
		agg.TxPackets += m.TxPackets
		agg.TxBytes += m.TxBytes
		agg.DroppedPackets += m.DroppedPackets
		agg.DroppedBytes += m.DroppedBytes
		agg.WouldDropPackets += m.WouldDropPackets
		agg.WouldDropBytes += m.WouldDropBytes
		agg.StateTableFull += m.StateTableFull
		agg.PacketParseFailures += m.PacketParseFailures
		agg.RatelimitedPackets += m.RatelimitedPackets
		agg.SynfloodDrops += m.SynfloodDrops
		agg.BlocklistDrops += m.BlocklistDrops
		agg.AllowlistPasses += m.AllowlistPasses
		agg.GeoblockDrops += m.GeoblockDrops
		agg.ConntrackEntries += m.ConntrackEntries
		agg.PortScanDrops += m.PortScanDrops
		agg.PortPolicyDrops += m.PortPolicyDrops
		agg.EgressIPDrops += m.EgressIPDrops
		agg.PPS += m.PPS
		agg.BPS += m.BPS
		agg.DropRatePct += m.DropRatePct
		if m.RecordedAt.After(agg.RecordedAt) {
			agg.RecordedAt = m.RecordedAt
		}
	}
	if rows.Err() != nil || !found {
		return nil, rows.Err()
	}
	return &agg, nil
}

// AggregateTraceStats sums trace severity/event counts across multiple agents.
// Returns a merged JSON payload matching the TraceStats shape.
func (r *EBPFRepo) AggregateTraceStats(ctx context.Context, agentIDs []string) (json.RawMessage, error) {
	if len(agentIDs) == 0 {
		return json.Marshal(map[string]any{})
	}
	type statsShape struct {
		TotalEvents int64            `json:"total_events"`
		EventCounts map[string]int64 `json:"event_counts"`
		BySeverity  map[string]int64 `json:"by_severity"`
		ByCategory  map[string]int64 `json:"by_category"`
		BufferUsed  int64            `json:"buffer_used"`
		BufferTotal int64            `json:"buffer_total"`
		UptimeMS    int64            `json:"uptime_ms"`
	}
	agg := statsShape{
		EventCounts: map[string]int64{},
		BySeverity:  map[string]int64{},
		ByCategory:  map[string]int64{},
	}
	// Batch fetch all trace stats in one query.
	payloads, err := r.BatchLatestTraceStats(ctx, agentIDs)
	if err != nil {
		return json.Marshal(map[string]any{})
	}
	found := false
	for _, payload := range payloads {
		if len(payload) == 0 {
			continue
		}
		var s statsShape
		if err := json.Unmarshal(payload, &s); err != nil {
			continue
		}
		found = true
		agg.TotalEvents += s.TotalEvents
		agg.BufferUsed += s.BufferUsed
		agg.BufferTotal += s.BufferTotal
		if s.UptimeMS > agg.UptimeMS {
			agg.UptimeMS = s.UptimeMS
		}
		for k, v := range s.EventCounts {
			agg.EventCounts[k] += v
		}
		for k, v := range s.BySeverity {
			agg.BySeverity[k] += v
		}
		for k, v := range s.ByCategory {
			agg.ByCategory[k] += v
		}
	}
	if !found {
		return json.Marshal(map[string]any{})
	}
	return json.Marshal(agg)
}

// AggregateTraceStatsSince returns time-windowed severity/category counts from
// host_sec_features (feature store). sinceMinutes=0 falls back to the push-payload
// stats (AggregateTraceStats). The two feature queries run concurrently.
func (r *EBPFRepo) AggregateTraceStatsSince(ctx context.Context, agentIDs []string, sinceMinutes int) (json.RawMessage, error) {
	if len(agentIDs) == 0 {
		return json.Marshal(map[string]any{})
	}
	if r.store == nil || sinceMinutes <= 0 {
		return r.AggregateTraceStats(ctx, agentIDs)
	}

	var (
		bySeverity map[string]int64
		total      int64
		sevErr     error
		byCategory map[string]int64
	)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		bySeverity, total, sevErr = r.store.QuerySecFeatureSeverityCountsMulti(ctx, agentIDs, sinceMinutes)
	}()
	go func() {
		defer wg.Done()
		byCategory, _ = r.store.QuerySecFeatureCategoriesMulti(ctx, agentIDs, sinceMinutes)
	}()
	wg.Wait()

	if sevErr != nil {
		// Fallback to push-payload stats on feature query error.
		return r.AggregateTraceStats(ctx, agentIDs)
	}
	if byCategory == nil {
		byCategory = map[string]int64{}
	}
	type statsShape struct {
		TotalEvents int64            `json:"total_events"`
		BySeverity  map[string]int64 `json:"by_severity"`
		EventCounts map[string]int64 `json:"event_counts"`
		ByCategory  map[string]int64 `json:"by_category"`
	}
	out := statsShape{
		TotalEvents: total,
		BySeverity:  bySeverity,
		EventCounts: map[string]int64{},
		ByCategory:  byCategory,
	}
	return json.Marshal(out)
}

// ── Firewall Analytics ───────────────────────────────────────────────────────

// FirewallTopIPRow is defined in domain; the alias keeps this package's API.
type FirewallTopIPRow = domain.FirewallTopIPRow

// FirewallDropsSummaryRange returns drop summary filtered by time range.
func (r *EBPFRepo) FirewallDropsSummaryRange(ctx context.Context, agentIDs []string, sinceTs, beforeTs int64) (map[string]int64, error) {
	if r.store == nil || len(agentIDs) == 0 {
		return map[string]int64{}, nil
	}
	return r.store.QueryFWFeatureDropsSummaryRange(ctx, agentIDs, sinceTs, beforeTs)
}

// FirewallPeakHours returns attack count per hour of day (UTC).
func (r *EBPFRepo) FirewallPeakHours(ctx context.Context, agentIDs []string, sinceTs int64) ([24]int64, error) {
	var out [24]int64
	if r.store == nil || len(agentIDs) == 0 {
		return out, nil
	}
	return r.store.QueryFWFeaturePeakHours(ctx, agentIDs, sinceTs)
}

// FirewallTopIPsRange returns top attacker IPs filtered by time range.
func (r *EBPFRepo) FirewallTopIPsRange(ctx context.Context, agentIDs []string, sinceTs int64, limit int) ([]FirewallTopIPRow, error) {
	if r.store == nil || len(agentIDs) == 0 {
		return nil, nil
	}
	entries, err := r.store.QueryFWFeatureTopIPsRange(ctx, agentIDs, sinceTs, limit)
	if err != nil {
		return nil, err
	}
	out := make([]FirewallTopIPRow, len(entries))
	for i, e := range entries {
		out[i] = FirewallTopIPRow{
			SrcIP:      e.SrcIP,
			Blocklist:  e.Blocklist,
			RateLimit:  e.RateLimit,
			SynFlood:   e.SynFlood,
			GeoBlock:   e.GeoBlock,
			PortScan:   e.PortScan,
			PortPolicy: e.PortPolicy,
			Other:      e.Other,
			Total:      e.Total,
		}
	}
	return out, nil
}

// FirewallUniqueIPCount returns distinct IP count in time range.
func (r *EBPFRepo) FirewallUniqueIPCount(ctx context.Context, agentIDs []string, sinceTs int64) (int64, error) {
	if r.store == nil || len(agentIDs) == 0 {
		return 0, nil
	}
	return r.store.QueryFWFeatureUniqueIPCount(ctx, agentIDs, sinceTs)
}

// FirewallDropsSummaryByMinutes returns drop counts per reason for the last sinceMinutes minutes.
func (r *EBPFRepo) FirewallDropsSummaryByMinutes(ctx context.Context, agentIDs []string, sinceMinutes int) (map[string]int64, error) {
	if r.store == nil || len(agentIDs) == 0 {
		return map[string]int64{}, nil
	}
	sinceTs := time.Now().Unix() - int64(sinceMinutes)*60
	return r.store.QueryFWFeatureDropsSummaryRange(ctx, agentIDs, sinceTs, 0)
}
