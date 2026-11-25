package repository

import (
	"context"
	"encoding/json"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ── Coverage column mapping (no database) ──────────────────────────────

func TestDecisionCopyRowMatchesColumns(t *testing.T) {
	row := decisionCopyRow(WAFDecision{AgentID: "a", Action: "allow", Coverage: "field_cap"})
	if len(row) != len(decisionCopyColumns) {
		t.Fatalf("row has %d values for %d columns", len(row), len(decisionCopyColumns))
	}
	idx := -1
	for i, c := range decisionCopyColumns {
		if c == "coverage" {
			idx = i
		}
	}
	if idx < 0 {
		t.Fatal("coverage column not copied")
	}
	if row[idx] != "field_cap" {
		t.Fatalf("coverage value = %v", row[idx])
	}
	// Complete coverage (and every pre-v1.2 agent) is stored NULL.
	if empty := decisionCopyRow(WAFDecision{AgentID: "a", Action: "allow"}); empty[idx] != nil {
		t.Fatalf("empty coverage must be NULL, got %v", empty[idx])
	}
}

func TestWAFDecisionRowJSONHasCoverage(t *testing.T) {
	b, err := json.Marshal(WAFDecisionRow{Coverage: "body_binary", Status: 403})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(b), `"coverage":"body_binary"`) || !strings.Contains(string(b), `"status":403`) {
		t.Fatalf("decision JSON: %s", b)
	}
	// Complete coverage is an explicit empty string, not a missing key, and an
	// unrecorded status is 0.
	b, _ = json.Marshal(WAFDecisionRow{})
	if !strings.Contains(string(b), `"coverage":""`) || !strings.Contains(string(b), `"status":0`) {
		t.Fatalf("decision JSON without coverage: %s", b)
	}
}

// presentDecisionRow gives a stored row the shape the API shows.
func TestPresentDecisionRow(t *testing.T) {
	for _, tc := range []struct {
		method, coverage    string
		wantMethod, wantCov string
		wantOff, wantLog    []string
	}{
		{"rule_based", "field_cap,engine_disabled:xss", "semantic", "field_cap", []string{"xss"}, []string{}},
		{"hybrid", "", "semantic", "", []string{}, []string{}},
		{"semantic", "engine_disabled:sql,engine_disabled:jwt", "semantic", "", []string{"sql", "jwt"}, []string{}},
		{"policy", "engine_weakened:xss", "policy", "engine_weakened:xss", []string{}, []string{}},
		{"", "truncated", "", "truncated", []string{}, []string{}},
		{"semantic", "engine_log_only:sql", "semantic", "", []string{}, []string{"sql"}},
		{"semantic", "field_cap,engine_disabled:xss,engine_log_only:jwt,engine_log_only:sql", "semantic", "field_cap", []string{"xss"}, []string{"jwt", "sql"}},
	} {
		d := WAFDecisionRow{AnalyzeMethod: tc.method, Coverage: tc.coverage}
		presentDecisionRow(&d)
		if d.AnalyzeMethod != tc.wantMethod || d.Coverage != tc.wantCov || !slices.Equal(d.EnginesOff, tc.wantOff) || d.EnginesOff == nil ||
			!slices.Equal(d.EnginesLogOnly, tc.wantLog) || d.EnginesLogOnly == nil {
			t.Errorf("%+v: got method %q coverage %q engines_off %v engines_log_only %v", tc, d.AnalyzeMethod, d.Coverage, d.EnginesOff, d.EnginesLogOnly)
		}
	}
}

// The row shows how strong the detection behind it was, and JSON null when none stands behind it.
func TestPresentDecisionRowStrength(t *testing.T) {
	for _, tc := range []struct {
		action, coverage string
		categories       []string
		want             string
	}{
		{"block", "", []string{"SQLi"}, `"strength":"block"`},
		{"monitor", "", []string{"SQLi"}, `"strength":"block"`},
		{"log", "engine_log_only:sql", []string{"SQLi"}, `"strength":"block"`},
		{"log", "field_cap", []string{"Anomaly"}, `"strength":"weak"`},
		{"log", "", nil, `"strength":null`},
		{"allow", "", nil, `"strength":null`},
		{"challenge", "", nil, `"strength":null`},
	} {
		d := WAFDecisionRow{Action: tc.action, Coverage: tc.coverage, Categories: tc.categories}
		presentDecisionRow(&d)
		b, err := json.Marshal(d)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), tc.want) {
			t.Errorf("%+v: row lacks %s: %s", tc, tc.want, b)
		}
	}
}

// The status of a decision is stored when the agent reported one and NULL when
// it did not (0 means not recorded); a value that is no HTTP status is dropped.
func TestDecisionCopyRowStatus(t *testing.T) {
	idx := slices.Index(decisionCopyColumns, "status")
	if idx < 0 {
		t.Fatal("status column not copied")
	}
	for status, want := range map[int]any{403: 403, 502: 502, 0: nil} {
		if got := decisionCopyRow(WAFDecision{AgentID: "a", Action: "block", Status: status})[idx]; got != want {
			t.Errorf("status %d stored as %v, want %v", status, got, want)
		}
	}
	for _, bad := range []int{-1, 1000, 70000} {
		if got := decisionCopyRow(sanitizeDecision(WAFDecision{AgentID: "a", Status: bad}))[idx]; got != nil {
			t.Errorf("status %d stored as %v, want NULL", bad, got)
		}
	}
}

// ── Agent health counters in the agent read model ─────────────────────

func TestAgentWithHostInfoJSONHealthCounters(t *testing.T) {
	n := func(v int64) *int64 { return &v }
	b, err := json.Marshal(AgentWithHostInfo{
		ID: "x", AnalyzePanicsTotal: n(0), EnginePanicsTotal: n(4),
		PartialCoverageTotal: n(12), ParseBudgetExhaustedTotal: n(1),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"analyze_panics_total":0`, `"engine_panics_total":4`, `"partial_coverage_total":12`, `"parse_budget_exhausted_total":1`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("agent JSON missing %s: %s", want, b)
		}
	}
	// Heartbeat fields 11-19 use these API names.
	b, err = json.Marshal(AgentWithHostInfo{
		ID: "z", ScriptIncompleteTotal: n(1), ScriptErrorsTotal: n(0), ScriptRulesRejectedTotal: n(2),
		ScriptRunsInFlight: n(0), AgentPanicsTotal: n(3), AnalyzeLatencyP50Us: n(300),
		AnalyzeLatencyP95Us: n(900), AnalyzeLatencyP99Us: n(2500), AnalyzeLatencySamples: n(77),
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"script_incomplete_total":1`, `"script_errors_total":0`, `"script_rules_rejected_total":2`,
		`"script_runs_in_flight":0`, `"agent_panics_total":3`, `"analyze_latency_p50_us":300`,
		`"analyze_latency_p95_us":900`, `"analyze_latency_p99_us":2500`, `"analyze_latency_samples":77`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("agent JSON missing %s: %s", want, b)
		}
	}
	// Heartbeat field 20 uses this API name.
	b, err = json.Marshal(AgentWithHostInfo{ID: "r", RegexRulesDroppedTotal: n(0)})
	if err != nil || !strings.Contains(string(b), `"regex_rules_dropped_total":0`) {
		t.Fatalf("agent JSON missing regex_rules_dropped_total (err=%v): %s", err, b)
	}
	// Never reported (old agent, host agent): keys omitted.
	b, _ = json.Marshal(AgentWithHostInfo{ID: "y"})
	if strings.Contains(string(b), "panics_total") || strings.Contains(string(b), "waf_health_updated_at") ||
		strings.Contains(string(b), "analyze_latency") || strings.Contains(string(b), "script_incomplete") ||
		strings.Contains(string(b), "script_errors") || strings.Contains(string(b), "script_rules_rejected") ||
		strings.Contains(string(b), "script_runs") || strings.Contains(string(b), "regex_rules_dropped") {
		t.Fatalf("unreported counters must be omitted: %s", b)
	}
}

func TestAgentWAFHealthReported(t *testing.T) {
	if (AgentWAFHealth{}).Reported() {
		t.Fatal("empty health reported")
	}
	zero := int64(0)
	if !(AgentWAFHealth{ParseBudgetExhaustedTotal: &zero}).Reported() {
		t.Fatal("a present zero counter is a report")
	}
	none := ""
	if !(AgentWAFHealth{BundleSource: &none}).Reported() {
		t.Fatal("a present empty bundle_source (no bundle yet) is a report")
	}
	// No counters: no query, so a nil pool is never touched.
	if err := (&EBPFRepo{}).UpdateAgentWAFHealth(context.Background(), "p", "a", AgentWAFHealth{}); err != nil {
		t.Fatal(err)
	}
}

// ── Against PostgreSQL (TEST_DB_URL): migration 000086 + queries ──────────

// preObservabilityDDL is the subset of the pre-000086 schema the touched
// queries read. The test applies the real 000086 up/down files on top.
const preObservabilityDDL = `
CREATE TABLE agents (
    id                uuid PRIMARY KEY,
    user_id           uuid NOT NULL,
    project_id        uuid NOT NULL,
    host_id           uuid,
    name              varchar(100) NOT NULL,
    kind              varchar(16) NOT NULL DEFAULT 'waf',
    last_seen         timestamptz,
    created_at        timestamptz NOT NULL DEFAULT NOW(),
    hostname          text, version text,
    host_os text, host_os_version text, host_kernel text, host_arch text,
    host_cpu_count int, host_memory bigint, host_virt text,
    host_boot_time timestamptz, host_updated_at timestamptz, host_info jsonb,
    proxy_listen_port int,
    deleted_at timestamptz
);
CREATE TABLE waf_decisions (
    id             bigserial,
    agent_id       uuid        NOT NULL REFERENCES agents(id) ON DELETE CASCADE,
    app_id         uuid,
    host text, method text, uri text, remote_addr text, country_code text,
    user_agent text, content_type text,
    action         text        NOT NULL,
    score          int         NOT NULL DEFAULT 0,
    categories     text[]      NOT NULL DEFAULT '{}',
    cwe text, match_detail text, analyze_method text,
    body_size      int         NOT NULL DEFAULT 0,
    latency_us     int         NOT NULL DEFAULT 0,
    body_preview   text,
    event_time     timestamptz NOT NULL,
    recorded_at    timestamptz NOT NULL DEFAULT NOW(),
    match_source text, request_headers jsonb, request_body text, query_params text, payload_type text,
    PRIMARY KEY (id, recorded_at)
);`

func readMigration(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile("../../../migrations/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestWAFObservabilityAgainstPostgres(t *testing.T) {
	dsn := os.Getenv("TEST_DB_URL")
	if dsn == "" {
		t.Skip("TEST_DB_URL not set")
	}
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "obs_" + uuid.NewString()[:8]
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if _, err := admin.Exec(ctx, "DROP SCHEMA "+quoted+" CASCADE"); err != nil {
			t.Error(err)
		}
	}()
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()

	if _, err := pool.Exec(ctx, preObservabilityDDL); err != nil {
		t.Fatalf("base schema: %v", err)
	}
	up := readMigration(t, "000086_waf_observability.up.sql")
	if _, err := pool.Exec(ctx, up); err != nil {
		t.Fatalf("000086 up: %v", err)
	}
	// Idempotent (IF NOT EXISTS), like the rest of the migration set.
	if _, err := pool.Exec(ctx, up); err != nil {
		t.Fatalf("000086 up twice: %v", err)
	}
	// 000096 adds heartbeat fields 11-19; the agent SELECTs read them.
	up96 := readMigration(t, "000096_agents_waf_observability.up.sql")
	for i := 0; i < 2; i++ {
		if _, err := pool.Exec(ctx, up96); err != nil {
			t.Fatalf("000096 up (run %d): %v", i+1, err)
		}
	}
	// 000097 adds heartbeat field 20.
	up97 := readMigration(t, "000097_agents_waf_regex_rules_dropped.up.sql")
	for i := 0; i < 2; i++ {
		if _, err := pool.Exec(ctx, up97); err != nil {
			t.Fatalf("000097 up (run %d): %v", i+1, err)
		}
	}
	// 000099 adds heartbeat fields 9-10.
	up99 := readMigration(t, "000099_agents_waf_bundle_provenance.up.sql")
	for i := 0; i < 2; i++ {
		if _, err := pool.Exec(ctx, up99); err != nil {
			t.Fatalf("000099 up (run %d): %v", i+1, err)
		}
	}

	// 000115 adds rule_engine; no code reads it now, the column stays.
	up115 := readMigration(t, "000115_agents_rule_engine.up.sql")
	for i := 0; i < 2; i++ {
		if _, err := pool.Exec(ctx, up115); err != nil {
			t.Fatalf("000115 up (run %d): %v", i+1, err)
		}
	}

	// 000116 adds script_rules, which the agent SELECTs read.
	up116 := readMigration(t, "000116_agents_script_rules.up.sql")
	for i := 0; i < 2; i++ {
		if _, err := pool.Exec(ctx, up116); err != nil {
			t.Fatalf("000116 up (run %d): %v", i+1, err)
		}
	}

	// 000119 and 000124 add agents.maintenance_mode and agents.tls_certificates, which UpdateAgentFeatures
	// writes. This schema has no apps table, so only the agents columns are added here; the migrations
	// themselves run in the round-trip test.
	if _, err := pool.Exec(ctx, `ALTER TABLE agents ADD COLUMN maintenance_mode BOOLEAN, ADD COLUMN tls_certificates BOOLEAN`); err != nil {
		t.Fatalf("feature columns: %v", err)
	}
	// The write of the TLS flag asks whether a credential is bound to the agent row; only the columns it reads exist here.
	if _, err := pool.Exec(ctx, `CREATE TABLE mtls_credentials (id uuid PRIMARY KEY, project_id uuid, host_id uuid, agent_kind text, agent_name text)`); err != nil {
		t.Fatalf("credentials table: %v", err)
	}

	// 000117 adds waf_decisions.status.
	up117 := readMigration(t, "000117_waf_decisions_status.up.sql")
	for i := 0; i < 2; i++ {
		if _, err := pool.Exec(ctx, up117); err != nil {
			t.Fatalf("000117 up (run %d): %v", i+1, err)
		}
	}

	// The app summary reads the rollup tables.
	if _, err := pool.Exec(ctx, readMigration(t, "000126_waf_rollups.up.sql")); err != nil {
		t.Fatalf("000126 up: %v", err)
	}

	projectID, otherProject := uuid.NewString(), uuid.NewString()
	userID := uuid.NewString()
	wafID, oldID, foreignID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	for _, a := range []struct{ id, project, name string }{
		{wafID, projectID, "edge-new"}, {oldID, projectID, "edge-old"}, {foreignID, otherProject, "edge-foreign"},
	} {
		if _, err := pool.Exec(ctx, `INSERT INTO agents (id,user_id,project_id,name,kind,last_seen) VALUES ($1,$2,$3,$4,'waf',NOW())`,
			a.id, userID, a.project, a.name); err != nil {
			t.Fatal(err)
		}
	}
	ebpf := &EBPFRepo{pool: pool}
	n := func(v int64) *int64 { return &v }
	health := AgentWAFHealth{AnalyzePanicsTotal: n(0), EnginePanicsTotal: n(3), PartialCoverageTotal: n(17), ParseBudgetExhaustedTotal: n(2),
		ScriptIncompleteTotal: n(6), ScriptErrorsTotal: n(1), ScriptRulesRejectedTotal: n(0), ScriptRunsInFlight: n(2),
		AgentPanicsTotal: n(1), AnalyzeLatencySamples: n(900), AnalyzeLatencyP50Us: n(350), AnalyzeLatencyP95Us: n(1500),
		AnalyzeLatencyP99Us: n(4100), RegexRulesDroppedTotal: n(2),
		BundleSource: func() *string { s := "cache_stale"; return &s }(), BundleGeneration: n(42)}
	if err := ebpf.UpdateAgentWAFHealth(ctx, projectID, wafID, health); err != nil {
		t.Fatalf("update health: %v", err)
	}
	// Cross-tenant write is a no-op (project_id scope).
	if err := ebpf.UpdateAgentWAFHealth(ctx, projectID, foreignID, health); err != nil {
		t.Fatal(err)
	}

	agents, err := ebpf.ListAgentsForUser(ctx, "", projectID, "waf")
	if err != nil {
		t.Fatalf("list agents: %v", err)
	}
	byID := map[string]AgentWithHostInfo{}
	for _, a := range agents {
		byID[a.ID] = a
	}
	got := byID[wafID]
	if got.EnginePanicsTotal == nil || *got.EnginePanicsTotal != 3 || *got.PartialCoverageTotal != 17 ||
		*got.AnalyzePanicsTotal != 0 || *got.ParseBudgetExhaustedTotal != 2 || got.WAFHealthUpdatedAt == nil {
		t.Fatalf("stored health not read back: %+v", got)
	}
	if got.AnalyzeLatencyP99Us == nil || *got.AnalyzeLatencyP99Us != 4100 || *got.AnalyzeLatencySamples != 900 ||
		*got.ScriptIncompleteTotal != 6 || *got.ScriptRunsInFlight != 2 || *got.AgentPanicsTotal != 1 {
		t.Fatalf("heartbeat fields 11-19 not read back: %+v", got)
	}
	if got.RegexRulesDroppedTotal == nil || *got.RegexRulesDroppedTotal != 2 {
		t.Fatalf("heartbeat field 20 not read back: %+v", got)
	}
	if got.BundleSource == nil || *got.BundleSource != "cache_stale" || got.BundleGeneration == nil || *got.BundleGeneration != 42 {
		t.Fatalf("heartbeat fields 9-10 not read back: %+v", got)
	}
	// 000115: the column stays and no code reads or writes it. A stored value
	// does not change what the agent reads return.
	if _, err := pool.Exec(ctx, `UPDATE agents SET rule_engine = TRUE WHERE id = $1`, wafID); err != nil {
		t.Fatal(err)
	}
	if agents, err = ebpf.ListAgentsForUser(ctx, "", projectID, "waf"); err != nil {
		t.Fatal(err)
	}
	var found bool
	for _, a := range agents {
		if a.ID == wafID {
			found = true
			if a.EnginePanicsTotal == nil || *a.EnginePanicsTotal != 3 {
				t.Fatalf("list: health read back wrong with the unused column set: %+v", a)
			}
		}
	}
	if !found {
		t.Fatal("list: the agent is missing")
	}
	// 000116: the same, for script_rules.
	if got.ScriptRules != nil {
		t.Fatalf("an agent that never reported script rules must read NULL: %+v", got)
	}
	no := false
	if err := ebpf.UpdateAgentFeatures(ctx, projectID, wafID, &no, nil, nil, true); err != nil {
		t.Fatal(err)
	}
	if err := ebpf.UpdateAgentFeatures(ctx, otherProject, oldID, &no, nil, nil, true); err != nil {
		t.Fatal(err)
	}
	if sr, err := ebpf.AgentScriptRules(ctx, wafID); err != nil || sr == nil || *sr {
		t.Fatalf("stored script rules not read back by id: %v %v", sr, err)
	}
	if sr, err := ebpf.AgentScriptRules(ctx, oldID); err != nil || sr != nil {
		t.Fatalf("a write scoped to another project must not change the agent: %v %v", sr, err)
	}
	if sr, err := ebpf.AgentScriptRules(ctx, uuid.NewString()); err != nil || sr != nil {
		t.Fatalf("an unknown agent reads as unknown: %v %v", sr, err)
	}
	if agents, err = ebpf.ListAgentsForUser(ctx, "", projectID, "waf"); err != nil {
		t.Fatal(err)
	}
	for _, a := range agents {
		if want := a.ID == wafID; (a.ScriptRules != nil && !*a.ScriptRules) != want || (a.ID == oldID && a.ScriptRules != nil) {
			t.Fatalf("list: agent %s script_rules %v", a.Name, a.ScriptRules)
		}
	}
	if old := byID[oldID]; old.BundleSource != nil || old.BundleGeneration != nil {
		t.Fatalf("agent that never reported bundle provenance must read NULL: %+v", old)
	}
	if old := byID[oldID]; old.EnginePanicsTotal != nil || old.WAFHealthUpdatedAt != nil {
		t.Fatalf("agent that never reported must read NULL: %+v", old)
	}
	foreign, err := ebpf.ListAgentsForUser(ctx, "", otherProject, "waf")
	if err != nil || len(foreign) != 1 || foreign[0].EnginePanicsTotal != nil {
		t.Fatalf("cross-tenant update leaked: err=%v %+v", err, foreign)
	}

	waf := &WAFRepo{pool: pool}
	now := time.Now().UTC()
	if err := waf.InsertDecisions(ctx, []WAFDecision{
		{AgentID: wafID, Action: "log", URI: "/partial", CountryCode: "ID", EventTime: now, Coverage: "field_cap,body_binary"},
		{AgentID: wafID, Action: "allow", URI: "/complete", EventTime: now},
		{AgentID: wafID, Action: "block", URI: "/blocked", EventTime: now, Status: 403, AnalyzeMethod: "semantic",
			Coverage: "truncated,engine_disabled:xss,engine_disabled:jwt"},
		{AgentID: wafID, Action: "log", URI: "/held", EventTime: now, Status: 200, AnalyzeMethod: "semantic",
			Coverage: "field_cap,engine_disabled:xss,engine_log_only:sql"},
	}); err != nil {
		t.Fatalf("insert decisions: %v", err)
	}
	var nulls int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM waf_decisions WHERE coverage IS NULL`).Scan(&nulls); err != nil || nulls != 1 {
		t.Fatalf("empty coverage must be stored NULL: n=%d err=%v", nulls, err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM waf_decisions WHERE status IS NULL`).Scan(&nulls); err != nil || nulls != 2 {
		t.Fatalf("a status of 0 must be stored NULL: n=%d err=%v", nulls, err)
	}
	rows, err := waf.ListDecisionsForProject(ctx, projectID, "", 10)
	if err != nil {
		t.Fatalf("list project decisions: %v", err)
	}
	cov, country, status, off, logOnly := map[string]string{}, map[string]string{}, map[string]int{}, map[string][]string{}, map[string][]string{}
	for _, r := range rows {
		cov[r.URI] = r.Coverage
		country[r.URI] = r.CountryCode
		status[r.URI] = r.Status
		off[r.URI] = r.EnginesOff
		logOnly[r.URI] = r.EnginesLogOnly
	}
	if cov["/partial"] != "field_cap,body_binary" || cov["/complete"] != "" || cov["/blocked"] != "truncated" || cov["/held"] != "field_cap" || len(cov) != 4 {
		t.Fatalf("project decisions coverage: %v", cov)
	}
	// The status the agent reported is read back; a row without one reads 0.
	if status["/blocked"] != 403 || status["/partial"] != 0 || status["/complete"] != 0 {
		t.Fatalf("project decisions status: %v", status)
	}
	// The engine marks leave the coverage text and become engines_off, [] when none.
	if !slices.Equal(off["/blocked"], []string{"xss", "jwt"}) || off["/partial"] == nil || len(off["/partial"]) != 0 {
		t.Fatalf("project decisions engines_off: %v", off)
	}
	// The engine_log_only marks become engines_log_only, [] when none and for rows that never had one.
	if !slices.Equal(logOnly["/held"], []string{"sql"}) || !slices.Equal(off["/held"], []string{"xss"}) {
		t.Fatalf("held row: engines_log_only %v engines_off %v", logOnly["/held"], off["/held"])
	}
	for _, uri := range []string{"/partial", "/complete", "/blocked"} {
		if logOnly[uri] == nil || len(logOnly[uri]) != 0 {
			t.Fatalf("%s: engines_log_only %v, want []", uri, logOnly[uri])
		}
	}
	// The stored country is read back (the Decisions table's Country column).
	if country["/partial"] != "ID" || country["/complete"] != "" {
		t.Fatalf("project decisions country: %v", country)
	}
	appPage, err := waf.ListDecisionsForApp(ctx, projectID, uuid.NewString(), AppDecisionsFilter{})
	if err != nil || appPage.Total != 0 || len(appPage.Rows) != 0 {
		t.Fatalf("app decisions query: rows=%d total=%d err=%v", len(appPage.Rows), appPage.Total, err)
	}

	// Rows an older agent wrote (analyze_method rule_based and hybrid, engine marks among the gap flags,
	// no status) read, count and list in the current vocabulary, and stay as stored.
	appID := uuid.NewString()
	for _, r := range []struct{ uri, method, coverage string }{
		{"/v1-rule-based", "rule_based", "header_len,engine_disabled:ssrf"},
		{"/v1-hybrid", "hybrid", ""},
		{"/v1-semantic", "semantic", "engine_disabled:xss"},
		{"/v1-policy", "policy", ""},
	} {
		if _, err := pool.Exec(ctx, `INSERT INTO waf_decisions (agent_id, app_id, uri, action, analyze_method, coverage, event_time, recorded_at)
			VALUES ($1, $2, $3, 'block', $4, NULLIF($5, ''), NOW(), NOW())`, wafID, appID, r.uri, r.method, r.coverage); err != nil {
			t.Fatal(err)
		}
	}
	page, err := waf.ListDecisionsForApp(ctx, projectID, appID, AppDecisionsFilter{})
	if err != nil || len(page.Rows) != 4 {
		t.Fatalf("v1 rows: %d err=%v", len(page.Rows), err)
	}
	for _, r := range page.Rows {
		wantMethod := map[string]string{"/v1-rule-based": "semantic", "/v1-hybrid": "semantic", "/v1-semantic": "semantic", "/v1-policy": "policy"}[r.URI]
		if r.AnalyzeMethod != wantMethod || r.Status != 0 {
			t.Errorf("%s: analyze_method %q status %d, want %q and 0", r.URI, r.AnalyzeMethod, r.Status, wantMethod)
		}
		switch r.URI {
		case "/v1-rule-based":
			if r.Coverage != "header_len" || !slices.Equal(r.EnginesOff, []string{"ssrf"}) {
				t.Errorf("%s: coverage %q engines_off %v", r.URI, r.Coverage, r.EnginesOff)
			}
		case "/v1-semantic":
			if r.Coverage != "" || !slices.Equal(r.EnginesOff, []string{"xss"}) {
				t.Errorf("%s: only marks are not a gap: coverage %q engines_off %v", r.URI, r.Coverage, r.EnginesOff)
			}
		}
	}
	var stored int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM waf_decisions WHERE analyze_method IN ('rule_based','hybrid')`).Scan(&stored); err != nil || stored != 2 {
		t.Fatalf("stored rows must not be rewritten: n=%d err=%v", stored, err)
	}
	sum, err := waf.SummarizeApp(ctx, projectID, appID, 60)
	if err != nil || sum.SemanticTriggers != 3 || sum.OtherTriggers != 1 {
		t.Fatalf("stats: %+v err=%v, want rule_based, hybrid and semantic counted as semantic", sum, err)
	}
	if raw, err := json.Marshal(sum); err != nil || strings.Contains(string(raw), "rule_based_triggers") || strings.Contains(string(raw), "hybrid_triggers") {
		t.Fatalf("stats JSON still has the removed fields: %s %v", raw, err)
	}
	byMethod, err := waf.DecisionsByAnalyzeMethod(ctx, projectID, now.Add(-time.Hour).Unix(), now.Add(time.Hour).Unix())
	if err != nil {
		t.Fatal(err)
	}
	counts := map[string]int{}
	for _, b := range byMethod {
		counts[b.Key] = b.Count
	}
	if counts["rule_based"] != 0 || counts["hybrid"] != 0 || counts["semantic"] != 5 || counts["policy"] != 1 {
		t.Fatalf("by analyze method: %v", counts)
	}

	if _, err := pool.Exec(ctx, readMigration(t, "000117_waf_decisions_status.down.sql")); err != nil {
		t.Fatalf("000117 down: %v", err)
	}
	if _, err := pool.Exec(ctx, readMigration(t, "000116_agents_script_rules.down.sql")); err != nil {
		t.Fatalf("000116 down: %v", err)
	}
	if _, err := pool.Exec(ctx, readMigration(t, "000115_agents_rule_engine.down.sql")); err != nil {
		t.Fatalf("000115 down: %v", err)
	}
	if _, err := pool.Exec(ctx, readMigration(t, "000099_agents_waf_bundle_provenance.down.sql")); err != nil {
		t.Fatalf("000099 down: %v", err)
	}
	if _, err := pool.Exec(ctx, readMigration(t, "000097_agents_waf_regex_rules_dropped.down.sql")); err != nil {
		t.Fatalf("000097 down: %v", err)
	}
	if _, err := pool.Exec(ctx, readMigration(t, "000096_agents_waf_observability.down.sql")); err != nil {
		t.Fatalf("000096 down: %v", err)
	}
	if _, err := pool.Exec(ctx, readMigration(t, "000086_waf_observability.down.sql")); err != nil {
		t.Fatalf("000086 down: %v", err)
	}
	var cols int
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns
		WHERE table_schema = $1 AND table_name = 'waf_decisions' AND column_name = 'status'`, schema).Scan(&cols); err != nil || cols != 0 {
		t.Fatalf("the 000117 down migration left the status column (err=%v)", err)
	}
	if err := pool.QueryRow(ctx, `SELECT count(*) FROM information_schema.columns
		WHERE table_schema = $1 AND column_name IN ('coverage','analyze_panics_total','engine_panics_total',
		  'partial_coverage_total','parse_budget_exhausted_total','waf_health_updated_at','waf_regex_rules_dropped_total',
		  'waf_bundle_source','waf_bundle_generation','rule_engine','script_rules')`, schema).Scan(&cols); err != nil || cols != 0 {
		t.Fatalf("down migration left %d columns (err=%v)", cols, err)
	}
}
