package repository

import (
	"strings"
	"testing"
)

// TestWSSummaryFiltersListScope guards this: the WS message KPIs
// (ws_messages_blocked / ws_messages_logged) must be FRAMES-only — handshake
// rows are excluded so they don't double-report with ws_handshake_rejected —
// while the handshake KPI keeps its own match. The FILTERs themselves execute
// in PostgreSQL (no DB in unit CI), so this asserts the generated SQL shape:
// the structural properties below are exactly what the rule requires.
func TestWSSummaryFiltersListScope(t *testing.T) {
	sqlText := wsSummaryFilters()
	lines := strings.Split(sqlText, ",\n")
	if len(lines) != 3 {
		t.Fatalf("wsSummaryFilters: got %d FILTER clauses, want 3\nSQL:\n%s", len(lines), sqlText)
	}
	wsBlocked, wsLogged, handshake := lines[0], lines[1], lines[2]

	for name, clause := range map[string]string{
		"ws_blocked": wsBlocked,
		"ws_logged":  wsLogged,
	} {
		if !strings.Contains(clause, wsScopePredicate) {
			t.Errorf("%s: missing WS scope predicate %q\nclause: %s", name, wsScopePredicate, clause)
		}
		// Handshake rows excluded from the message KPIs. IS DISTINCT FROM
		// TRUE (not <> / NOT), so NULL match_source frame rows stay counted.
		if !strings.Contains(clause, wsHandshakePredicate+" IS DISTINCT FROM TRUE") {
			t.Errorf("%s: missing NULL-safe handshake exclusion %q\nclause: %s", name, wsHandshakePredicate+" IS DISTINCT FROM TRUE", clause)
		}
		if strings.Contains(clause, "AS ws_handshake_rejected") {
			t.Errorf("%s: must not be the handshake KPI\nclause: %s", name, clause)
		}
	}

	if !strings.Contains(handshake, wsHandshakePredicate) {
		t.Errorf("handshake KPI: missing %q\nclause: %s", wsHandshakePredicate, handshake)
	}
	if strings.Contains(handshake, "IS DISTINCT FROM TRUE") {
		t.Errorf("handshake KPI: must not carry the message-KPI exclusion\nclause: %s", handshake)
	}

	// wsScopePredicate itself must stay the LIST-scope predicate
	// (frames + handshake); only the KPI FILTERs narrow it.
	if !strings.Contains(wsScopePredicate, "method = 'WEBSOCKET'") ||
		!strings.Contains(wsScopePredicate, "match_source LIKE 'ws:%'") {
		t.Errorf("wsScopePredicate drifted from the list scope: %q", wsScopePredicate)
	}
}

func TestAppDecisionHTTPSourceIncludesNullMatchSource(t *testing.T) {
	clause := appDecisionSourceClause("http")
	if !strings.Contains(clause, wsScopePredicate+" IS NOT TRUE") {
		t.Fatalf("HTTP source must include legacy rows with NULL match_source: %s", clause)
	}
	if got := appDecisionSourceClause("ws"); !strings.Contains(got, wsScopePredicate) || strings.Contains(got, "IS NOT TRUE") {
		t.Fatalf("WebSocket source predicate changed: %s", got)
	}
}

func TestSummarizeProjectQueryNoFormatMangle(t *testing.T) {
	// Guard against fmt.Sprintf corrupting queries with %!(MISSING) when wsSummaryFilters is used
	sqlText := wsSummaryFilters()
	if strings.Contains(sqlText, "%!(MISSING)") {
		t.Fatalf("wsSummaryFilters contains corrupted format specifier: %s", sqlText)
	}
	agentClause := " AND a.id = $4::uuid"
	q := `WITH scoped AS (
		SELECT d.* FROM waf_decisions d JOIN agents a ON a.id = d.agent_id
		WHERE a.project_id = $1 ` + agentClause + `
	)
	SELECT COUNT(*), ` + wsSummaryFilters() + ` FROM scoped`
	if strings.Contains(q, "%!(MISSING)") {
		t.Fatalf("query corrupted by format specifiers: %s", q)
	}
}
