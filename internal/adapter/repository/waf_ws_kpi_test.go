package repository

import (
	"strings"
	"testing"
)

// TestWSSummaryFiltersListScope guards this: the WS message KPIs
// (ws_messages_blocked / ws_messages_logged) must be FRAMES-only — handshake
// rows are excluded so they don't double-report with ws_handshake_rejected —
// while the handshake KPI keeps its own match. The FILTERs themselves execute
// in PostgreSQL (no DB in unit CI), so this asserts the SQL shape of the
// counters: the structural properties below are exactly what the rule requires.
func TestWSSummaryFiltersListScope(t *testing.T) {
	wsBlocked, wsLogged, handshake := wafCountWSBlocked+" AS ws_blocked", wafCountWSLogged+" AS ws_logged", wafCountWSHandshakeRejected+" AS ws_handshake_rejected"

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
