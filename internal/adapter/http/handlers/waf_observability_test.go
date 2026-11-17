package handlers

import (
	"encoding/json"
	"slices"
	"strings"
	"testing"

	agentv1 "github.com/wafio/wafio-cp-backend/shared/agentpb"
)

// The live SSE decision payload carries the coverage flags in snake_case
// and omits the key when the scan was complete (or the agent is older).
func TestLiveDecisionDTOCoverage(t *testing.T) {
	b, err := json.Marshal(newLiveDecisionDTO(&agentv1.WAFDecisionEvent{
		Uri: "/upload", Action: "log", PayloadType: "json", Coverage: "field_cap,body_binary",
	}))
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"coverage":"field_cap,body_binary"`, `"uri":"/upload"`, `"payload_type":"json"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("SSE payload missing %s: %s", want, b)
		}
	}
	b, _ = json.Marshal(newLiveDecisionDTO(&agentv1.WAFDecisionEvent{Uri: "/", Action: "allow"}))
	if strings.Contains(string(b), "coverage") {
		t.Fatalf("complete coverage must be omitted: %s", b)
	}
}

// The live decision carries the derived strength, "block", "weak" or null, never a missing key.
func TestLiveDecisionDTOStrength(t *testing.T) {
	for name, tc := range map[string]struct {
		ev   *agentv1.WAFDecisionEvent
		want string
	}{
		"block":     {&agentv1.WAFDecisionEvent{Action: "block", Categories: []string{"SQLi"}, Score: 180}, `"strength":"block"`},
		"held":      {&agentv1.WAFDecisionEvent{Action: "log", Categories: []string{"SQLi"}, Coverage: "engine_log_only:sql"}, `"strength":"block"`},
		"weak":      {&agentv1.WAFDecisionEvent{Action: "log", Categories: []string{"Anomaly"}, Score: 115}, `"strength":"weak"`},
		"allow":     {&agentv1.WAFDecisionEvent{Action: "allow"}, `"strength":null`},
		"no source": {&agentv1.WAFDecisionEvent{Action: "log"}, `"strength":null`},
	} {
		b, err := json.Marshal(newLiveDecisionDTO(tc.ev))
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), tc.want) {
			t.Errorf("%s: SSE payload lacks %s: %s", name, tc.want, b)
		}
	}
}

// The legacy HTTP ingest accepts the optional coverage field.
func TestWAFIngestDecisionAcceptsCoverage(t *testing.T) {
	var p wafIngestPayload
	if err := json.Unmarshal([]byte(`{"decisions":[{"action":"allow","uri":"/","coverage":"header_count"}]}`), &p); err != nil {
		t.Fatal(err)
	}
	if len(p.Decisions) != 1 || p.Decisions[0].Coverage != "header_count" {
		t.Fatalf("decoded: %+v", p.Decisions)
	}
}

type fakeGeoEnricher map[string]string

func (f fakeGeoEnricher) Enrich(ip string) (string, string, float64, float64, string) {
	return "", f[ip], 0, 0, ""
}

// A live decision carries the client's country like a stored one; the
// agent event has none, so the stream resolves it.
func TestLiveCountry(t *testing.T) {
	geo := fakeGeoEnricher{"119.235.222.161": "id", "203.0.113.9": "ZZZ"}
	cases := []struct {
		geo  GeoEnricher
		ip   string
		want string
	}{
		{geo, "119.235.222.161", "ID"},
		{geo, "119.235.222.161:51234", "ID"},
		{geo, "203.0.113.9", ""}, // not an alpha-2 code
		{geo, "198.51.100.1", ""},
		{geo, "", ""},
		{nil, "119.235.222.161", ""},
	}
	for _, c := range cases {
		if got := liveCountry(c.geo, c.ip); got != c.want {
			t.Errorf("liveCountry(%q) = %q, want %q", c.ip, got, c.want)
		}
	}
}

// The SSE decision event carries the reported status (0 = not recorded), an older agent's analyze method
// as semantic, and the coverage text split into gap flags, engines_off and engines_log_only.
func TestLiveDecisionDTOStatusMethodAndEnginesOff(t *testing.T) {
	var got struct {
		Status         int      `json:"status"`
		AnalyzeMethod  string   `json:"analyze_method"`
		Coverage       string   `json:"coverage"`
		EnginesOff     []string `json:"engines_off"`
		EnginesLogOnly []string `json:"engines_log_only"`
	}
	decode := func(ev *agentv1.WAFDecisionEvent) string {
		got.Status, got.AnalyzeMethod, got.Coverage, got.EnginesOff, got.EnginesLogOnly = 0, "", "", nil, nil
		b, err := json.Marshal(newLiveDecisionDTO(ev))
		if err != nil {
			t.Fatal(err)
		}
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatal(err)
		}
		return string(b)
	}
	decode(&agentv1.WAFDecisionEvent{Uri: "/x", Action: "block", Status: 403, AnalyzeMethod: "semantic",
		Coverage: "truncated,engine_disabled:xss,engine_disabled:jwt"})
	if got.Status != 403 || got.AnalyzeMethod != "semantic" || got.Coverage != "truncated" || !slices.Equal(got.EnginesOff, []string{"xss", "jwt"}) {
		t.Errorf("status 403 event: %+v", got)
	}
	raw := decode(&agentv1.WAFDecisionEvent{Uri: "/x", Action: "allow", AnalyzeMethod: "rule_based", Coverage: "engine_disabled:sql"})
	if got.Status != 0 || got.AnalyzeMethod != "semantic" || got.Coverage != "" || !slices.Equal(got.EnginesOff, []string{"sql"}) {
		t.Errorf("status 0 event from an older agent: %+v", got)
	}
	if !strings.Contains(raw, `"status":0`) {
		t.Errorf("an unrecorded status is an explicit 0: %s", raw)
	}
	raw = decode(&agentv1.WAFDecisionEvent{Uri: "/x", Action: "allow"})
	if !strings.Contains(raw, `"engines_off":[]`) || !strings.Contains(raw, `"engines_log_only":[]`) {
		t.Errorf("engines_off and engines_log_only are arrays when none: %s", raw)
	}
	// A block held back as LOG: the mark leaves the coverage text and the key is listed.
	decode(&agentv1.WAFDecisionEvent{Uri: "/x", Action: "log", Status: 200, AnalyzeMethod: "semantic",
		Coverage: "field_cap,engine_disabled:xss,engine_log_only:sql"})
	if got.Coverage != "field_cap" || !slices.Equal(got.EnginesOff, []string{"xss"}) || !slices.Equal(got.EnginesLogOnly, []string{"sql"}) {
		t.Errorf("held event: %+v", got)
	}
}

// The legacy HTTP ingest takes the optional status and maps an older agent's
// analyze method to semantic.
func TestWAFIngestRowsStatusAndMethod(t *testing.T) {
	var p wafIngestPayload
	if err := json.Unmarshal([]byte(`{"decisions":[
		{"action":"block","uri":"/a","status":403,"analyze_method":"semantic"},
		{"action":"allow","uri":"/b","analyze_method":"rule_based"}]}`), &p); err != nil {
		t.Fatal(err)
	}
	rows := wafIngestRows("p", "a", p.Decisions)
	if rows[0].Status != 403 || rows[0].AnalyzeMethod != "semantic" || rows[1].Status != 0 || rows[1].AnalyzeMethod != "semantic" {
		t.Fatalf("rows: %+v", rows)
	}
}
