package domain

import (
	"strings"
	"testing"
)

const flaggedPayload = "admin' or 1=1-- "

func flagged(source, value string) MatchEvidence {
	return MatchEvidence{Source: source, Exact: true, Flagged: &value}
}

// With the flagged value known, a same-named field holding
// another value is redacted — nested duplicate, escaped or percent-encoded
// key, a duplicate past the stored copy's cut — and the flagged one is kept.
func TestRedactBodyKeepsOnlyFlaggedValue(t *testing.T) {
	m := flagged("body.json:token", flaggedPayload)
	cases := []struct{ in, want string }{
		{`{"token":"VICTIM-1","d":{"token":"` + flaggedPayload + `"}}`, `{"token":"[redacted]","d":{"token":"` + flaggedPayload + `"}}`},
		{`{"token":"VICTIM-1","token":"` + flaggedPayload + `"}`, `{"token":"[redacted]","token":"` + flaggedPayload + `"}`},
		{`{"tok%65n":"VICTIM-1","token":"` + flaggedPayload + `"}`, `{"tok%65n":"[redacted]","token":"` + flaggedPayload + `"}`},
		// cut copy: the flagged duplicate lies past the end
		{`{"token":"VICTIM-1","pad":"xxxx`, `{"token":"[redacted]","pad":"xxxx`},
		// the flagged value written with escapes is still the flagged value
		{`{"token":"admin' or 1=1-- "}`, `{"token":"admin' or 1=1-- "}`},
		// an object under the flagged key is not the flagged string
		{`{"token":{"v":"VICTIM-1"}}`, `{"token":{"v":"[redacted]"}}`},
	}
	for _, c := range cases {
		for _, complete := range []bool{true, false} {
			got := RedactDecisionBodyCopy(c.in, "json", m, complete)
			if got != c.want {
				t.Errorf("%s (complete=%v):\n got  %s\n want %s", c.in, complete, got, c.want)
			}
			if again := RedactDecisionBodyCopy(got, "json", m, complete); again != got {
				t.Errorf("not idempotent: %s -> %s", got, again)
			}
		}
	}
	form := flagged("body:token", flaggedPayload)
	in := "token=VICTIM-1&q=" + strings.Repeat("a", 64) // flagged duplicate past the cut
	if got := RedactDecisionBodyCopy(in, "form", form, false); strings.Contains(got, "VICTIM") {
		t.Errorf("form cut: %s", got)
	}
	in = "token=admin%27+or+1%3D1--+&token=VICTIM-1"
	if got, want := RedactDecisionBodyCopy(in, "form", form, true), "token=admin%27+or+1%3D1--+&token=[redacted]"; got != want {
		t.Errorf("form: got %s want %s", got, want)
	}
	mp := "--b\r\nContent-Disposition: form-data; name=\"token\"\r\n\r\nVICTIM-1\r\n--b\r\nContent-Disposition: form-data; name=\"x\"\r\n\r\ny"
	if got := RedactDecisionBodyCopy(mp, "multipart/form-data; boundary=b", form, false); strings.Contains(got, "VICTIM") {
		t.Errorf("multipart: %s", got)
	}
	// query and header of the exact source follow the same rule
	if got := RedactDecisionQuery("token=VICTIM-1&token="+flaggedPayload, flagged("query:token", flaggedPayload)); got != "token=[redacted]&token="+flaggedPayload {
		t.Errorf("query: %s", got)
	}
	h := RedactDecisionHeaders(map[string]string{"X-Api-Token": "VICTIM-1"}, flagged("header:X-Api-Token", "<script>"))
	if h["X-Api-Token"] != DecisionRedactedMarker {
		t.Errorf("header: %v", h)
	}
}

// Without the flagged value, several values of the
// target — names decoded as the engine decodes them — or a copy that may be
// cut keep only payload-like values; a current agent's output is unchanged.
func TestRedactBodyFlaggedUnknownIsConservative(t *testing.T) {
	m := MatchEvidence{Source: "body.json:token", Exact: true}
	for _, in := range []string{
		`{"token":"VICTIM-1","d":{"token":"` + flaggedPayload + `"}}`,
		`{"token":"VICTIM-1","d":{"token":"` + flaggedPayload + `"}}`,
		`{"tok%65n":"VICTIM-1","d":{"token":"` + flaggedPayload + `"}}`,
	} {
		got := RedactDecisionBodyCopy(in, "json", m, true)
		if strings.Contains(got, "VICTIM") || !strings.Contains(got, flaggedPayload) {
			t.Errorf("%s -> %s", in, got)
		}
	}
	single := `{"token":"VICTIM-1"}`
	if got := RedactDecisionBodyCopy(single, "json", m, true); got != single {
		t.Errorf("complete single value: %s", got)
	}
	if got := RedactDecisionBodyCopy(single, "json", m, false); strings.Contains(got, "VICTIM") {
		t.Errorf("cut copy kept a non-payload target: %s", got)
	}
	fm := MatchEvidence{Source: "body:token", Exact: true}
	if got := RedactDecisionBodyCopy("token=VICTIM-1&q=1", "form", fm, false); strings.Contains(got, "VICTIM") {
		t.Errorf("form cut: %s", got)
	}
	// agent output, then control plane: unchanged (one unredacted value left)
	agent := RedactDecisionBodyCopy(`{"token":"VICTIM-1","d":{"token":"`+flaggedPayload+`"}}`, "json", flagged("body.json:token", flaggedPayload), true)
	if cp := RedactDecisionBodyCopy(agent, "json", m, true); cp != agent {
		t.Errorf("control plane changed the agent's output: %s -> %s", agent, cp)
	}
	agentForm := RedactDecisionBodyCopy("token="+flaggedPayload+"&token=VICTIM-1", "form", flagged("body:token", flaggedPayload), true)
	if cp := RedactDecisionBodyCopy(agentForm, "form", fm, true); cp != agentForm {
		t.Errorf("control plane changed the agent's form: %s -> %s", agentForm, cp)
	}
}

// Item 4: past maxRedactJSONDepth every scalar value is redacted, keys stay;
// above it the walk is unchanged.
func TestRedactJSONDepthCap(t *testing.T) {
	deep := strings.Repeat(`{"a":`, maxRedactJSONDepth) + `{"note":"hello","n":5,"ok":true}` + strings.Repeat("}", maxRedactJSONDepth)
	got := RedactDecisionBody(deep, "json", MatchEvidence{})
	if !strings.Contains(got, `{"note":"[redacted]","n":"[redacted]","ok":true}`) {
		t.Errorf("past the cap: %s", got[len(got)-120:])
	}
	if RedactDecisionBody(got, "json", MatchEvidence{}) != got {
		t.Error("not idempotent past the cap")
	}
	shallow := strings.Repeat(`{"a":`, maxRedactJSONDepth-1) + `{"note":"hello","password":"p"}` + strings.Repeat("}", maxRedactJSONDepth-1)
	if got := RedactDecisionBody(shallow, "json", MatchEvidence{}); !strings.Contains(got, `{"note":"hello","password":"[redacted]"}`) {
		t.Errorf("at the cap: %s", got[len(got)-120:])
	}
	// back above the cap after the deep part closes
	mixed := `{"x":` + strings.Repeat("[", maxRedactJSONDepth+3) + `"v"` + strings.Repeat("]", maxRedactJSONDepth+3) + `,"note":"hello","pin":"1"}`
	if got, want := RedactDecisionBody(mixed, "json", MatchEvidence{}), strings.Replace(strings.Replace(mixed, `"v"`, `"[redacted]"`, 1), `"pin":"1"`, `"pin":"[redacted]"`, 1); got != want {
		t.Errorf("after the deep part:\n got  %s\n want %s", got, want)
	}
	if got := RedactDecisionBody(strings.Repeat("[", 4096), "json", MatchEvidence{}); got != strings.Repeat("[", 4096) {
		t.Error("bare nesting changed")
	}
}

func TestJSONUnescape(t *testing.T) {
	cases := []struct {
		in, want string
		ok       bool
	}{
		{`a\"b\\c\/d\n`, "a\"b\\c/d\n", true},
		{`token`, "token", true},
		{`😀`, "\U0001F600", true},
		{`\ud83dx`, "�x", true},
		{`\u12`, `\u12`, false},
		{`\q`, `\q`, false},
		{`x\`, `x\`, false},
	}
	for _, c := range cases {
		if got, ok := jsonUnescape(c.in); got != c.want || ok != c.ok {
			t.Errorf("%q: got %q %v, want %q %v", c.in, got, ok, c.want, c.ok)
		}
	}
}

// The control plane never un-redacts the agent's output: every marker the
// agent wrote survives, and the agent's output is stable under its own
// evidence.
func FuzzRedactDecisionBodyFlagged(f *testing.F) {
	f.Add(`{"token":"V","d":{"token":"admin' or 1=1-- "}}`, "json", "body.json:token", "admin' or 1=1-- ", true)
	f.Add("token=V&token=%3Cscript%3E", "form", "body:token", "<script>", false)
	f.Add(strings.Repeat("[", 70)+`{"pin":1}`, "json", "", "", true)
	f.Fuzz(func(t *testing.T, body, ct, ms, val string, complete bool) {
		agent := MatchEvidence{Source: ms, Exact: true, Flagged: &val}
		out := RedactDecisionBodyCopy(body, ct, agent, complete)
		if again := RedactDecisionBodyCopy(out, ct, agent, complete); again != out {
			t.Fatalf("agent not idempotent: %q -> %q -> %q", body, out, again)
		}
		cp := RedactDecisionBodyCopy(out, ct, MatchEvidence{Source: ms, Exact: true}, complete)
		if strings.Count(cp, DecisionRedactedMarker) < strings.Count(out, DecisionRedactedMarker) {
			t.Fatalf("control plane dropped a marker: %q -> %q", out, cp)
		}
	})
}
