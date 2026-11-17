package httpadapter

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"

	"github.com/wafio/wafio-cp-backend/internal/engine"
)

// script_rules is true, false or null in the three agent reads (null when the agent never said, and for
// a host agent). rule_engine is in none of them.
func TestDBAgentScriptRulesInAgentReads(t *testing.T) {
	f := newDBFixture(t)
	ctx := context.Background()
	p := "/api/projects/" + f.project
	agentID, appID := createTestRoute(t, f, "caps-"+uuid.NewString()[:8], 18082, nil)
	_, hostAgentID := f.fleetHost(t, "host-"+uuid.NewString()[:8])

	field := func(m map[string]any) string {
		v, ok := m["script_rules"]
		switch {
		case !ok:
			return "absent"
		case v == nil:
			return "null"
		case v == true:
			return "true"
		case v == false:
			return "false"
		}
		return "other"
	}
	reads := func() map[string]string {
		out := map[string]string{}
		out["fleet agent"] = field(call(t, f.app, http.MethodGet, "/api/fleet/agents/"+agentID, f.tokens["viewer"], nil).body)
		list := call(t, f.app, http.MethodGet, "/api/fleet/agents?kind=waf&project="+f.project, f.tokens["viewer"], nil)
		out["fleet list"] = "absent"
		agents, _ := list.body["agents"].([]any)
		for _, a := range agents {
			if m, _ := a.(map[string]any); m["id"] == agentID {
				out["fleet list"] = field(m)
			}
		}
		out["app agent"] = field(call(t, f.app, http.MethodGet, p+"/apps/"+appID+"/waf-agent", f.tokens["viewer"], nil).body)
		return out
	}
	// rule_engine left the answers; the column stays and is not read.
	for read, body := range map[string]map[string]any{
		"fleet agent": call(t, f.app, http.MethodGet, "/api/fleet/agents/"+agentID, f.tokens["viewer"], nil).body,
		"app agent":   call(t, f.app, http.MethodGet, p+"/apps/"+appID+"/waf-agent", f.tokens["viewer"], nil).body,
		"host agent":  call(t, f.app, http.MethodGet, "/api/fleet/agents/"+hostAgentID, f.tokens["viewer"], nil).body,
	} {
		if _, has := body["rule_engine"]; has {
			t.Errorf("%s still answers rule_engine: %v", read, body)
		}
	}
	yes, no := true, false
	for _, tc := range []struct {
		name  string
		store *bool
		want  string
	}{
		{"never reported", nil, "null"},
		{"runs script rules", &yes, "true"},
		{"no script rules", &no, "false"},
		{"replaced by an old agent", nil, "null"},
	} {
		if err := f.repo.EBPF.UpdateAgentScriptRules(ctx, f.project, agentID, tc.store); err != nil {
			t.Fatal(err)
		}
		for read, got := range reads() {
			if got != tc.want {
				t.Errorf("%s: %s shows script_rules %s, want %s", tc.name, read, got, tc.want)
			}
		}
	}
	if got := field(call(t, f.app, http.MethodGet, "/api/fleet/agents/"+hostAgentID, f.tokens["viewer"], nil).body); got != "null" {
		t.Errorf("host agent shows script_rules %s, want null", got)
	}
}

// capsFixture is a project with one app served by one WAF agent, whose reported
// capabilities a test sets.
type capsFixture struct {
	*dbFixture
	agentID, appID string
	rules          map[string]any // the project's default rules, to start every save from
}

func newCapsFixture(t *testing.T) *capsFixture {
	t.Helper()
	f := newDBFixture(t)
	f.seedConfig(t)
	cur := call(t, f.app, http.MethodGet, "/api/projects/"+f.project+"/config", f.tokens["owner"], nil)
	rules, _ := cur.body["rules_json"].(map[string]any)
	agentID, appID := createTestRoute(t, f, "caps-"+uuid.NewString()[:8], 18083, nil)
	return &capsFixture{dbFixture: f, agentID: agentID, appID: appID, rules: rules}
}

// fresh returns a copy of the default rules.
func (c *capsFixture) fresh(t *testing.T) map[string]any {
	t.Helper()
	b, err := json.Marshal(c.rules)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func (c *capsFixture) setScripts(t *testing.T, v *bool) {
	t.Helper()
	if err := c.repo.EBPF.UpdateAgentScriptRules(context.Background(), c.project, c.agentID, v); err != nil {
		t.Fatal(err)
	}
}

func (c *capsFixture) putApp(t *testing.T, rules map[string]any) testResponse {
	t.Helper()
	url := "/api/projects/" + c.project + "/agents/" + c.agentID + "/routes/" + c.appID + "/config"
	cur := call(t, c.app, http.MethodGet, url, c.tokens["owner"], nil)
	return call(t, c.app, http.MethodPut, url, c.tokens["owner"], map[string]any{
		"expected_revision": cur.body["config_revision"], "rules_json": rules, "sensitivity": 2,
	})
}

// putProjectBody saves a project config with exactly the body given.
func (c *capsFixture) putProjectBody(t *testing.T, body map[string]any) testResponse {
	t.Helper()
	url := "/api/projects/" + c.project + "/config"
	cur := call(t, c.app, http.MethodGet, url, c.tokens["owner"], nil)
	body["expected_revision"] = cur.body["config_revision"]
	return call(t, c.app, http.MethodPut, url, c.tokens["owner"], body)
}

// storedProjectRules reads the project's saved rules back.
func (c *capsFixture) storedProjectRules(t *testing.T) map[string]any {
	t.Helper()
	got := call(t, c.app, http.MethodGet, "/api/projects/"+c.project+"/config", c.tokens["owner"], nil)
	rules, _ := got.body["rules_json"].(map[string]any)
	return rules
}

// A v1 document saves and is stored rewritten: inspection_off for the old off switches, no
// skip_coraza_when_clean, no limits of the removed engine, no threshold, base score or override, a
// switched-off engine for a base score of 0, record_weak_detections for a log score at the block score.
func TestDBLegacyRulesSaveWithoutRefusalAndAreReduced(t *testing.T) {
	c := newCapsFixture(t)
	r := c.fresh(t)
	r["request_body_in_memory_limit"] = "1M"
	r["response_body_limit"] = 2048
	sp, _ := r["semantic_policies"].(map[string]any)
	sp["skip_coraza_when_clean"] = false
	sp["disable_semantic"] = true
	sp["disable_rule_based"] = true
	sp["sql"] = map[string]any{"base_score": 0, "block_threshold": 4.0}
	sp["ldap"] = map[string]any{"base_score": 180}
	r["thresholds"] = map[string]any{"log": 150, "block": 150}
	r["categories"] = map[string]any{
		"XSS":     map[string]any{"base_score": 150},
		"RFI":     map[string]any{"base_score": 180, "confidence": 0.85, "sensitivity": 1},
		"Scanner": map[string]any{"base_score": 70, "confidence": 0.8, "sensitivity": 2, "disabled": true},
	}
	r["path_exceptions"] = []any{
		map[string]any{"path": "/a", "match": "exact", "disable_semantic": true},
		map[string]any{"path": "/b", "match": "exact", "disable_rule_based": true,
			"rule_override": map[string]any{"block_threshold": 200, "log_threshold": 100}},
		map[string]any{"path": "/c", "match": "exact", "disable_semantic": true, "disable_rule_based": true},
		map[string]any{"path": "/t", "match": "exact", "tuning": map[string]any{"effect": map[string]any{
			"skip_crs": []any{"tag:no-such-tag", "942100"}, "skip_semantic": []any{"*"}}}},
		map[string]any{"path": "/w", "match": "exact", "tuning": map[string]any{"effect": map[string]any{
			"weaken": map[string]any{"score_multiplier": 0.5}}}},
	}
	// A sensitivity out of the old range is ignored, not refused.
	body := map[string]any{"rules_json": r, "sensitivity": 9}
	wantStatus(t, "v1 document", c.putProjectBody(t, body), fiber.StatusOK, "")

	stored := c.storedProjectRules(t)
	for _, gone := range []string{"request_body_in_memory_limit", "response_body_limit"} {
		if _, has := stored[gone]; has {
			t.Errorf("%s stored: %v", gone, stored)
		}
	}
	stp, _ := stored["semantic_policies"].(map[string]any)
	if stp["inspection_off"] != true {
		t.Errorf("the project off switch must be stored as inspection_off: %v", stp)
	}
	for _, old := range []string{"disable_semantic", "disable_rule_based", "skip_coraza_when_clean"} {
		if _, has := stp[old]; has {
			t.Errorf("%s stored: %v", old, stp)
		}
	}
	if _, has := stored["thresholds"]; has {
		t.Errorf("thresholds stored: %v", stored)
	}
	if stp["record_weak_detections"] != false {
		t.Errorf("a log score at the block score must be stored as record_weak_detections false: %v", stp)
	}
	if sql, _ := stp["sql"].(map[string]any); sql["disabled"] != true || sql["base_score"] != nil || sql["block_threshold"] != 4.0 {
		t.Errorf("sql base_score 0 must be stored as disabled with its threshold kept: %v", stp["sql"])
	}
	if xss, _ := stp["xss"].(map[string]any); xss["disabled"] == true {
		t.Errorf("the xss category score is not 0, so xss stays on: %v", stp["xss"])
	}
	if _, has := stp["ldap"]; has {
		t.Errorf("ldap held only a base_score and is gone: %v", stp["ldap"])
	}
	sc, _ := stored["categories"].(map[string]any)
	if sc["RFI"] == nil || sc["Scanner"] == nil || sc["XSS"] != nil {
		t.Errorf("the stored categories of v1 stay without their base_score: %v", stored["categories"])
	}
	if raw, _ := json.Marshal(stored["categories"]); strings.Contains(string(raw), "base_score") {
		t.Errorf("a category base_score is stored: %s", raw)
	}
	paths, _ := stored["path_exceptions"].([]any)
	byPath := map[string]map[string]any{}
	for _, p := range paths {
		m, _ := p.(map[string]any)
		byPath[m["path"].(string)] = m
	}
	for _, p := range []string{"/a", "/c"} {
		if byPath[p]["inspection_off"] != true {
			t.Errorf("%s: the old off switch must be stored as inspection_off: %v", p, byPath[p])
		}
	}
	if _, has := byPath["/b"]["inspection_off"]; has {
		t.Errorf("/b: a lone disable_rule_based means nothing: %v", byPath["/b"])
	}
	for p, m := range byPath {
		for _, old := range []string{"disable_semantic", "disable_rule_based"} {
			if _, has := m[old]; has {
				t.Errorf("%s: %s stored: %v", p, old, m)
			}
		}
	}
	if _, has := byPath["/b"]["rule_override"]; has {
		t.Errorf("/b: rule_override is removed: %v", byPath["/b"]["rule_override"])
	}
	if raw, _ := json.Marshal(byPath["/w"]); strings.Contains(string(raw), "weaken") || !strings.Contains(string(raw), `"action":"log"`) {
		t.Errorf("/w: weaken becomes action log: %s", raw)
	}
	if raw, _ := json.Marshal(byPath["/t"]); strings.Contains(string(raw), "skip_crs") || !strings.Contains(string(raw), `"skip_semantic":["*"]`) {
		t.Errorf("/t: skip_crs dropped and skip_semantic * kept: %s", raw)
	}
	cfg := call(t, c.app, http.MethodGet, "/api/projects/"+c.project+"/config", c.tokens["owner"], nil)
	if cfg.body["sensitivity"] != float64(2) {
		t.Errorf("sensitivity answered %v, want the fixed 2", cfg.body["sensitivity"])
	}
	// The same document saves for the application too.
	r2 := c.fresh(t)
	sp2, _ := r2["semantic_policies"].(map[string]any)
	sp2["disable_semantic"] = true
	r2["response_body_limit"] = "1M"
	wantStatus(t, "v1 document (app)", c.putApp(t, r2), fiber.StatusOK, "")
}

// What the current dashboard sends saves: no sensitivity, no per-category extras, no v1-only categories,
// no skip_coraza_when_clean, inspection_off on a path rule.
func TestDBDashboardShapedConfigSaves(t *testing.T) {
	c := newCapsFixture(t)
	r := map[string]any{
		"bot_protection": map[string]any{"enabled": true, "mode": "score", "base_score": 100, "score_threshold": 150},
		"semantic_policies": map[string]any{"scan_all_headers": true, "record_weak_detections": false,
			"sql": map[string]any{"disabled": true}, "jwt": map[string]any{"disabled": true},
			"header_injection": map[string]any{"disabled": true}, "anomaly": map[string]any{"disabled": false}},
		"path_exceptions": []any{
			map[string]any{"path": "/off", "match": "exact", "inspection_off": true},
			map[string]any{"path": "/log", "match": "exact", "tuning": map[string]any{"target": nil,
				"effect": map[string]any{"action": "log"}}},
			map[string]any{"path": "/tune", "match": "exact", "tuning": map[string]any{"target": nil,
				"effect": map[string]any{"skip_semantic": []any{"sql", "xss", "prompt_injection"}}}},
			map[string]any{"path": "/engine", "match": "exact", "semantic_override": map[string]any{
				"cmd": map[string]any{"disabled": true}, "open_redirect": map[string]any{"disabled": true}}},
		},
	}
	wantStatus(t, "project, no sensitivity", c.putProjectBody(t, map[string]any{"rules_json": r}), fiber.StatusOK, "")
	stored := c.storedProjectRules(t)
	stp, _ := stored["semantic_policies"].(map[string]any)
	if _, has := stp["skip_coraza_when_clean"]; has {
		t.Errorf("the control plane no longer writes skip_coraza_when_clean: %v", stp)
	}
	if sql, _ := stp["sql"].(map[string]any); sql["disabled"] != true {
		t.Errorf("the per-engine switch must be stored: %v", stp["sql"])
	}
	if !reflect.DeepEqual(keyPaths(stored), keyPaths(r)) {
		t.Errorf("a dashboard document is stored as sent:\n sent   %v\n stored %v", keyPaths(r), keyPaths(stored))
	}
	appURL := "/api/projects/" + c.project + "/agents/" + c.agentID + "/routes/" + c.appID + "/config"
	cur := call(t, c.app, http.MethodGet, appURL, c.tokens["owner"], nil)
	wantStatus(t, "app, no sensitivity", call(t, c.app, http.MethodPut, appURL, c.tokens["owner"],
		map[string]any{"expected_revision": cur.body["config_revision"], "rules_json": r}), fiber.StatusOK, "")
}

// keyPaths lists every object key path of a decoded JSON document (arrays
// contribute their elements' paths under "[]").
func keyPaths(v any) []string {
	var out []string
	var walk func(prefix string, v any)
	walk = func(prefix string, v any) {
		switch x := v.(type) {
		case map[string]any:
			for k, e := range x {
				out = append(out, prefix+"/"+k)
				walk(prefix+"/"+k, e)
			}
		case []any:
			for _, e := range x {
				walk(prefix+"[]", e)
			}
		}
	}
	walk("", v)
	slices.Sort(out)
	return slices.Compact(out)
}

// A new project stores the default document, and saving it unchanged is a no-op, the challenge template
// version included (TestDefaultChallengeTemplateVersionIsCurrent).
func TestDBNewProjectStoresTheDefaultKeySet(t *testing.T) {
	f := newDBFixture(t)
	created := call(t, f.app, http.MethodPost, "/api/projects", f.tokens["owner"], map[string]any{"name": "default-" + uuid.NewString()[:8]})
	wantStatus(t, "create project", created, fiber.StatusCreated, "")
	id, _ := created.body["id"].(string)
	t.Cleanup(func() { _ = f.repo.Project.DeleteByID(context.Background(), id) })

	var def any
	if err := json.Unmarshal(engine.DefaultRulesJSON(), &def); err != nil {
		t.Fatal(err)
	}
	url := "/api/projects/" + id + "/config"
	got := call(t, f.app, http.MethodGet, url, f.tokens["owner"], nil)
	if !reflect.DeepEqual(got.body["rules_json"], def) {
		t.Fatalf("a new project must store the default document:\n got  %v\n want %v", keyPaths(got.body["rules_json"]), keyPaths(def))
	}
	wantStatus(t, "save the unchanged default", call(t, f.app, http.MethodPut, url, f.tokens["owner"], map[string]any{
		"expected_revision": got.body["config_revision"], "rules_json": got.body["rules_json"],
	}), fiber.StatusOK, "")
	again := call(t, f.app, http.MethodGet, url, f.tokens["owner"], nil)
	if !reflect.DeepEqual(again.body["rules_json"], def) {
		t.Fatalf("saving the unchanged default changed it:\n got  %v\n want %v", keyPaths(again.body["rules_json"]), keyPaths(def))
	}
}

func tuningRuleBody(name string, enabled bool, tuning map[string]any) map[string]any {
	base := map[string]any{
		"scope":  map[string]any{"logic": "and", "conditions": []any{}},
		"target": map[string]any{"components": []string{}, "match": "exact"},
	}
	for k, v := range tuning {
		base[k] = v
	}
	return map[string]any{"name": name, "mode": "tuning", "enabled": enabled, "tuning": base}
}

// Tuning rules as the dashboard saves them (engine omitted, an empty target, no
// skip_crs) and as an older client sends them (engine crs, scan_mode crs_only,
// skip_crs) are all accepted, whatever the agent of the app reports. A crs_only
// scan mode is stored as default.
func TestDBTuningRulesLegacyAndDashboardShapesAccepted(t *testing.T) {
	c := newCapsFixture(t)
	tok := c.tokens["owner"]
	rulesURL := "/api/projects/" + c.project + "/apps/" + c.appID + "/custom-rules"
	for name, effect := range map[string]map[string]any{
		"skip_semantic *":                    {"skip_semantic": []any{"*"}},
		"scan mode both":                     {"scan_mode": "both"},
		"scan mode off":                      {"scan_mode": "disabled"},
		"skip every detector key":            {"skip_semantic": []any{"header_injection", "open_redirect", "prompt_injection", "anomaly"}},
		"scan mode crs_only (older client)":  {"scan_mode": "crs_only"},
		"scan mode semantic_only (older v1)": {"scan_mode": "semantic_only"},
		"skip_crs (older client)":            {"skip_crs": []any{"tag:no-such-tag"}, "skip_semantic": []any{"sql"}},
	} {
		body := tuningRuleBody(name, true, map[string]any{"effect": effect})
		wantStatus(t, name, call(t, c.app, http.MethodPost, rulesURL, tok, body), fiber.StatusCreated, "")
	}
	legacy := tuningRuleBody("engine crs", true, map[string]any{"engine": "crs", "effect": map[string]any{"skip_crs": []any{"*"}}})
	wantStatus(t, "engine crs (older client)", call(t, c.app, http.MethodPost, rulesURL, tok, legacy), fiber.StatusCreated, "")
	bad := tuningRuleBody("bad mode", true, map[string]any{"effect": map[string]any{"scan_mode": "sometimes"}})
	wantStatus(t, "unknown scan_mode", call(t, c.app, http.MethodPost, rulesURL, tok, bad), fiber.StatusBadRequest, "")
	list := call(t, c.app, http.MethodGet, rulesURL, tok, nil)
	raw, _ := json.Marshal(list.body)
	for _, gone := range []string{`"scan_mode":"crs_only"`, `"scan_mode":"semantic_only"`, `"skip_crs"`} {
		if strings.Contains(string(raw), gone) {
			t.Errorf("a stored tuning rule still has %s: %s", gone, raw)
		}
	}
}

func scriptRuleBody(name string, enabled bool) map[string]any {
	return map[string]any{"name": name, "mode": "script", "action": "block", "script": "waf_block()", "enabled": enabled}
}

// A script rule cannot be created or enabled for an app whose agents all report
// script_rules false. Editing or switching off one that is already enabled still
// works, and an agent that never said, or one that can, takes any script rule.
func TestDBScriptRuleRefusedWhenEveryAgentCannotRunIt(t *testing.T) {
	c := newCapsFixture(t)
	tok := c.tokens["owner"]
	rulesURL := "/api/projects/" + c.project + "/apps/" + c.appID + "/custom-rules"
	yes, no := true, false
	create := func(body map[string]any) testResponse { return call(t, c.app, http.MethodPost, rulesURL, tok, body) }
	refused := func(what string, r testResponse) {
		t.Helper()
		wantStatus(t, what, r, fiber.StatusBadRequest, "SCRIPT_RULES_UNSUPPORTED")
		if msg, _ := r.body["error"].(string); !strings.Contains(msg, "cannot run script rules") {
			t.Errorf("%s: message is not a plain explanation: %q", what, msg)
		}
	}

	// Already enabled while the agent could run it.
	c.setScripts(t, &yes)
	running := create(scriptRuleBody("running", true))
	wantStatus(t, "create, agent runs scripts", running, fiber.StatusCreated, "")
	runningID, _ := running.body["id"].(string)
	c.setScripts(t, nil)
	wantStatus(t, "create, agent never said", create(scriptRuleBody("unknown", true)), fiber.StatusCreated, "")

	c.setScripts(t, &no)
	refused("create enabled", create(scriptRuleBody("bad", true)))
	off := create(scriptRuleBody("off", false))
	wantStatus(t, "create disabled", off, fiber.StatusCreated, "")
	offID, _ := off.body["id"].(string)
	refused("enable by patch", call(t, c.app, http.MethodPut, rulesURL+"/"+offID, tok, map[string]any{"enabled": true}))
	refused("enable by full save", call(t, c.app, http.MethodPut, rulesURL+"/"+offID, tok, scriptRuleBody("off", true)))
	// A rule of another kind is not a script rule.
	wantStatus(t, "gui rule", create(map[string]any{
		"name": "gui", "mode": "gui", "action": "block", "condition_logic": "and",
		"conditions": []map[string]any{{"field": "path", "operator": "equals", "value": "/x"}},
	}), fiber.StatusCreated, "")

	// The enabled script rule can still be edited and switched off.
	edited := scriptRuleBody("running edited", true)
	edited["script"] = "waf_block()\n"
	wantStatus(t, "edit an enabled script rule", call(t, c.app, http.MethodPut, rulesURL+"/"+runningID, tok, edited), fiber.StatusOK, "")
	wantStatus(t, "switch it off", call(t, c.app, http.MethodPut, rulesURL+"/"+runningID, tok, map[string]any{"enabled": false}), fiber.StatusOK, "")
	refused("switch it back on", call(t, c.app, http.MethodPut, rulesURL+"/"+runningID, tok, map[string]any{"enabled": true}))

	// An app that no agent serves has nothing to refuse for.
	if err := c.repo.WAF.ReplaceAssignment(context.Background(), c.project, c.appID, "", "block"); err != nil {
		t.Fatal(err)
	}
	wantStatus(t, "app without agent", create(scriptRuleBody("free", true)), fiber.StatusCreated, "")
}
