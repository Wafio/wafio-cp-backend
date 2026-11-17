package agentserver

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/engine"
	agentv1 "github.com/wafio/wafio-cp-backend/shared/agentpb"
)

// A bundle with every key the removed feature gates used to rewrite (jwt and graphql keys, urlencoded
// sources, rules that read field paths) and the v1 key skip_coraza_when_clean, which is still rewritten.
const gatedKeysBundle = `{
  "agent_id": "a1", "generation": 7, "project_id": "p1",
  "rules_json": {
    "semantic_policies": {"skip_coraza_when_clean": true, "jwt": {"action": "log"}, "sql": {"action": "log"}},
    "path_exceptions": [
      {"path": "/api", "match": "prefix",
       "semantic_override": {"jwt": {"disabled": true}, "sql": {"action": "block"}, "xss": {"action": "log"}},
       "tuning": {"effect": {"skip_semantic": [" JWT ", "xss"]}},
       "field_rules": [{"field": "p", "source": "urlencoded", "action": "encrypt_aes"}]},
      {"path": "/plain", "match": "exact"}
    ]
  },
  "apps": [
    {"app_id": "app-1", "listen_host": "a.example", "upstream": "http://127.0.0.1:1", "mode": "block",
     "rules_json": {"path_exceptions": [{"path": "/graphql", "match": "exact",
        "semantic_override": {"graphql": {"action": "log"}}}]},
     "custom_gui_rules": [{"id": "g", "enabled": true, "conditions": [{"field": "param:user.role", "operator": "exists"}]}],
     "custom_script_rules": [{"id": "s", "enabled": true, "script": "if (waf_field(\"param:x\") == \"1\") then:\n waf_block()\nend"}],
     "custom_tuning_rules": [
       {"id": "t1", "name": "n", "enabled": true, "priority": 1, "engine": "semantic",
        "scope": {"logic": "and", "conditions": [{"field": "json:/items/*/sku", "operator": "exists"}]},
        "target": {"components": ["request"], "match": "exact"},
        "effect": {"skip_semantic": ["graphql", "nosql"]}}
     ]},
    {"app_id": "app-2", "listen_host": "b.example", "upstream": "http://127.0.0.1:2", "mode": "monitor"}
  ]
}`

func compactJSON(t *testing.T, s string) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := json.Compact(&buf, []byte(s)); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// helloFeatureSets are what agents report: the Rust agent with and without the script sidecar, a v1
// agent with its four feature names, a v1 agent older than any feature, and one that reports none.
var helloFeatureSets = map[string][]string{
	"rust agent with scripts":    {engine.FeatureScriptRules},
	"rust agent without scripts": {engine.FeatureNoScriptRules},
	"v1 agent":                   {"semantic_keys_jwt_graphql", "field_rules_v2", "custom_rule_field_paths", "semantic_only"},
	"v1 agent, one feature":      {"semantic_keys_jwt_graphql"},
	"no features":                nil,
}

// Every agent gets the normalized bundle whatever it reports in Hello: an agent that sends no features
// gets the Rust agent's bundle, and the keys the feature gates used to rewrite stay.
func TestBundleIsTheSameForEveryAgent(t *testing.T) {
	in := compactJSON(t, gatedKeysBundle)
	want, legacy := engine.NormalizeBundle(in)
	if len(legacy) != 1 || bytes.Equal(want, in) {
		t.Fatalf("the fixture must carry exactly one v1 rewrite: %v", legacy)
	}
	for name, features := range helloFeatureSets {
		t.Run(name, func(t *testing.T) {
			h := &streamHandle{agentName: "w", features: features}
			out := h.bundleForAgent(in)
			if !bytes.Equal(out, want) {
				t.Fatalf("bundle differs from the normalized one:\n got  %s\n want %s", out, want)
			}
			for _, kept := range []string{`"jwt":{"disabled":true}`, `"graphql":{"action":"log"}`, `"sql":{"action":"log"}`, `"sql":{"action":"block"}`, `"xss":{"action":"log"}`, `"urlencoded"`, `param:user.role`, `json:/items/*/sku`, `waf_field`, `"enabled":true`} {
				if !bytes.Contains(out, []byte(kept)) {
					t.Errorf("the bundle lost %s", kept)
				}
			}
			if bytes.Contains(out, []byte("skip_coraza_when_clean")) {
				t.Error("skip_coraza_when_clean is still in the bundle")
			}
			// A second pass changes nothing and logs nothing new.
			if again := h.bundleForAgent(out); !bytes.Equal(again, out) {
				t.Errorf("not idempotent: %s", again)
			}
		})
	}
	var rust, none []byte
	rust = (&streamHandle{features: helloFeatureSets["rust agent with scripts"]}).bundleForAgent(in)
	none = (&streamHandle{}).bundleForAgent(in)
	if !bytes.Equal(rust, none) {
		t.Fatal("the bundle for an agent that sends no features differs from the Rust agent's")
	}
}

// Over the real stream the initial bundle and a push are byte for byte the same for every set of Hello
// features, and for an agent that reconnects with the generation it holds.
func TestStreamBundleDoesNotFollowHelloFeatures(t *testing.T) {
	env := newE2EEnv(t)
	full := compactJSON(t, gatedKeysBundle)
	want, _ := engine.NormalizeBundle(full)
	env.loader.set(9, string(full))
	client := env.dial(t, &env.pki.clientCert)

	open := func(gen int64, features []string) (agentv1.AgentControl_StreamClient, context.CancelFunc) {
		ctx, cancel := context.WithCancel(context.Background())
		st, err := client.Stream(ctx)
		if err != nil {
			cancel()
			t.Fatal(err)
		}
		if err := st.Send(&agentv1.AgentMessage{Kind: &agentv1.AgentMessage_Hello{Hello: &agentv1.Hello{
			AgentName: e2eAgent, AgentKind: "waf", Hostname: "edge-host", AgentVersion: "test",
			BundleGeneration: gen, Features: features,
		}}}); err != nil {
			cancel()
			t.Fatal(err)
		}
		if recvWithin(t, st, 5*time.Second).GetWelcome() == nil {
			cancel()
			t.Fatal("no welcome")
		}
		return st, cancel
	}
	wantBundle := func(st agentv1.AgentControl_StreamClient, gen int64) {
		t.Helper()
		b := recvWithin(t, st, 5*time.Second).GetBundle()
		if b == nil || b.GetGeneration() != gen {
			t.Fatalf("bundle = %+v, want generation %d", b, gen)
		}
		if !bytes.Equal(b.GetBundleJson(), want) {
			t.Fatalf("the bundle differs from the normalized one: %s", b.GetBundleJson())
		}
	}
	gen := int64(9)
	for name, features := range helloFeatureSets {
		t.Logf("hello: %s", name)
		st, cancel := open(gen, features)
		wantBundle(st, gen)
		gen++
		env.loader.set(gen, string(full))
		go env.s.PushBundleToProject(e2eProject)
		wantBundle(st, gen)
		cancel()
	}
}
