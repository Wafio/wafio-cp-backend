package agentserver

import (
	"os"
	"strings"
	"testing"
)

// The proto comments and docs/agent-protocol.md are the contract the agents and
// the ingest are built from. This guards the points where an earlier wording
// told an agent to do less than the dashboard needs: the cache refusal is sent
// for every app, a purge address may be an absolute URL, the agent reads it the
// way it makes the key (a lower-case escape names the same copy), and every app
// gets a status after a bundle, one with no part on with no features.
func TestEdgeContractText(t *testing.T) {
	flat := func(path, commentMark string) string {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		var words []string
		for _, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimSpace(line)
			if commentMark != "" {
				line = strings.TrimSpace(strings.TrimPrefix(line, commentMark))
			}
			words = append(words, strings.Fields(strings.ReplaceAll(line, "`", ""))...)
		}
		return strings.Join(words, " ")
	}
	proto := flat("../../shared/proto/agent/v1/agent_control.proto", "//")
	doc := flat("../../docs/agent-protocol.md", "")
	for name, text := range map[string]string{"agent_control.proto": proto, "agent-protocol.md": doc} {
		for _, want := range []string{
			"even if the cache is off",
			"cache_dir_unusable",
			"an absolute http:// or https:// URL",
			"byte for byte",
			"escaped again with upper-case hex",
			"an app with no edge part on gets one with no features and no counters",
		} {
			if !strings.Contains(text, want) {
				t.Errorf("%s no longer says %q", name, want)
			}
		}
		for _, stale := range []string{
			"never sends edge settings",
			"whose bundle entry holds edge settings",
			`a path that starts with "/". Empty`,
			"a path that starts with /. Empty",
			"goes to each app in the bundle that has an edge part on",
			"spellings of the same target",
		} {
			if strings.Contains(text, stale) {
				t.Errorf("%s still says %q", name, stale)
			}
		}
	}
}

// The cache does not look at a signed-in request, and a cookie that is not a session cookie is stored
// only for a public, s-maxage or file-type answer; a rule alone does not change that, only signed_in
// does. The agent, the dashboard and the OpenAPI text are built from these sentences, so a wording
// that says the old thing (a rule is enough, signed-in visitors are looked up) fails here.
func TestCacheSignedInContractText(t *testing.T) {
	flat := func(path string) string {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		return strings.Join(strings.Fields(strings.ReplaceAll(string(raw), "`", "")), " ")
	}
	for path, want := range map[string][]string{
		"../../docs/agent-protocol.md": {
			"it is never answered from a stored copy and never makes one, and goes upstream with X-Cache: BYPASS, unless a rule that matches it has signed_in true",
			"a matching rule alone does not allow it, only a rule with signed_in true does",
			"is stored only when the answer is marked public or has s-maxage, or its type is one that default_ttl_s covers",
			"This limits only what is stored, and such a request is still answered from a copy that another request made.",
		},
		"../../api/openapi.yaml": {
			"A signed-in request is never answered from a stored copy and never makes one, unless a path rule that matches it has signed_in. It goes to the application with X-Cache BYPASS.",
			"A matching path rule alone does not allow that, only a rule with signed_in does.",
			"is stored only when the answer is marked public or has s-maxage, or its type is one of the file types that default_ttl_s covers",
			"This limits only what is stored, and such a request is still answered from a copy that another request made.",
			"A request with another cookie is answered from a copy either way.",
		},
	} {
		text := flat(path)
		for _, s := range want {
			if !strings.Contains(text, s) {
				t.Errorf("%s no longer says %q", path, s)
			}
		}
		for _, stale := range []string{
			"unless a rule says so",
			"Also keep answers for visitors who are signed in",
			"or a rule matches",
			"both are stored and answered from a copy",
		} {
			if strings.Contains(text, stale) {
				t.Errorf("%s still says %q", path, stale)
			}
		}
	}
}
