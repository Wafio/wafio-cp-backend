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
