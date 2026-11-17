package setup

import (
	"os"
	"regexp"
	"slices"
	"testing"
)

// AllComponents must name every component FetchAll checks, so dropping
// malware from "every component" keeps all the others.
func TestAllComponentsMatchFetchAll(t *testing.T) {
	src, err := os.ReadFile("fetcher.go")
	if err != nil {
		t.Fatal(err)
	}
	for _, m := range regexp.MustCompile(`shouldFetch\("([a-z0-9-]+)"\)`).FindAllStringSubmatch(string(src), -1) {
		name := m[1]
		if name == "malware-hashes" {
			name = "malware"
		}
		if !slices.Contains(AllComponents, name) {
			t.Errorf("FetchAll checks %q, missing from AllComponents", m[1])
		}
	}
}

func TestWithoutMalware(t *testing.T) {
	if !IncludesMalware(nil) || !IncludesMalware([]string{"firehol", "Malware"}) || !IncludesMalware([]string{"malware-hashes"}) {
		t.Fatal("malware not detected")
	}
	if IncludesMalware([]string{"geoip-country"}) {
		t.Fatal("geoip-country is not malware")
	}
	all := WithoutMalware(nil)
	if slices.Contains(all, "malware") || len(all) != len(AllComponents)-1 {
		t.Fatalf("every component without malware: %v", all)
	}
	agent := WithoutMalware(ProfileComponents(ProfileAgent))
	if slices.Contains(agent, "malware") || !slices.Contains(agent, "firehol") {
		t.Fatalf("agent profile without malware: %v", agent)
	}
	if got := WithoutMalware([]string{"geoip-country"}); !slices.Equal(got, []string{"geoip-country"}) {
		t.Fatalf("unchanged list: %v", got)
	}
}
