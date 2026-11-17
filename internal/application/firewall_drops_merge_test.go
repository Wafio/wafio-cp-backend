package application

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/domain"
)

func TestMergeFirewallDropsSummaryKeepsEveryReason(t *testing.T) {
	for name, counts := range map[string]map[string]int64{
		"nil":     nil,
		"empty":   {},
		"partial": {"blocklist": 4},
		"unknown": {"blocklist": 4, "future_reason": 3},
	} {
		got := MergeFirewallDropsSummary(counts)
		if len(got) != len(ZeroFirewallDropsSummary()) {
			t.Fatalf("%s: %v, want the 8 documented reasons", name, got)
		}
		for reason := range ZeroFirewallDropsSummary() {
			if _, ok := got[reason]; !ok {
				t.Fatalf("%s: %q missing from %v", name, reason, got)
			}
		}
	}
	got := MergeFirewallDropsSummary(map[string]int64{"blocklist": 4, "other": 1, "future_reason": 3})
	if got["blocklist"] != 4 || got["other"] != 4 || got["egress"] != 0 {
		t.Fatalf("counts: %v", got)
	}
}

// partialDropsStore answers the drop summaries with an empty map, as the
// repository does without a host event store.
type partialDropsStore struct{}

func (partialDropsStore) ListAgentsByProject(context.Context, string) ([]domain.EBPFAgent, error) {
	return nil, nil
}
func (partialDropsStore) FirewallDropsSummaryRange(context.Context, []string, int64, int64) (map[string]int64, error) {
	return map[string]int64{}, nil
}
func (partialDropsStore) FirewallUniqueIPCount(context.Context, []string, int64) (int64, error) {
	return 0, nil
}
func (partialDropsStore) FirewallPeakHours(context.Context, []string, int64) ([24]int64, error) {
	return [24]int64{}, nil
}
func (partialDropsStore) FirewallTopIPsRange(context.Context, []string, int64, int) ([]domain.FirewallTopIPRow, error) {
	return nil, nil
}

type zeroPortPolicies struct{}

func (zeroPortPolicies) PortPolicyCount(context.Context, string) (int, error) { return 0, nil }

// The contract sweep found drops_current = {} for a store that returned an
// empty map: the store's map replaced the zero-filled one.
func TestFirewallAnalyticsDropsAlwaysCarryEveryReason(t *testing.T) {
	s := &FirewallAnalytics{Store: partialDropsStore{}, PortPolicies: zeroPortPolicies{}}
	raw, err := s.Analytics(context.Background(), "p-1", []domain.EBPFAgent{{ID: "a-1"}}, ParseFirewallRange("24h", time.Now().UTC()))
	if err != nil {
		t.Fatal(err)
	}
	var body struct {
		DropsCurrent  map[string]int64 `json:"drops_current"`
		DropsPrevious map[string]int64 `json:"drops_previous"`
	}
	if err := json.Unmarshal(raw, &body); err != nil {
		t.Fatal(err)
	}
	want := len(ZeroFirewallDropsSummary())
	if len(body.DropsCurrent) != want {
		t.Fatalf("drops_current %v, want all %d reasons (%s)", body.DropsCurrent, want, raw)
	}
	if len(body.DropsPrevious) != want {
		t.Fatalf("drops_previous %v, want all %d reasons", body.DropsPrevious, want)
	}
}
