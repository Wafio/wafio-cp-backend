package dashboard

import (
	"testing"
	"time"
)

func TestHeartbeatFreshnessUsesExplicitSnapshotAndNeverInfersHealthy(t *testing.T) {
	now := time.Date(2026, 9, 11, 0, 0, 0, 0, time.UTC)
	for _, tc := range []struct {
		age   time.Duration
		state string
	}{{0, "fresh"}, {90 * time.Second, "fresh"}, {91 * time.Second, "stale"}, {-time.Second, "clock_skew"}} {
		at := now.Add(-tc.age)
		if got := HeartbeatFreshness(&at, now); got != tc.state {
			t.Fatalf("age=%v got=%s", tc.age, got)
		}
	}
	if HeartbeatFreshness(nil, now) != "unobserved" {
		t.Fatal("missing heartbeat inferred healthy")
	}
}
