package repository

import "testing"

// secShouldPersist is the sampling decision for the PG write path. High-severity
// events are the historical record of real incidents — they must NEVER be
// sampled away. Position-based 1-in-5 previously discarded 80% of criticals.
func TestSecShouldPersist(t *testing.T) {
	// Critical and high: always persisted, any counter position.
	for _, sev := range []string{"critical", "high"} {
		for n := uint64(1); n <= 6; n++ {
			if !secShouldPersist(sev, n) {
				t.Errorf("%s at n=%d must always persist", sev, n)
			}
		}
	}
	// Low severities: sampled 1-in-5 (persisted exactly at n%5==0).
	got := 0
	for n := uint64(1); n <= 20; n++ {
		if secShouldPersist("info", n) {
			got++
		}
	}
	if got != 4 {
		t.Errorf("info over 20 events: want 4 sampled writes, got %d", got)
	}
	// Unknown severity name must not silently bypass sampling.
	for n := uint64(1); n <= 4; n++ {
		if secShouldPersist("unknown", n) {
			t.Errorf("unknown severity should sample like low, persisted at n=%d", n)
		}
	}
	if !secShouldPersist("unknown", 5) {
		t.Errorf("unknown severity should hit the 1-in-5 slot")
	}
}

// Agent loss and shed reports are never sampled away, whatever
// their severity; other low events still are.
func TestInsertSecurityEventsKeepsAgentReports(t *testing.T) {
	s := &HostEventStore{secCh: make(chan secWriteEntry, 64), stop: make(chan struct{})}
	events := []TraceEventRow{
		{EventName: "openat", SeverityName: "low"},
		{EventName: "trace_events_lost", SeverityName: "low"},
		{EventName: "openat", SeverityName: "low"},
		{EventName: "trace_events_shed", SeverityName: "medium"},
		{EventName: "openat", SeverityName: "low"},
	}
	if err := s.InsertSecurityEvents("agent-1", events); err != nil {
		t.Fatal(err)
	}
	close(s.secCh)
	var names []string
	for entry := range s.secCh {
		names = append(names, entry.e.EventName)
	}
	if len(names) != 2 || names[0] != "trace_events_lost" || names[1] != "trace_events_shed" {
		t.Fatalf("persisted %v, want both agent reports and no sampled openat", names)
	}
}

// A repeat summary is the only stored trace of the rows the ingest cap left
// out, so low severities do not sample it away either.
func TestInsertSecurityEventsKeepsRepeatSummaries(t *testing.T) {
	s := &HostEventStore{secCh: make(chan secWriteEntry, 64), stop: make(chan struct{})}
	events := []TraceEventRow{
		{EventName: "openat", SeverityName: "medium", Description: "plain"},
		{EventName: "openat", SeverityName: "medium", Description: "[repeated 40 more times in 60 s, not stored] plain"},
		{EventName: "openat", SeverityName: "medium", Description: "plain"},
		{EventName: "openat", SeverityName: "medium", Description: "plain"},
	}
	if err := s.InsertSecurityEvents("agent-1", events); err != nil {
		t.Fatal(err)
	}
	close(s.secCh)
	var kept []string
	for entry := range s.secCh {
		kept = append(kept, entry.e.Description)
	}
	if len(kept) != 1 || kept[0] != events[1].Description {
		t.Fatalf("persisted %v, want only the summary", kept)
	}
}
