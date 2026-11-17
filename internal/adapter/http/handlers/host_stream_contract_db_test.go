package handlers

import (
	"context"
	"encoding/json"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/apicontract"
	"github.com/wafio/wafio-cp-backend/internal/testutil/dbfixture"
)

// GET /host/stream frames built by the real channel readers from stored
// telemetry are validated against the operation's x-sse-events schemas
// (readStream goes through apicontract.FiberTest). The stream ends at the
// shortened lifetime cap.
func TestDBHostStreamFramesMatchContract(t *testing.T) {
	repo := deleteStreamsRepo(t)
	// As serve.go wires it: firewall events and the enforcement feed live in
	// the host event store.
	store := repository.NewHostEventStore(repo.DB)
	repo.EBPF.SetHostEventStore(store)
	t.Cleanup(store.Close)
	ctx := context.Background()
	projectID, userID := dbfixture.SeedProject(t, repo.DB)
	// Projects created through the API always have a description; the
	// fixture leaves it NULL, which ProjectRepo.GetByID cannot scan.
	if _, err := repo.DB.Exec(ctx, `UPDATE projects SET description = '' WHERE id = $1`, projectID); err != nil {
		t.Fatal(err)
	}
	agentID := uuid.NewString()
	if _, err := repo.DB.Exec(ctx, `INSERT INTO agents (id, user_id, project_id, name, kind, host_info, last_seen)
		VALUES ($1, $2, $3, $4, 'host', $5, now())`, agentID, userID, projectID, "stream-"+agentID[:8],
		`{"hostname":"edge-1","kernel":"6.8.0","os":"linux","arch":"amd64","ssh_ports":[22]}`); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := repo.EBPF.InsertStatus(ctx, projectID, agentID, json.RawMessage(`{"xdp_attached":true,"mode":"enforce"}`)); err != nil {
		t.Fatal(err)
	}
	if err := repo.EBPF.InsertMetrics(ctx, projectID, agentID, &repository.EBPFMetricsRow{RxPackets: 100, RxBytes: 6000, DroppedPackets: 3, PPS: 10, BPS: 600, RecordedAt: now}); err != nil {
		t.Fatal(err)
	}
	if err := repo.EBPF.InsertTraceStats(ctx, projectID, agentID, json.RawMessage(`{"total_events":2,"event_counts":{"execve":1,"openat":1}}`)); err != nil {
		t.Fatal(err)
	}
	if err := repo.EBPF.InsertTraceEvents(ctx, agentID, []repository.TraceEventRow{
		{EventID: "stream-1", PID: 4242, PPID: 1, EventType: 1, EventName: "execve", Category: "process", Severity: 3, SeverityName: "high", ActionName: "alert", Comm: "nc", Filename: "/usr/bin/nc", EventTime: now},
	}); err != nil {
		t.Fatal(err)
	}
	if err := repo.EBPF.InsertEvents(ctx, agentID, []repository.EBPFEventRow{
		{SrcIP: "198.51.100.20", DstIP: "10.0.0.5", SrcPort: 51515, DstPort: 22, Proto: "tcp", Action: "drop", Reason: "blocklist", PktLen: 60, EventTime: now},
	}); err != nil {
		t.Fatal(err)
	}
	if err := repo.EBPF.InsertEnforcementLog(ctx, agentID, []repository.EnforcementLogRow{
		{PolicyName: "watch-nc", Action: "alert", Success: true, Mode: "alert", EventData: json.RawMessage(`{"comm":"nc"}`), EventTime: now, Severity: "high", Tags: json.RawMessage(`["contract"]`)},
	}); err != nil {
		t.Fatal(err)
	}

	// The store writes asynchronously; stream once the rows are readable, or
	// the initial burst can miss them (seen under -race).
	since := now.Add(-time.Hour)
	deadline := time.Now().Add(10 * time.Second)
	for {
		evts, _ := repo.EBPF.RecentEventsSince(ctx, agentID, since, 1)
		enf, _ := repo.EBPF.RecentEnforcementLogSince(ctx, agentID, since, 1)
		if len(evts) > 0 && len(enf) > 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("seeded events (%d) and enforcement entries (%d) never became readable", len(evts), len(enf))
		}
		time.Sleep(20 * time.Millisecond)
	}

	shortStreamTimers(t, 1500*time.Millisecond)
	h := &HostStreamHandler{Repo: repo, Guard: newFakeGuard(true)}
	app := streamApp("/api/projects/:id/host/stream", h.Stream)
	status, body := readStream(t, app, "/api/projects/"+projectID+"/host/stream?agent_id="+agentID)
	if status != 200 {
		t.Fatalf("status %d: %s", status, body)
	}
	seen := map[string]int{}
	for _, f := range apicontract.ParseSSE([]byte(body)) {
		seen[f.Event]++
	}
	names := make([]string, 0, len(seen))
	for k := range seen {
		names = append(names, k)
	}
	sort.Strings(names)
	t.Logf("host stream events validated: %s", strings.Join(names, ", "))
	for _, want := range []string{"status", "metrics", "hostinfo", "stats", "trace", "events", "enforcement"} {
		if seen[want] == 0 {
			t.Errorf("no %s frame in %q", want, body)
		}
	}
}
