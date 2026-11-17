package application_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/application"
	"github.com/wafio/wafio-cp-backend/internal/testutil/dbfixture"
)

func retryIngestFixture(t *testing.T) (*retryIngest, string, string, *application.HostTelemetryPayload) {
	t.Helper()
	dsn := os.Getenv("TEST_DB_URL")
	if dsn == "" {
		t.Skip("TEST_DB_URL not set")
	}
	ctx := context.Background()
	repo, err := repository.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(repo.Close)
	// Seed our own project: a freshly migrated database has none.
	project, user := dbfixture.SeedProject(t, repo.DB)
	agent := uuid.NewString()
	if _, err := repo.DB.Exec(ctx, `INSERT INTO agents(id,user_id,project_id,name,kind) VALUES($1,$2,$3,$4,'host')`, agent, user, project, agent); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = repo.DB.Exec(ctx, `DELETE FROM host_incidents WHERE agent_id=$1`, agent)
		_, _ = repo.DB.Exec(ctx, `DELETE FROM ebpf_trace_policies WHERE agent_id=$1`, agent)
		_, _ = repo.DB.Exec(ctx, `DELETE FROM agents WHERE id=$1`, agent)
	})
	id := 1
	if _, err := repo.EBPF.UpsertTracePolicy(ctx, &repository.TracePolicyRow{AgentID: agent, PolicyID: &id, Name: "retry-policy", Action: "alert", MinSeverity: "high", EnforcementMode: "userspace"}); err != nil {
		t.Fatal(err)
	}
	trEvent := application.TraceEventPayload{
		Timestamp:      time.Now().UTC().Format(time.RFC3339Nano),
		EventType:      1,
		EventID:        "boot:123:42:1",
		EventName:      "ptrace",
		Category:       "security",
		Severity:       4,
		SeverityName:   "critical",
		Comm:           agent,
		PID:            42,
		TID:            42,
		ProcessStartNS: "12345678901234567890",
		SignalOutcome:  "requested",
	}
	enf := application.EnforcementPayload{
		PolicyID:   1,
		PolicyName: "retry-policy",
		Action:     "alert",
		Mode:       "userspace",
	}
	return &retryIngest{HostTelemetryIngest: newTestIngest(repo), Repo: repo}, project, agent, &application.HostTelemetryPayload{BatchID: uuid.NewString(), TraceEvents: []application.TraceEventPayload{trEvent}, Enforcement: []application.EnforcementPayload{enf}}
}
func retryCounts(t *testing.T, h *retryIngest, agent string) (incidents, hits int64) {
	t.Helper()
	if err := h.Repo.DB.QueryRow(context.Background(), `SELECT COALESCE(SUM(event_count),0) FROM host_incidents WHERE agent_id=$1`, agent).Scan(&incidents); err != nil {
		t.Fatal(err)
	}
	if err := h.Repo.DB.QueryRow(context.Background(), `SELECT hit_count FROM ebpf_trace_policies WHERE agent_id=$1 AND policy_id=1`, agent).Scan(&hits); err != nil {
		t.Fatal(err)
	}
	return
}
func TestIngestRejectedQueuesDoNotCreateIncidentsOrHits(t *testing.T) {
	h, project, agent, p := retryIngestFixture(t)
	h.SetTraceAdmission(func(context.Context, string, []repository.TraceEventRow) error {
		return repository.ErrTelemetryQueueFull
	})
	h.SetEnforcementAdmission(func(context.Context, string, []repository.EnforcementLogRow) error {
		return repository.ErrTelemetryQueueFull
	})
	for range 3 {
		if err := h.IngestDecoded(context.Background(), project, agent, "", p); !errors.Is(err, repository.ErrTelemetryQueueFull) {
			t.Fatal(err)
		}
	}
	if incidents, hits := retryCounts(t, h, agent); incidents != 0 || hits != 0 {
		t.Fatalf("rejected events generated side effects incidents=%d hits=%d", incidents, hits)
	}
}
func TestIngestMixedRetryAdmitsEachSectionAndSideEffectOnce(t *testing.T) {
	h, project, agent, p := retryIngestFixture(t)
	traceCalls, enforcementCalls := 0, 0
	h.SetTraceAdmission(func(ctx context.Context, id string, rows []repository.TraceEventRow) error {
		traceCalls++
		return h.Repo.EBPF.InsertTraceEvents(ctx, id, rows)
	})
	h.SetEnforcementAdmission(func(context.Context, string, []repository.EnforcementLogRow) error {
		enforcementCalls++
		if enforcementCalls == 1 {
			return repository.ErrTelemetryQueueFull
		}
		return nil
	})
	if err := h.IngestDecoded(context.Background(), project, agent, "", p); !errors.Is(err, repository.ErrTelemetryQueueFull) {
		t.Fatal(err)
	}
	if inc, hits := retryCounts(t, h, agent); inc != 1 || hits != 0 {
		t.Fatalf("first admission counts %d %d", inc, hits)
	}
	for range 2 {
		if err := h.IngestDecoded(context.Background(), project, agent, "", p); err != nil {
			t.Fatal(err)
		}
	}
	if traceCalls != 1 || enforcementCalls != 2 {
		t.Fatalf("duplicate admission trace=%d enforcement=%d", traceCalls, enforcementCalls)
	}
	if inc, hits := retryCounts(t, h, agent); inc != 1 || hits != 1 {
		t.Fatalf("replay duplicated counts %d %d", inc, hits)
	}
	rows, err := h.Repo.EBPF.RecentTraceEvents(context.Background(), agent, 10)
	if err != nil || len(rows) != 1 {
		t.Fatalf("duplicate live trace rows=%d err=%v", len(rows), err)
	}
	update := p.TraceEvents[0]
	update.OutcomeUpdate = true
	update.SignalOutcome = "accepted"
	if err := h.IngestDecoded(context.Background(), project, agent, "", &application.HostTelemetryPayload{BatchID: uuid.NewString(), TraceEvents: []application.TraceEventPayload{update}}); err != nil {
		t.Fatal(err)
	}
	if inc, hits := retryCounts(t, h, agent); inc != 1 || hits != 1 {
		t.Fatalf("outcome update counted as activity %d %d", inc, hits)
	}
	rows, err = h.Repo.EBPF.RecentTraceEvents(context.Background(), agent, 10)
	if err != nil || len(rows) != 1 || rows[0].SignalOutcome != "accepted" {
		t.Fatalf("outcome did not update original trace %+v %v", rows, err)
	}
}

// retryIngest pairs the service with the repository the assertions query.
type retryIngest struct {
	*application.HostTelemetryIngest
	Repo *repository.Repository
}
