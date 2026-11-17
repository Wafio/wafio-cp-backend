package repository

import (
	"context"
	"github.com/google/uuid"
	"testing"
	"time"
)

func TestTraceOutcomesSurviveColdQueriesExactly(t *testing.T) {
	_, pool, project := incidentTestSetup(t)
	defer pool.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var user string
	if err := pool.QueryRow(ctx, `SELECT user_id FROM projects WHERE id=$1`, project).Scan(&user); err != nil {
		t.Fatal(err)
	}
	agent := uuid.NewString()
	if _, err := pool.Exec(ctx, `INSERT INTO agents(id,user_id,project_id,name,kind) VALUES($1,$2,$3,$4,'host')`, agent, user, project, agent); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM host_security_events WHERE agent_id=$1`, agent)
		_, _ = pool.Exec(context.Background(), `DELETE FROM agents WHERE id=$1`, agent)
	}()
	store := &HostEventStore{pool: pool}
	signalErr := int32(-3)
	store.flushSecurityBatch([]secWriteEntry{{agentID: agent, e: TraceEventRow{PID: 3, EventTime: time.Now(), Category: "process", SeverityName: "critical", ProcessStartNS: "18446744073709551615", SignalOutcome: "failed", SignalError: &signalErr, ActivityOutcome: "attempt"}}})
	checks := []func() ([]TraceEventRow, error){func() ([]TraceEventRow, error) { return store.QuerySecurityEvents(ctx, agent, 10) }, func() ([]TraceEventRow, error) { return store.QuerySecurityEventsByCategory(ctx, agent, "process", 10) }, func() ([]TraceEventRow, error) {
		return store.QuerySecurityEventsSince(ctx, agent, time.Now().Add(-time.Minute), 10, 0)
	}, func() ([]TraceEventRow, error) { return store.QuerySecurityEventsMulti(ctx, []string{agent}, 0, 10) }}
	for _, query := range checks {
		rows, err := query()
		if err != nil {
			t.Fatal(err)
		}
		if len(rows) != 1 {
			t.Fatalf("lost cold row %d", len(rows))
		}
		got := rows[0]
		if got.ProcessStartNS != "18446744073709551615" || got.SignalOutcome != "failed" || got.SignalError == nil || *got.SignalError != -3 || got.ActivityOutcome != "attempt" {
			t.Fatalf("lost exact outcome %+v", got)
		}
	}
	original, err := store.QuerySecurityEvents(ctx, agent, 10)
	if err != nil {
		t.Fatal(err)
	}
	update := original[0]
	update.OutcomeUpdate = true
	update.SignalOutcome = "accepted"
	update.SignalError = nil
	store.flushSecurityBatch([]secWriteEntry{{agentID: agent, e: update}})
	updated, err := store.QuerySecurityEvents(ctx, agent, 10)
	if err != nil || len(updated) != 1 || updated[0].SignalOutcome != "accepted" {
		t.Fatalf("outcome update duplicated/lost original %+v %v", updated, err)
	}
	store.flushSecurityBatch([]secWriteEntry{{agentID: agent, e: TraceEventRow{PID: 4, EventTime: time.Now(), Category: "process"}}})
	rows, err := store.QuerySecurityEvents(ctx, agent, 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if row.PID == 4 && (row.SignalOutcome != "unknown" || row.ActivityOutcome != "unknown" || row.SignalError != nil) {
			t.Fatal("missing outcome became success")
		}
	}
}

func TestStableTraceIdentitySeparatesSameMicrosecondOutcomes(t *testing.T) {
	_, pool, project := incidentTestSetup(t)
	defer pool.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	var user string
	if err := pool.QueryRow(ctx, `SELECT user_id FROM projects WHERE id=$1`, project).Scan(&user); err != nil {
		t.Fatal(err)
	}
	agent := uuid.NewString()
	if _, err := pool.Exec(ctx, `INSERT INTO agents(id,user_id,project_id,name,kind) VALUES($1,$2,$3,$4,'host')`, agent, user, project, agent); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM host_security_events WHERE agent_id=$1`, agent)
		_, _ = pool.Exec(context.Background(), `DELETE FROM agents WHERE id=$1`, agent)
	}()
	at := time.Now().Truncate(time.Microsecond)
	first := TraceEventRow{EventID: "boot:100:42:1", EventTime: at.Add(100 * time.Nanosecond), PID: 42, TID: 42, EventType: 1, ProcessStartNS: "12345678901234567890", Category: "process", SignalOutcome: "requested", ActivityOutcome: "attempt"}
	second := first
	second.EventID = "boot:200:42:1"
	second.EventTime = at.Add(200 * time.Nanosecond)
	store := &HostEventStore{pool: pool}
	store.flushSecurityBatch([]secWriteEntry{{agentID: agent, e: first}, {agentID: agent, e: second}})
	update := second
	update.OutcomeUpdate = true
	update.SignalOutcome = "accepted"
	store.flushSecurityBatch([]secWriteEntry{{agentID: agent, e: update}})
	rows, err := store.QuerySecurityEvents(ctx, agent, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 || !rows[0].EventTime.Equal(rows[1].EventTime) {
		t.Fatalf("fixture must share DB microsecond: %+v", rows)
	}
	outcomes := map[string]string{}
	for _, row := range rows {
		outcomes[row.EventID] = row.SignalOutcome
	}
	if outcomes[first.EventID] != "requested" || outcomes[second.EventID] != "accepted" {
		t.Fatalf("cross-event outcome corruption: %+v", outcomes)
	}
	// A modern update with an unknown ID must never fall back to the lossy timestamp key.
	update.EventID = "boot:unknown:42:1"
	update.SignalOutcome = "failed"
	store.flushSecurityBatch([]secWriteEntry{{agentID: agent, e: update}})
	rows, err = store.QuerySecurityEvents(ctx, agent, 10)
	if err != nil {
		t.Fatal(err)
	}
	for _, row := range rows {
		if outcomes[row.EventID] != row.SignalOutcome {
			t.Fatal("unknown event ID fell back to timestamp")
		}
	}
	cache := newTraceEventCache()
	cache.push(liveTenant{}, agent, []TraceEventRow{first, second})
	update = second
	update.OutcomeUpdate = true
	update.EventTime = at
	update.SignalOutcome = "accepted"
	cache.push(liveTenant{}, agent, []TraceEventRow{update})
	live, ok := cache.recent(agent, 10)
	if !ok || len(live) != 2 {
		t.Fatal("live update created an extra event")
	}
	for _, row := range live {
		if outcomes[row.EventID] != row.SignalOutcome {
			t.Fatalf("live identity mismatch %+v", row)
		}
	}
}
