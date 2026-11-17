package repository

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/wafio/wafio-cp-backend/internal/domain"
)

const testIncidentAgent = "test-incident-agent"

// incidentTestSetup returns a pool on TEST_DB_URL and a project of its own
// (owner user with a name, project, both removed at cleanup), so the DB tests
// built on it run on a freshly migrated, empty database instead of skipping
// when no project row happens to exist.
func incidentTestSetup(t *testing.T) (*IncidentRepo, *pgxpool.Pool, string) {
	t.Helper()
	dsn := os.Getenv("TEST_DB_URL")
	if dsn == "" {
		t.Skip("TEST_DB_URL not set")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	var userID, projectID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO users (email, password_hash, name) VALUES ($1, 'fixture-hash', 'repository test') RETURNING id`,
		uuid.NewString()+"@repo-fixture.test").Scan(&userID); err != nil {
		pool.Close()
		t.Fatalf("seed user: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO projects (user_id, name, code) VALUES ($1, 'repository test', $2) RETURNING id`,
		userID, uuid.NewString()).Scan(&projectID); err != nil {
		pool.Close()
		t.Fatalf("seed project: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO project_members (project_id, user_id, role) VALUES ($1, $2, 'owner') ON CONFLICT DO NOTHING`,
		projectID, userID); err != nil {
		pool.Close()
		t.Fatalf("seed member: %v", err)
	}
	// Callers close the returned pool with defer, which runs before
	// t.Cleanup, so the fixture is removed over a pool of its own.
	t.Cleanup(func() {
		cctx := context.Background()
		cp, err := pgxpool.New(cctx, dsn)
		if err != nil {
			t.Logf("fixture cleanup: %v", err)
			return
		}
		defer cp.Close()
		if _, err := cp.Exec(cctx, `DELETE FROM projects WHERE user_id = $1`, userID); err != nil {
			t.Logf("fixture cleanup projects: %v", err)
		}
		if _, err := cp.Exec(cctx, `DELETE FROM users WHERE id = $1`, userID); err != nil {
			t.Logf("fixture cleanup user: %v", err)
		}
	})
	cleanupIncidents(t, pool)
	return &IncidentRepo{pool: pool}, pool, projectID
}

func cleanupIncidents(t *testing.T, pool *pgxpool.Pool) {
	if _, err := pool.Exec(context.Background(),
		`DELETE FROM host_incidents WHERE agent_id=$1`, testIncidentAgent); err != nil {
		t.Logf("cleanup: %v", err)
	}
}

func TestIncidentUpsertDedupAndResolve(t *testing.T) {
	r, pool, projectID := incidentTestSetup(t)
	defer pool.Close()
	defer cleanupIncidents(t, pool)
	ctx := context.Background()

	base := domain.HostIncident{
		ProjectID: projectID, AgentID: testIncidentAgent, TechniqueID: "T1548.001",
		Comm: "evil", Tactic: "Privilege Escalation", Severity: 3, SeverityName: "high",
		SampleDesc: "setuid(0)",
	}
	if err := r.Upsert(ctx, base, 1); err != nil {
		t.Fatalf("upsert insert: %v", err)
	}
	hi := base
	hi.Severity = 4
	hi.SeverityName = "critical"
	if err := r.Upsert(ctx, hi, 2); err != nil {
		t.Fatalf("upsert bump: %v", err)
	}
	list, total, err := r.List(ctx, projectID, "", 50, 0)
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	// filter to our test agent (project may hold other incidents)
	var mine []domain.HostIncident
	for _, i := range list {
		if i.AgentID == testIncidentAgent {
			mine = append(mine, i)
		}
	}
	if len(mine) != 1 {
		t.Fatalf("expected 1 test incident, got %d (total=%d)", len(mine), total)
	}
	if mine[0].EventCount != 3 || mine[0].SeverityName != "critical" {
		t.Fatalf("expected count=3 sev=critical, got count=%d sev=%s", mine[0].EventCount, mine[0].SeverityName)
	}
	if _, err := r.Resolve(ctx, projectID, mine[0].ID, "user1"); err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if err := r.Upsert(ctx, base, 1); err != nil {
		t.Fatalf("upsert after resolve: %v", err)
	}
	list, _, _ = r.List(ctx, projectID, "", 50, 0)
	cnt := 0
	for _, i := range list {
		if i.AgentID == testIncidentAgent {
			cnt++
		}
	}
	if cnt != 2 {
		t.Fatalf("expected 2 incidents after resolve+new, got %d", cnt)
	}
}

func TestIncidentResolveStaleSkipsAcknowledged(t *testing.T) {
	r, pool, projectID := incidentTestSetup(t)
	defer pool.Close()
	defer cleanupIncidents(t, pool)
	ctx := context.Background()
	if _, err := pool.Exec(ctx, `INSERT INTO host_incidents
		(project_id, agent_id, technique_id, comm, severity, severity_name, status, last_seen_at)
		VALUES ($1,$2,'T1','c1',4,'critical','open', now()-interval '48 hours'),
		       ($1,$2,'T1','c2',4,'critical','acknowledged', now()-interval '48 hours')`,
		projectID, testIncidentAgent); err != nil {
		t.Fatalf("seed: %v", err)
	}
	n, err := r.ResolveStale(ctx, projectID, 24*time.Hour)
	if err != nil {
		t.Fatalf("resolvestale: %v", err)
	}
	if n != 1 {
		t.Fatalf("expected 1 stale open resolved, got %d", n)
	}
}
