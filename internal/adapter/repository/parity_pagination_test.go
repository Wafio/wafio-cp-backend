package repository

import (
	"context"
	"fmt"
	"github.com/google/uuid"
	"github.com/wafio/wafio-cp-backend/internal/domain"
	"sync"
	"testing"
)

func TestProjectPaginationPreservesRoleAndLastPage(t *testing.T) {
	_, pool, _ := incidentTestSetup(t)
	defer pool.Close()
	ctx := context.Background()
	users := &UserRepo{pool: pool}
	user, err := users.Create(ctx, uuid.NewString()+"@pagination.test", "fixture-hash", "pagination")
	if err != nil {
		t.Fatal(err)
	}
	defer users.Delete(ctx, user.ID) //nolint:errcheck
	projects := &ProjectRepo{pool: pool}
	for i := 0; i < 21; i++ {
		if _, err := projects.Create(ctx, user.ID, fmt.Sprintf("Project %d", i), uuid.NewString(), ""); err != nil {
			t.Fatal(err)
		}
	}
	first, total, err := projects.ListForUser(ctx, user.ID, false, 20, 0)
	if err != nil || total != 21 || len(first) != 20 {
		t.Fatalf("first page len=%d total=%d err=%v", len(first), total, err)
	}
	last, total, err := projects.ListForUser(ctx, user.ID, false, 20, 20)
	if err != nil || total != 21 || len(last) != 1 || last[0].EffectiveRole != "owner" {
		t.Fatalf("last page %+v total=%d err=%v", last, total, err)
	}
}

func TestAdminUserPaginationReachesUser101(t *testing.T) {
	_, pool, _ := incidentTestSetup(t)
	defer pool.Close()
	ctx := context.Background()
	repo := &UserRepo{pool: pool}
	_, before, err := repo.List(ctx, 1, 0)
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	defer func() {
		for _, id := range ids {
			_ = repo.Delete(ctx, id)
		}
	}()
	for i := 0; i < 101; i++ {
		user, err := repo.Create(ctx, uuid.NewString()+"@users-page.test", "fixture-hash", "pagination")
		if err != nil {
			t.Fatal(err)
		}
		ids = append(ids, user.ID)
	}
	first, total, err := repo.List(ctx, 100, before)
	if err != nil || total != before+101 || len(first) != 100 {
		t.Fatalf("first page len=%d total=%d err=%v", len(first), total, err)
	}
	last, _, err := repo.List(ctx, 100, before+100)
	if err != nil || len(last) != 1 || last[0].ID != ids[100] {
		t.Fatalf("last user %+v err=%v", last, err)
	}
}

func TestUnresolvedIncidentPaginationKeepsAcknowledged(t *testing.T) {
	_, pool, seed := incidentTestSetup(t)
	defer pool.Close()
	ctx := context.Background()
	var user string
	if err := pool.QueryRow(ctx, `SELECT user_id FROM projects WHERE id=$1`, seed).Scan(&user); err != nil {
		t.Fatal(err)
	}
	projects := &ProjectRepo{pool: pool}
	project, err := projects.Create(ctx, user, "incident pages", uuid.NewString(), "")
	if err != nil {
		t.Fatal(err)
	}
	defer projects.DeleteByID(ctx, project.ID) //nolint:errcheck
	for i := 0; i < 51; i++ {
		if _, err := pool.Exec(ctx, `INSERT INTO host_incidents(project_id,agent_id,technique_id,comm,severity,severity_name,status,last_seen_at) VALUES($1,'pagination-agent',$2,$2,3,'high','open',now()-interval '48 hours')`, project.ID, fmt.Sprintf("technique-%d", i)); err != nil {
			t.Fatal(err)
		}
	}
	repo := &IncidentRepo{pool: pool}
	first, total, err := repo.List(ctx, project.ID, "unresolved", 50, 0)
	if err != nil || len(first) != 50 || total != 51 {
		t.Fatalf("first page len=%d total=%d err=%v", len(first), total, err)
	}
	if changed, err := repo.Acknowledge(ctx, project.ID, first[0].ID, user); err != nil || !changed {
		t.Fatal("acknowledge failed")
	}
	last, total, err := repo.List(ctx, project.ID, "unresolved", 50, 50)
	if err != nil || len(last) != 1 || total != 51 {
		t.Fatalf("ack removed unresolved incident len=%d total=%d err=%v", len(last), total, err)
	}
}

func TestIncidentConcurrentFirstSightingsAreNotLost(t *testing.T) {
	_, pool, project := incidentTestSetup(t)
	defer pool.Close()
	ctx := context.Background()
	agent := uuid.NewString()
	comm := uuid.NewString()
	r := &IncidentRepo{pool: pool}
	defer func() {
		_, _ = pool.Exec(ctx, `DELETE FROM host_incidents WHERE project_id=$1 AND agent_id=$2`, project, agent)
	}()
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := r.Upsert(ctx, domain.HostIncident{ProjectID: project, AgentID: agent, TechniqueID: "T1000", Comm: comm, Severity: 3, SeverityName: "high"}, 1); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	var count int
	if err := pool.QueryRow(ctx, `SELECT event_count FROM host_incidents WHERE project_id=$1 AND agent_id=$2`, project, agent).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 20 {
		t.Fatalf("lost concurrent first sightings: %d", count)
	}
}
