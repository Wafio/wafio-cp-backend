package httpadapter

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
)

// Deleting an agent is a soft delete. The request returns without
// touching the agent's telemetry, the agent disappears from every read, its
// decisions leave the project feed, new decisions for it are not written,
// and its name can be registered again.
func TestDBAgentDeleteIsSoftAndHidesTheAgent(t *testing.T) {
	f := newDBFixture(t)
	ctx := context.Background()
	name := "test-" + uuid.NewString()[:8]
	agentID := f.registerAgent(t, "memberA", name, "waf")

	marker := "/test-" + uuid.NewString()[:8]
	if err := f.repo.WAF.InsertDecisions(ctx, []repository.WAFDecision{{
		ProjectID: f.project, AgentID: agentID, Action: "block", URI: marker, EventTime: time.Now().UTC(),
	}}); err != nil {
		t.Fatal(err)
	}
	feed := func() string {
		r := call(t, f.app, http.MethodGet, "/api/projects/"+f.project+"/waf-events/recent?limit=500", f.tokens["viewer"], nil)
		if r.status != fiber.StatusOK {
			t.Fatalf("feed: %d %s", r.status, r.raw)
		}
		return string(r.raw)
	}
	if !strings.Contains(feed(), marker) {
		t.Fatal("decision not in the feed before delete")
	}

	start := time.Now()
	r := call(t, f.app, http.MethodDelete, "/api/fleet/agents/"+agentID, f.tokens["memberA"], nil)
	if r.status != fiber.StatusOK {
		t.Fatalf("delete: %d %s", r.status, r.raw)
	}
	if d := time.Since(start); d > 2*time.Second {
		t.Fatalf("delete took %v", d)
	}

	// Hidden from single read, the fleet list and the project feed.
	if r := call(t, f.app, http.MethodGet, "/api/fleet/agents/"+agentID, f.tokens["owner"], nil); r.status != fiber.StatusNotFound {
		t.Fatalf("read after delete: %d, want 404", r.status)
	}
	if r := call(t, f.app, http.MethodGet, "/api/fleet/agents", f.tokens["owner"], nil); agentIDs(r)[agentID] {
		t.Fatal("deleted agent still listed")
	}
	if strings.Contains(feed(), marker) {
		t.Fatal("deleted agent's decision still in the project feed")
	}
	// A second delete finds nothing.
	if r := call(t, f.app, http.MethodDelete, "/api/fleet/agents/"+agentID, f.tokens["memberA"], nil); r.status != fiber.StatusNotFound {
		t.Fatalf("second delete: %d, want 404", r.status)
	}

	// The row and its telemetry are kept for retention, not deleted.
	var deletedAt *time.Time
	if err := f.repo.DB.QueryRow(ctx, `SELECT deleted_at FROM agents WHERE id=$1`, agentID).Scan(&deletedAt); err != nil || deletedAt == nil {
		t.Fatalf("agent row: deleted_at=%v err=%v; want a soft-deleted row", deletedAt, err)
	}
	var kept int
	if err := f.repo.DB.QueryRow(ctx, `SELECT count(*) FROM waf_decisions WHERE agent_id=$1`, agentID).Scan(&kept); err != nil || kept != 1 {
		t.Fatalf("decisions kept=%d err=%v; telemetry is left to retention", kept, err)
	}

	// New decisions for the deleted agent are not written.
	if err := f.repo.WAF.InsertDecisions(ctx, []repository.WAFDecision{{
		ProjectID: f.project, AgentID: agentID, Action: "allow", URI: marker + "-late", EventTime: time.Now().UTC(),
	}}); err != nil {
		t.Fatal(err)
	}
	if err := f.repo.DB.QueryRow(ctx, `SELECT count(*) FROM waf_decisions WHERE agent_id=$1`, agentID).Scan(&kept); err != nil || kept != 1 {
		t.Fatalf("decision for a deleted agent was written (count %d, err %v)", kept, err)
	}

	// The name is free again.
	again := f.registerAgent(t, "memberA", name, "waf")
	if again == agentID {
		t.Fatal("re-registration returned the deleted agent")
	}
}

// An empty audit page is [] in JSON, not null.
func TestDBEmptyAuditPageIsArray(t *testing.T) {
	f := newDBFixture(t)
	r := call(t, f.app, http.MethodGet, "/api/projects/"+f.project+"/audit-log?limit=20&offset=100000", f.tokens["owner"], nil)
	if r.status != fiber.StatusOK {
		t.Fatalf("audit: %d %s", r.status, r.raw)
	}
	if !strings.Contains(string(r.raw), `"events":[]`) {
		t.Fatalf("empty audit page: %s, want \"events\":[]", r.raw)
	}
}
