package handlers

import (
	"context"
	"github.com/wafio/wafio-cp-backend/internal/apicontract"
	"io"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/domain"
	"github.com/wafio/wafio-cp-backend/internal/testutil/dbfixture"
)

const ingestRedactBody = `{"decisions":[{"action":"block","method":"GET",` +
	`"uri":"/s;jsessionid=JS1?access_token=SECRET123&q=%3Cscript%3E;sig=S2","event_time":"2026-10-17T00:00:00Z"}]}`

const ingestRedactWant = "/s;jsessionid=" + domain.DecisionRedactedMarker + "?access_token=" + domain.DecisionRedactedMarker +
	"&q=%3Cscript%3E;sig=" + domain.DecisionRedactedMarker

// The legacy HTTP ingest applies the
// control-plane redaction before the rows are stored.
func TestWAFIngestRowsRedactURI(t *testing.T) {
	rows := wafIngestRows("p1", "a1", []wafIngestDecision{{URI: "/s;jsessionid=JS1?access_token=SECRET123&q=%3Cscript%3E;sig=S2"}, {URI: "/plain?id=1"}})
	if len(rows) != 2 || rows[0].URI != ingestRedactWant || rows[1].URI != "/plain?id=1" {
		t.Fatalf("rows = %+v", rows)
	}
	if rows[0].ProjectID != "p1" || rows[0].AgentID != "a1" {
		t.Fatalf("tenant fields = %q %q", rows[0].ProjectID, rows[0].AgentID)
	}
	// The body preview has its secret-named fields
	// redacted too (no match source here: nothing is exempt).
	body := wafIngestRows("p1", "a1", []wafIngestDecision{
		{ContentType: "form", BodyPreview: "user=a&password=' OR 1=1--"},
		{ContentType: "json", BodyPreview: `{"user":"a","api_key":"K"}`},
	})
	if body[0].BodyPreview != "user=a&password="+domain.DecisionRedactedMarker ||
		body[1].BodyPreview != `{"user":"a","api_key":"`+domain.DecisionRedactedMarker+`"}` {
		t.Fatalf("body previews = %q, %q", body[0].BodyPreview, body[1].BodyPreview)
	}
}

// End to end through Fiber and the database: what POST
// /api/internal/waf/ingest stores carries no credential.
func TestWAFIngestStoresRedactedURI(t *testing.T) {
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
	project, user := dbfixture.SeedProject(t, repo.DB)
	_, rawKey, err := repo.Host.Create(ctx, user, project, "ingest-redact-host", nil)
	if err != nil {
		t.Fatal(err)
	}
	app := fiber.New()
	ingest := &HostIngestHandler{Repo: repo}
	app.Post("/api/internal/waf/ingest", ingest.RequireAgentKey(), (&WAFAgentHandler{Repo: repo}).Ingest)

	req := httptest.NewRequest("POST", "/api/internal/waf/ingest", strings.NewReader(ingestRedactBody))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Wafio-Host-Key", rawKey)
	req.Header.Set("X-Wafio-Agent-Name", "ingest-redact-waf")
	resp, err := apicontract.FiberTest(t, app, req, -1)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, resp.Body)
	_ = resp.Body.Close()
	if resp.StatusCode != fiber.StatusAccepted {
		t.Fatalf("status %d, want 202", resp.StatusCode)
	}
	var uri string
	if err := repo.DB.QueryRow(ctx, `SELECT d.uri FROM waf_decisions d
		JOIN agents a ON a.id = d.agent_id AND a.deleted_at IS NULL
		WHERE a.project_id = $1 ORDER BY d.recorded_at DESC LIMIT 1`, project).Scan(&uri); err != nil {
		t.Fatal(err)
	}
	if uri != ingestRedactWant {
		t.Fatalf("stored uri = %q, want %q", uri, ingestRedactWant)
	}
}
