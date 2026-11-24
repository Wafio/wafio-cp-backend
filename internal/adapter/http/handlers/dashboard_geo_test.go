package handlers

import (
	"encoding/json"
	"fmt"
	"github.com/wafio/wafio-cp-backend/internal/apicontract"
	"net/http/httptest"
	"net/url"
	"os"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
)

type countingGeoEnricher struct{ calls int }

func (e *countingGeoEnricher) Enrich(string) (string, string, float64, float64, string) {
	e.calls++
	return "city", "US", 1, 2, "isp"
}

func TestAppGeoLocationsCapsBeforeEnrichment(t *testing.T) {
	dsn := os.Getenv("TEST_DB_URL")
	if dsn == "" {
		t.Skip("TEST_DB_URL not set")
	}
	ctx := t.Context()
	admin, err := repository.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "geo_" + uuid.NewString()[:8]
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.DB.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		t.Fatal(err)
	}
	defer admin.DB.Exec(ctx, "DROP SCHEMA "+quoted+" CASCADE") //nolint:errcheck
	config, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	query := config.Query()
	query.Set("search_path", schema)
	config.RawQuery = query.Encode()
	repo, err := repository.New(ctx, config.String())
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	if _, err := repo.DB.Exec(ctx, `
		CREATE TABLE projects(id uuid PRIMARY KEY, user_id uuid, name text, code text, description text, created_at timestamptz, updated_at timestamptz);
		CREATE TABLE agents(id uuid PRIMARY KEY, project_id uuid,deleted_at timestamptz);
		CREATE TABLE waf_decisions(agent_id uuid, app_id uuid, remote_addr text, action text, event_time timestamptz, recorded_at timestamptz);
		CREATE TABLE waf_rollup_state(covered_from timestamptz, minute_mark timestamptz, hour_mark timestamptz, kept_from timestamptz);
		CREATE TABLE waf_rollup_hour(agent_id uuid, app_key uuid, dim smallint, bucket timestamptz, key uuid, value text, total bigint, blocks bigint, logs bigint);
	`); err != nil {
		t.Fatal(err)
	}
	projectID, appID, agentID := uuid.NewString(), uuid.NewString(), uuid.NewString()
	if _, err := repo.DB.Exec(ctx, `INSERT INTO projects VALUES($1,$2,'test','test','',now(),now())`, projectID, uuid.NewString()); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.DB.Exec(ctx, `INSERT INTO agents VALUES($1,$2)`, agentID, projectID); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.DB.Exec(ctx, `INSERT INTO waf_decisions SELECT $1,$2,'198.51.' || (n/256)::text || '.' || (n%256)::text,'allow',now()-interval '1 minute',now()-interval '1 minute' FROM generate_series(0,1199) n`, agentID, appID); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.DB.Exec(ctx, `INSERT INTO waf_decisions VALUES($1,$2,'198.51.0.0','block',now()-interval '1 minute',now()-interval '1 minute')`, agentID, appID); err != nil {
		t.Fatal(err)
	}
	enricher := &countingGeoEnricher{}
	handler := &DashboardHandler{Repo: repo, GeoEnricher: enricher}
	app := fiber.New()
	app.Get("/projects/:id/apps/:appId/geo", handler.AppGeoLocations)
	for _, tc := range []struct {
		query string
		want  int
	}{
		{"", 500},
		{"?limit=1", 1},
		{"?limit=2000", 1000},
	} {
		t.Run(fmt.Sprintf("limit_%d", tc.want), func(t *testing.T) {
			enricher.calls = 0
			resp, err := apicontract.TestOperation(t, app, "GET /api/projects/{id}/apps/{appId}/waf-events/geo", httptest.NewRequest("GET", "/projects/"+projectID+"/apps/"+appID+"/geo"+tc.query, nil))
			if err != nil {
				t.Fatal(err)
			}
			defer resp.Body.Close()
			if resp.StatusCode != 200 {
				t.Fatalf("status=%d", resp.StatusCode)
			}
			var body struct {
				Locations []struct {
					RemoteAddr string `json:"remote_addr"`
					Count      int    `json:"count"`
					Allow      int    `json:"allow"`
					Block      int    `json:"block"`
				} `json:"locations"`
				TotalRequests  int `json:"total_requests"`
				TotalLocations int `json:"total_locations"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
				t.Fatal(err)
			}
			if len(body.Locations) != tc.want || body.TotalLocations != tc.want || body.TotalRequests != tc.want+1 {
				t.Fatalf("locations=%d total_locations=%d total_requests=%d", len(body.Locations), body.TotalLocations, body.TotalRequests)
			}
			if enricher.calls != tc.want {
				t.Fatalf("enrichment calls=%d want=%d", enricher.calls, tc.want)
			}
			if body.Locations[0].RemoteAddr != "198.51.0.0" || body.Locations[0].Count != 2 || body.Locations[0].Block != 1 || body.Locations[0].Allow != 1 {
				t.Fatalf("top location=%+v", body.Locations[0])
			}
		})
	}
}
