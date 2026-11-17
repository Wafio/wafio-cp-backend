package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/wafio/wafio-cp-backend/internal/apicontract"
	"io"
	"net/http/httptest"
	"os"
	"strconv"
	"strings"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/testutil/dbfixture"
)

// The Overview cache kept every key it was asked for, and the key is
// built from query parameters, so cycling bucket_seconds or host_id grew it
// without bound. It now holds at most overviewCacheMax entries and a project
// at most overviewCachePerProject; a flooding project evicts its own entries
// first and cannot push out another project's below the global cap.
func TestOverviewCacheBounded(t *testing.T) {
	c := &OverviewCache{maxEntries: 64, perProject: 8}
	body := json.RawMessage(`{}`)
	victim := overviewCacheKey{projectID: "victim", minutes: 60, bucketSecs: 150, limit: 8}
	c.Set(victim, body)
	for i := range 20_000 {
		c.Set(overviewCacheKey{projectID: "flood", minutes: 60, bucketSecs: 60 + i, limit: 8}, body)
	}
	if n := c.Len(); n != 9 {
		t.Fatalf("cache holds %d entries, want 9 (8 of the flooding project + the victim's)", n)
	}
	if _, hit, _ := c.Get(victim); !hit {
		t.Fatal("the victim's entry was evicted by another project's keys")
	}
	// Many projects: the global cap holds.
	for i := range 1000 {
		c.Set(overviewCacheKey{projectID: "p" + strconv.Itoa(i), minutes: 60, bucketSecs: 150, limit: 8}, body)
	}
	if n := c.Len(); n != 64 {
		t.Fatalf("cache holds %d entries, want the global cap 64", n)
	}
	if c.projects["flood"] > 8 {
		t.Fatalf("project bookkeeping drifted: %v", c.projects["flood"])
	}
}

func TestOverviewParamBounds(t *testing.T) {
	for _, tc := range []struct{ b, minutes, want int }{
		{300, 60, 300},
		{1, 60, 60},         // at least 60 s
		{1 << 30, 60, 3600}, // at most one bucket for the window
		{60, 43200, 1800},   // at most 1,440 buckets over 30 days
		{uiBucketSecs(1440), 1440, uiBucketSecs(1440)}, // what the UI sends stays as is
	} {
		if got := clampBucketSecs(tc.b, tc.minutes); got != tc.want {
			t.Errorf("clampBucketSecs(%d, %d) = %d, want %d", tc.b, tc.minutes, got, tc.want)
		}
	}
	id := uuid.NewString()
	for s, want := range map[string]bool{"": true, id: true, "x": false, "  " + id: false, "{" + id + "}": false} {
		if got := isCanonicalUUID(s); got != want {
			t.Errorf("isCanonicalUUID(%q) = %v, want %v", s, got, want)
		}
	}
}

// The Overview refuses a host or WAF agent of another project (404) and a
// malformed id (400) before computing or caching anything.
func TestOverviewScopeMustBelongToProject(t *testing.T) {
	dsn := os.Getenv("TEST_DB_URL")
	if dsn == "" {
		t.Skip("TEST_DB_URL not set")
	}
	repo, err := repository.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(repo.Close)
	project, user := dbfixture.SeedProject(t, repo.DB)
	other, otherUser := dbfixture.SeedProject(t, repo.DB)
	// The handlers read the project row (description NOT NULL there).
	if _, err := repo.DB.Exec(context.Background(), `UPDATE projects SET description = '' WHERE id = ANY($1)`, []string{project, other}); err != nil {
		t.Fatal(err)
	}
	own, _, err := repo.Host.Create(context.Background(), user, project, "own-host", nil)
	if err != nil {
		t.Fatal(err)
	}
	foreign, _, err := repo.Host.Create(context.Background(), otherUser, other, "foreign-host", nil)
	if err != nil {
		t.Fatal(err)
	}
	cache := NewOverviewCache()
	h := &WAFAgentHandler{Repo: repo, OverviewCache: cache}
	app := fiber.New()
	app.Get("/api/projects/:id/overview", h.ProjectOverview)
	get := func(q string) (int, string) {
		resp, err := apicontract.FiberTest(t, app, httptest.NewRequest("GET", "/api/projects/"+project+"/overview?"+q, nil), -1)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		return resp.StatusCode, string(b)
	}
	if code, body := get("host_id=" + foreign.ID); code != fiber.StatusNotFound || !strings.Contains(body, "HOST_NOT_FOUND") {
		t.Fatalf("foreign host: %d %s, want 404 HOST_NOT_FOUND", code, body)
	}
	if code, body := get("waf_agent_id=" + uuid.NewString()); code != fiber.StatusNotFound || !strings.Contains(body, "AGENT_NOT_FOUND") {
		t.Fatalf("unknown agent: %d %s, want 404 AGENT_NOT_FOUND", code, body)
	}
	if code, body := get("host_id=not-an-id"); code != fiber.StatusBadRequest {
		t.Fatalf("malformed host: %d %s, want 400", code, body)
	}
	if n := cache.Len(); n != 0 {
		t.Fatalf("refused scopes left %d cache entries", n)
	}
	if code, body := get(fmt.Sprintf("host_id=%s&minutes=60&bucket_seconds=999999999", own.ID)); code != fiber.StatusOK {
		t.Fatalf("own host: %d %s, want 200", code, body)
	}
	if n := cache.Len(); n != 1 {
		t.Fatalf("cache holds %d entries after one good request, want 1", n)
	}

	// The detection-rule list (whose host id used to key a cache entry that
	// never went away) answers 404 for a host outside the project.
	rules := &DetectionRulesHandler{Repo: repo}
	app.Get("/api/projects/:id/host/trace/rules", rules.List)
	list := func(hostID string) int {
		resp, err := apicontract.FiberTest(t, app, httptest.NewRequest("GET", "/api/projects/"+project+"/host/trace/rules?host_id="+hostID, nil), -1)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if resp.StatusCode == fiber.StatusNotFound && !strings.Contains(string(b), "HOST_NOT_FOUND") {
			t.Fatalf("404 for another reason: %s", b)
		}
		return resp.StatusCode
	}
	for _, id := range []string{foreign.ID, uuid.NewString(), "x"} {
		if code := list(id); code != fiber.StatusNotFound {
			t.Fatalf("rules for host %q: %d, want 404", id, code)
		}
	}
	if code := list(own.ID); code != fiber.StatusOK {
		t.Fatalf("rules for own host: %d, want 200", code)
	}
}
