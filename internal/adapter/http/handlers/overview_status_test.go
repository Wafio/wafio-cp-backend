package handlers

import (
	"context"
	"github.com/google/uuid"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"os"
	"testing"
)

func TestOverviewQueryFailuresAreUnavailable(t *testing.T) {
	dsn := os.Getenv("TEST_DB_URL")
	if dsn == "" {
		t.Skip("TEST_DB_URL not set")
	}
	repo, err := repository.New(context.Background(), dsn)
	if err != nil {
		t.Fatal(err)
	}
	repo.DB.Close()
	handler := WAFAgentHandler{Repo: repo}
	result, err := handler.computeOverview(uuid.NewString(), "", "", "", 60, 300, 8)
	if err != nil {
		t.Fatal(err)
	}
	for _, key := range []string{"waf_summary", "waf_summary_prev", "waf_timeline", "waf_top_ips", "waf_top_categories", "waf_top_countries", "waf_agents", "host_agg_status", "host_agg_metrics", "host_fw_drops", "host_firewall_events", "host_trace_stats", "host_trace_events", "hosts"} {
		if result.Widgets[key].State != "unavailable" {
			t.Errorf("%s=%+v", key, result.Widgets[key])
		}
	}
	if result.GeneratedAt.IsZero() {
		t.Fatal("snapshot timestamp missing")
	}
}
