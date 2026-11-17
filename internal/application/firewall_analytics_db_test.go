package application_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/wafio/wafio-cp-backend/internal/adapter/http/handlers"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/application"
)

type fixedFirewallGeo struct{}

func (fixedFirewallGeo) Enrich(ip string) (string, string, float64, float64, string) {
	if ip == "198.51.100.10" {
		return "Example City", "US", 1, 2, "Example ISP"
	}
	return "Other City", "GB", 3, 4, "Other ISP"
}

func TestFirewallCacheWarmerReadsTopIPsOncePerRange(t *testing.T) {
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
	schema := "fw_warm_" + uuid.NewString()[:8]
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.DB.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		t.Fatal(err)
	}
	defer admin.DB.Exec(ctx, "DROP SCHEMA "+quoted+" CASCADE") //nolint:errcheck
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	repo, err := repository.New(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer repo.Close()
	repo.EBPF.SetHostEventStore(repository.NewHostEventStore(repo.DB))
	_, err = repo.DB.Exec(ctx, `
		CREATE TABLE projects (id uuid PRIMARY KEY);
		CREATE TABLE agents (
			id uuid PRIMARY KEY, user_id uuid, project_id uuid, name text,
			last_seen timestamptz, created_at timestamptz, kind text, desired_state jsonb,
			deleted_at timestamptz
		);
		CREATE SEQUENCE topip_reads;
		CREATE FUNCTION counted_topips(value text) RETURNS text LANGUAGE plpgsql VOLATILE AS $$
		BEGIN
			IF current_query() LIKE 'SELECT top_src_ips FROM host_fw_features%' THEN
				PERFORM nextval('topip_reads');
			END IF;
			RETURN value;
		END $$;
		CREATE TABLE feature_fixture (
			agent_id uuid, ts timestamptz, top_src_ips text,
			r_blocklist bigint DEFAULT 0, r_syn_flood bigint DEFAULT 0,
			r_rate_limit bigint DEFAULT 0, r_geo_block bigint DEFAULT 0,
			r_port_scan bigint DEFAULT 0, r_port_policy bigint DEFAULT 0,
			r_egress bigint DEFAULT 0, r_other bigint DEFAULT 0,
			peak_hour integer DEFAULT 0, drop_count bigint DEFAULT 0,
			unique_src bigint DEFAULT 0
		);
		CREATE VIEW host_fw_features AS
		SELECT agent_id, ts, counted_topips(top_src_ips) AS top_src_ips,
			r_blocklist, r_syn_flood, r_rate_limit, r_geo_block,
			r_port_scan, r_port_policy, r_egress, r_other,
			peak_hour, drop_count, unique_src
		FROM feature_fixture;
	`)
	if err != nil {
		t.Fatal(err)
	}
	projectID, agentID := uuid.NewString(), uuid.NewString()
	if _, err := repo.DB.Exec(ctx, `INSERT INTO projects VALUES ($1)`, projectID); err != nil {
		t.Fatal(err)
	}
	if _, err := repo.DB.Exec(ctx, `INSERT INTO agents VALUES ($1,$2,$3,'host',now(),now(),'host','{}')`, agentID, uuid.NewString(), projectID); err != nil {
		t.Fatal(err)
	}
	const topIPs = `[{"ip":"198.51.100.10","total":3,"blocklist":2,"rate_limit":1},{"ip":"203.0.113.20","total":1,"egress":1}]`
	if _, err := repo.DB.Exec(ctx, `INSERT INTO feature_fixture(agent_id,ts,top_src_ips,r_blocklist,r_egress,drop_count,unique_src) VALUES ($1,now(),$2,2,1,4,2)`, agentID, topIPs); err != nil {
		t.Fatal(err)
	}
	h := handlers.NewFirewallAnalytics(repo, fixedFirewallGeo{})
	// The warmer only warms projects viewed within the last hour.
	h.NoteViewed(projectID)
	warmCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	h.StartFirewallCacheWarmer(warmCtx)
	deadline := time.NewTimer(15 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(20 * time.Millisecond)
	defer tick.Stop()
	for {
		complete := true
		for _, rangeKey := range application.WarmRanges() {
			for _, limit := range []int{20, 50} {
				if _, ok := h.TopIPsCacheData(fmt.Sprintf("%s:%s:%s:%d", projectID, agentID, rangeKey, limit)); !ok {
					complete = false
					break
				}
			}
		}
		if complete {
			break
		}
		select {
		case <-deadline.C:
			t.Fatal("cache warmer did not populate all three ranges")
		case <-tick.C:
		}
	}
	var payload struct {
		IPs []struct {
			SrcIP       string `json:"src_ip"`
			CountryCode string `json:"country_code"`
			Blocklist   int    `json:"blocklist"`
			RateLimit   int    `json:"rate_limit"`
			Other       int    `json:"other"`
			Total       int    `json:"total"`
		} `json:"ips"`
		Count int `json:"count"`
	}
	key := fmt.Sprintf("%s:%s:24h:20", projectID, agentID)
	entry, ok := h.TopIPsCacheData(key)
	if !ok {
		t.Fatal("24h top IP cache missing")
	}
	if err := json.Unmarshal(entry, &payload); err != nil {
		t.Fatal(err)
	}
	if payload.Count != 2 || len(payload.IPs) != 2 ||
		payload.IPs[0].SrcIP != "198.51.100.10" || payload.IPs[0].CountryCode != "US" ||
		payload.IPs[0].Blocklist != 2 || payload.IPs[0].RateLimit != 1 || payload.IPs[0].Total != 3 ||
		payload.IPs[1].SrcIP != "203.0.113.20" || payload.IPs[1].CountryCode != "GB" || payload.IPs[1].Other != 1 {
		t.Fatalf("top-20 payload changed: %+v", payload)
	}
	var reads int
	if err := repo.DB.QueryRow(ctx, `SELECT last_value FROM topip_reads`).Scan(&reads); err != nil {
		t.Fatal(err)
	}
	if reads != len(application.WarmRanges()) {
		t.Fatalf("top IP JSON fetched %d times for %d warm ranges; want one fetch per range", reads, len(application.WarmRanges()))
	}
}
