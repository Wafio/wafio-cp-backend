package repository

import (
	"net/url"
	"os"
	"sort"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

func TestQueryFWFeatureTopIPsRangeFiltersAgentsAndTime(t *testing.T) {
	dsn := os.Getenv("TEST_DB_URL")
	if dsn == "" {
		t.Skip("TEST_DB_URL not set")
	}
	ctx := t.Context()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	defer admin.Close()
	schema := "fw_topips_" + uuid.NewString()[:8]
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		t.Fatal(err)
	}
	defer admin.Exec(ctx, "DROP SCHEMA "+quoted+" CASCADE") //nolint:errcheck
	u, err := url.Parse(dsn)
	if err != nil {
		t.Fatal(err)
	}
	q := u.Query()
	q.Set("search_path", schema)
	u.RawQuery = q.Encode()
	pool, err := pgxpool.New(ctx, u.String())
	if err != nil {
		t.Fatal(err)
	}
	defer pool.Close()
	if _, err := pool.Exec(ctx, `CREATE TABLE host_fw_features (agent_id uuid, ts timestamptz, top_src_ips text)`); err != nil {
		t.Fatal(err)
	}
	first, second := uuid.NewString(), uuid.NewString()
	now := time.Now().UTC().Truncate(time.Second)
	fixtures := []struct {
		agent string
		ts    time.Time
		json  string
	}{
		{first, now, `[{"ip":"198.51.100.1","blocklist":2,"total":3}]`},
		{first, now, `[{"ip":"198.51.100.1","egress":2,"other":1,"total":1}]`},
		{first, now.Add(-2 * time.Hour), `[{"ip":"198.51.100.99","total":99}]`},
		{first, now, `{invalid`},
		{second, now, `[{"ip":"203.0.113.2","total":5}]`},
	}
	for _, fixture := range fixtures {
		if _, err := pool.Exec(ctx, `INSERT INTO host_fw_features(agent_id,ts,top_src_ips) VALUES($1,$2,$3)`, fixture.agent, fixture.ts, fixture.json); err != nil {
			t.Fatal(err)
		}
	}
	store := NewHostEventStore(pool)
	since := now.Add(-time.Hour).Unix()
	onlyFirst, err := store.QueryFWFeatureTopIPsRange(ctx, []string{first}, since, 20)
	if err != nil {
		t.Fatal(err)
	}
	if len(onlyFirst) != 1 || onlyFirst[0].SrcIP != "198.51.100.1" || onlyFirst[0].Blocklist != 2 || onlyFirst[0].Other != 3 || onlyFirst[0].Total != 4 {
		t.Fatalf("agent/time filter or egress aggregation changed: %+v", onlyFirst)
	}
	both, err := store.QueryFWFeatureTopIPsRange(ctx, []string{first, second}, since, 20)
	if err != nil {
		t.Fatal(err)
	}
	sort.Slice(both, func(i, j int) bool { return both[i].SrcIP < both[j].SrcIP })
	if len(both) != 2 || both[0].Total != 4 || both[1].SrcIP != "203.0.113.2" || both[1].Total != 5 {
		t.Fatalf("multiple-agent aggregation changed: %+v", both)
	}
	limited, err := store.QueryFWFeatureTopIPsRange(ctx, []string{first, second}, since, 1)
	if err != nil || len(limited) != 1 || limited[0].SrcIP != "203.0.113.2" {
		t.Fatalf("top-1 result changed: %+v, %v", limited, err)
	}
}
