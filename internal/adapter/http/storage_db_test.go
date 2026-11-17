package httpadapter

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"github.com/gofiber/fiber/v2"
)

// Administration › Data retention end to end against TEST_DB_URL (a
// database without TimescaleDB in local runs: plain tables, control-plane
// retention): saves are audited with old → new values.
func TestDBStorageSettingsAudited(t *testing.T) {
	f := newMailFixture(t)
	bg := context.Background()
	clear := func() {
		_, _ = f.repo.DB.Exec(bg, `DELETE FROM system_settings WHERE key IN ('data_retention', 'db_size_budget', 'db_size_alert_state')`)
	}
	clear()
	t.Cleanup(clear)
	// Saving retention swaps waf_decisions' TimescaleDB retention policy, which
	// clear() does not undo; the schema tests of the repository package read
	// that policy from the same database, so put it back.
	var daysBefore *int
	if err := f.repo.DB.QueryRow(bg, `SELECT (EXTRACT(EPOCH FROM (config->>'drop_after')::interval) / 86400)::int
		  FROM timescaledb_information.jobs
		 WHERE proc_name = 'policy_retention' AND hypertable_schema = current_schema() AND hypertable_name = 'waf_decisions'
		 ORDER BY job_id LIMIT 1`).Scan(&daysBefore); err == nil && daysBefore != nil {
		t.Cleanup(func() {
			_, _ = f.repo.DB.Exec(bg, `SELECT remove_retention_policy('waf_decisions'::regclass, if_exists => true)`)
			_, _ = f.repo.DB.Exec(bg, `SELECT add_retention_policy('waf_decisions'::regclass, drop_after => make_interval(days => $1::int))`, *daysBefore)
		})
	}

	if r := call(t, f.app, http.MethodGet, "/api/admin/storage", f.memberToken, nil); r.status != fiber.StatusForbidden {
		t.Fatalf("user: %d", r.status)
	}
	r := call(t, f.app, http.MethodGet, "/api/admin/storage", f.adminToken, nil)
	if r.status != fiber.StatusOK {
		t.Fatalf("status: %d %s", r.status, r.raw)
	}
	if r := call(t, f.app, http.MethodPut, "/api/admin/storage/retention", f.adminToken, map[string]any{"tables": map[string]int{"waf_decisions": 1}}); r.status != fiber.StatusBadRequest {
		t.Fatalf("below minimum: %d", r.status)
	}
	if r := call(t, f.app, http.MethodPut, "/api/admin/storage/retention", f.adminToken, map[string]any{"tables": map[string]int{"waf_decisions": 14}}); r.status != fiber.StatusOK {
		t.Fatalf("save: %d %s", r.status, r.raw)
	}
	if r := call(t, f.app, http.MethodPut, "/api/admin/storage/budget", f.adminToken, map[string]any{"budget_gb": 50}); r.status != fiber.StatusOK {
		t.Fatalf("budget: %d %s", r.status, r.raw)
	}

	var saved map[string]map[string]int
	if err := f.repo.SystemSettings.GetJSON(bg, "data_retention", &saved); err != nil || saved["tables"]["waf_decisions"] != 14 {
		t.Fatalf("saved %v %v", saved, err)
	}

	rows, err := f.repo.DB.Query(bg,
		`SELECT action, outcome, target_id, COALESCE(metadata::text, '') FROM system_audit
		 WHERE actor_user_id = $1 AND action IN ('admin.retention_updated', 'admin.storage_budget_updated') ORDER BY created_at, id`, f.adminID)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	type row struct{ action, outcome, target, meta string }
	var got []row
	for rows.Next() {
		var x row
		if err := rows.Scan(&x.action, &x.outcome, &x.target, &x.meta); err != nil {
			t.Fatal(err)
		}
		got = append(got, x)
	}
	if len(got) != 3 {
		t.Fatalf("audit rows %+v", got)
	}
	if got[0].action != "admin.retention_updated" || got[0].outcome != "failure" || got[0].meta != "" {
		t.Fatalf("failed save row %+v", got[0])
	}
	var meta struct {
		Tables map[string]struct {
			Old, New int
			Mode     string
		} `json:"tables"`
	}
	if err := json.Unmarshal([]byte(got[1].meta), &meta); err != nil || got[1].outcome != "success" || got[1].target != "data_retention" {
		t.Fatalf("retention row %+v %v", got[1], err)
	}
	if c := meta.Tables["waf_decisions"]; c.Old != 30 || c.New != 14 || c.Mode == "" || len(meta.Tables) != 1 {
		t.Fatalf("retention metadata %+v", meta)
	}
	var bmeta map[string]int64
	if err := json.Unmarshal([]byte(got[2].meta), &bmeta); err != nil || bmeta["old_bytes"] != 0 || bmeta["new_bytes"] != 50_000_000_000 {
		t.Fatalf("budget row %+v %v", got[2], err)
	}
}
