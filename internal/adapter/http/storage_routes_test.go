package httpadapter

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/wafio/wafio-cp-backend/internal/adapter/http/auth"
	"github.com/wafio/wafio-cp-backend/internal/adapter/http/handlers"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/application"
	"github.com/wafio/wafio-cp-backend/internal/config"
	"github.com/wafio/wafio-cp-backend/internal/domain"
	"github.com/wafio/wafio-cp-backend/shared/metrics"
)

// memSettings is an in-memory system_settings.
type memSettings struct {
	mu   sync.Mutex
	data map[string][]byte
}

func (m *memSettings) GetJSON(_ context.Context, key string, dst any) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if raw, ok := m.data[key]; ok {
		return json.Unmarshal(raw, dst)
	}
	return nil
}

func (m *memSettings) SetJSON(_ context.Context, key string, v any) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	raw, err := json.Marshal(v)
	if err != nil {
		return err
	}
	if m.data == nil {
		m.data = map[string][]byte{}
	}
	m.data[key] = raw
	return nil
}

// plainStorage is a database without TimescaleDB: plain tables.
type plainStorage struct {
	settings *memSettings
	down     bool
}

func (p *plainStorage) TimescaleInfo(context.Context) (domain.TimescaleInfo, error) {
	if p.down {
		return domain.TimescaleInfo{}, errors.New("db down: secret detail")
	}
	return domain.TimescaleInfo{}, nil
}
func (p *plainStorage) TableStats(context.Context, domain.RetentionTable, bool) (domain.TableStorageStats, error) {
	return domain.TableStorageStats{Exists: true, TotalBytes: 1 << 20}, nil
}
func (p *plainStorage) ApplyRetention(ctx context.Context, _ []domain.RetentionApply, key string, v any) error {
	return p.settings.SetJSON(ctx, key, v)
}
func (p *plainStorage) DropChunksOlderThan(context.Context, string, int) (int, error) { return 0, nil }
func (p *plainStorage) DeleteOlderThan(context.Context, domain.RetentionTable, int, int) (int64, error) {
	return 0, nil
}
func (p *plainStorage) DatabaseSize(context.Context) (int64, error) { return 900_000_000, nil }
func (p *plainStorage) DataDirectory(context.Context) (string, error) {
	return "", errors.New("permission denied")
}
func (p *plainStorage) AdminEmails(context.Context) ([]string, error) { return nil, nil }
func (p *plainStorage) TryRetentionLock(context.Context) (func(), bool, error) {
	return func() {}, true, nil
}

func newStorageTestApp(t *testing.T) (*fiber.App, *plainStorage, *metrics.Registry) {
	t.Helper()
	poolCfg, err := pgxpool.ParseConfig("postgres://wafio:unused@127.0.0.1:1/wafio?connect_timeout=1&sslmode=disable")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		cancel()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		cancel()
		pool.Close()
	})
	set := &memSettings{}
	store := &plainStorage{settings: set}
	svc := &application.Storage{Store: store, Settings: set}
	cfg := &config.Config{}
	cfg.JWT.Secret = secret
	cfg.JWT.ExpireHours = 1
	cfg.Server.FrontendPath = t.TempDir()
	reg := metrics.NewRegistry()
	app := NewFiberApp(ctx, cfg, repository.FromPool(pool), nil, nil, nil, nil, &handlers.SecurityDataHandler{}, "test",
		WithUserStateLoader(testUsers.load), WithStorage(svc), WithMetrics(reg))
	return app, store, reg
}

func userToken(t *testing.T) string {
	t.Helper()
	id := uuid.NewString()
	testUsers.put(id, auth.UserState{Exists: true, Role: "user"})
	tok, err := auth.SignJWT(id, "user@example.test", "user", secret, 1)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

var storageRoutes = []struct{ method, path string }{
	{http.MethodGet, "/api/admin/storage"},
	{http.MethodGet, "/api/admin/storage/alert"},
	{http.MethodPut, "/api/admin/storage/retention"},
	{http.MethodPut, "/api/admin/storage/budget"},
}

// System admin only: no session 401, a project user 403, nothing saved.
func TestStorageRoutesAdminOnly(t *testing.T) {
	app, store, _ := newStorageTestApp(t)
	user := userToken(t)
	for _, rt := range storageRoutes {
		body := map[string]any{"tables": map[string]int{"waf_decisions": 14}, "budget_gb": 10}
		if r := call(t, app, rt.method, rt.path, "", body); r.status != fiber.StatusUnauthorized {
			t.Fatalf("%s %s without a session: %d", rt.method, rt.path, r.status)
		}
		if r := call(t, app, rt.method, rt.path, user, body); r.status != fiber.StatusForbidden {
			t.Fatalf("%s %s as a user: %d %s", rt.method, rt.path, r.status, r.raw)
		}
	}
	if len(store.settings.data) != 0 {
		t.Fatalf("a refused request saved settings: %v", store.settings.data)
	}
}

func TestStorageRoutesThroughApp(t *testing.T) {
	app, store, reg := newStorageTestApp(t)
	admin := adminToken(t)

	r := call(t, app, http.MethodGet, "/api/admin/storage", admin, nil)
	if r.status != fiber.StatusOK || r.header.Get("Cache-Control") != "no-store" {
		t.Fatalf("status: %d %s", r.status, r.raw)
	}
	tables, _ := r.body["tables"].([]any)
	if len(tables) != len(domain.RetentionTables) {
		t.Fatalf("tables: %v", r.body["tables"])
	}
	first := tables[0].(map[string]any)
	if first["mode"] != "delete" || first["active"] != true || first["retention_days"] != float64(30) {
		t.Fatalf("plain table row %v", first)
	}
	tsv := r.body["timescaledb"].(map[string]any)
	if tsv["installed"] != false || tsv["note"] == "" {
		t.Fatalf("timescaledb %v", tsv)
	}
	fs := r.body["database"].(map[string]any)["filesystem"].(map[string]any)
	if fs["known"] != false || fs["reason"] == "" {
		t.Fatalf("filesystem %v", fs)
	}

	// Validation: field-scoped 400s.
	for _, tc := range []struct {
		body  any
		field string
	}{
		{map[string]any{"tables": map[string]int{"waf_decisions": 6}}, "tables.waf_decisions"},
		{map[string]any{"tables": map[string]int{"waf_decisions": 3651}}, "tables.waf_decisions"},
		{map[string]any{"tables": map[string]int{"agents": 30}}, "tables.agents"},
		{map[string]any{"tables": map[string]any{}}, "tables"},
	} {
		r := call(t, app, http.MethodPut, "/api/admin/storage/retention", admin, tc.body)
		if r.status != fiber.StatusBadRequest || r.body["code"] != "VALIDATION_FAILED" || r.body["field"] != tc.field {
			t.Fatalf("%v: %d %s", tc.body, r.status, r.raw)
		}
	}
	if r := call(t, app, http.MethodPut, "/api/admin/storage/retention", admin, map[string]any{"tables": map[string]any{"waf_decisions": 7.5}}); r.status != fiber.StatusBadRequest {
		t.Fatalf("fractional days: %d", r.status)
	}

	r = call(t, app, http.MethodPut, "/api/admin/storage/retention", admin, map[string]any{"tables": map[string]any{"waf_decisions": 14, "host_security_events": nil}})
	if r.status != fiber.StatusOK {
		t.Fatalf("save: %d %s", r.status, r.raw)
	}
	row := r.body["tables"].([]any)[0].(map[string]any)
	if row["retention_days"] != float64(14) || row["saved"] != true {
		t.Fatalf("saved row %v", row)
	}

	for _, gb := range []any{0, 0.05, -3, 2_000_000, "ten"} {
		r := call(t, app, http.MethodPut, "/api/admin/storage/budget", admin, map[string]any{"budget_gb": gb})
		if r.status != fiber.StatusBadRequest {
			t.Fatalf("budget %v: %d %s", gb, r.status, r.raw)
		}
	}
	r = call(t, app, http.MethodPut, "/api/admin/storage/budget", admin, map[string]any{"budget_gb": 1})
	db := r.body["database"].(map[string]any)
	if r.status != fiber.StatusOK || db["budget_bytes"] != float64(1e9) || db["level"] != "warning" {
		t.Fatalf("budget: %d %v", r.status, db)
	}
	r = call(t, app, http.MethodGet, "/api/admin/storage/alert", admin, nil)
	if r.status != fiber.StatusOK || r.body["level"] != "warning" || r.body["level_reason"] != "budget" {
		t.Fatalf("alert: %d %s", r.status, r.raw)
	}

	// Metrics follow the cached status.
	var out strings.Builder
	if err := reg.Write(&out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"wafio_db_size_bytes 9e+08", "wafio_db_size_budget_bytes 1e+09", "wafio_db_size_alert_level 1", `wafio_retention_days{table="waf_decisions"} 14`} {
		if !strings.Contains(out.String(), want) {
			t.Fatalf("metrics lack %q:\n%s", want, out.String())
		}
	}

	// Storage errors: generic 503, no detail.
	store.down = true
	r = call(t, app, http.MethodGet, "/api/admin/storage", admin, nil)
	if r.status != fiber.StatusServiceUnavailable || r.body["code"] != "STORAGE_UNAVAILABLE" || strings.Contains(r.raw, "secret detail") {
		t.Fatalf("down: %d %s", r.status, r.raw)
	}
}
