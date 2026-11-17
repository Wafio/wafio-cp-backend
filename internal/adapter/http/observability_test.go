package httpadapter

import (
	"context"
	"encoding/json"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/wafio/wafio-cp-backend/internal/apicontract"

	"github.com/gofiber/fiber/v2"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/wafio/wafio-cp-backend/internal/adapter/http/handlers"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/config"
	"github.com/wafio/wafio-cp-backend/shared/metrics"
)

// /ready through the real app reports the database and the agent gRPC
// server; a configured gRPC address with no running server is unavailable.
// The HTTP series are registered on the WithMetrics registry.
func TestReadyAndMetricsThroughNewFiberApp(t *testing.T) {
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
	cfg := &config.Config{}
	cfg.JWT.Secret = secret
	cfg.JWT.ExpireHours = 1
	cfg.Server.FrontendPath = t.TempDir()
	cfg.Server.AgentGRPCAddr = "127.0.0.1:0"
	reg := metrics.NewRegistry()
	app := NewFiberApp(ctx, cfg, repository.FromPool(pool), nil, nil, nil, nil, &handlers.SecurityDataHandler{}, "test",
		WithUserStateLoader(testUsers.load), WithMetrics(reg))

	resp, err := apicontract.FiberTest(t, app, httptest.NewRequest("GET", "/ready", nil), 5000)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != fiber.StatusServiceUnavailable {
		t.Fatalf("status = %d body %s", resp.StatusCode, body)
	}
	var parsed struct {
		Checks map[string]string `json:"checks"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatal(err)
	}
	if parsed.Checks["database"] != "unavailable" || parsed.Checks["grpc"] != handlers.GRPCNotServing {
		t.Fatalf("checks = %v", parsed.Checks)
	}
	if strings.Contains(string(body), "127.0.0.1:1") {
		t.Fatal("dependency detail leaked")
	}

	var out strings.Builder
	if err := reg.Write(&out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"wafio_http_panics_recovered_total ",
		`wafio_sse_streams{stream="host"} 0`,
		`wafio_sse_streams{stream="waf_liveness"} 0`,
		"wafio_sse_host_pollers 0",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q", want)
		}
	}
}

func TestRecoverMiddlewareCountsPanics(t *testing.T) {
	app := fiber.New(fiber.Config{ErrorHandler: ErrorHandler})
	app.Use(recoverMiddleware())
	app.Get("/boom", func(*fiber.Ctx) error { panic("secret detail") })
	before := HTTPPanicsRecovered()
	resp, err := app.Test(httptest.NewRequest("GET", "/boom", nil))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 500 || strings.Contains(string(body), "secret detail") {
		t.Fatalf("status %d body %s", resp.StatusCode, body)
	}
	if HTTPPanicsRecovered() != before+1 {
		t.Fatalf("panics = %d, want %d", HTTPPanicsRecovered(), before+1)
	}
}
