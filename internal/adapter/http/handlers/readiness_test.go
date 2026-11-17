package handlers

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/wafio/wafio-cp-backend/internal/apicontract"
	"io"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gofiber/fiber/v2"
)

func readinessResponse(t *testing.T, checks ReadinessChecks) (int, map[string]any, string) {
	t.Helper()
	app := fiber.New()
	app.Get("/ready", Readiness(checks))
	response, err := apicontract.FiberTest(t, app, httptest.NewRequest("GET", "/ready", nil))
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("cache-control = %q", response.Header.Get("Cache-Control"))
	}
	var parsed struct {
		Status string         `json:"status"`
		Checks map[string]any `json:"checks"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		t.Fatalf("body %s: %v", body, err)
	}
	return response.StatusCode, parsed.Checks, string(body)
}

func TestReadinessDatabaseDependency(t *testing.T) {
	for _, tc := range []struct {
		name   string
		err    error
		status int
	}{{"ready", nil, 200}, {"unavailable", errors.New("private DSN must not escape"), 503}} {
		t.Run(tc.name, func(t *testing.T) {
			status, _, body := readinessResponse(t, ReadinessChecks{Ping: func(ctx context.Context) error {
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > time.Second {
					t.Error("dependency check must have a bounded deadline")
				}
				return tc.err
			}})
			if strings.Contains(body, "private DSN") {
				t.Fatal("error text leaked into the readiness body")
			}
			if status != tc.status {
				t.Fatalf("status = %d, want %d", status, tc.status)
			}
		})
	}
}

// /ready fails when gRPC is not serving or the decision writer dropped
// in the last window; gRPC disabled by configuration is not a failure.
func TestReadinessGRPCAndWriterDrops(t *testing.T) {
	ok := func(context.Context) error { return nil }
	var drops atomic.Uint64
	idle := NewDropWatch(func() uint64 { return 0 }, time.Minute)

	for _, tc := range []struct {
		name   string
		checks ReadinessChecks
		status int
		key    string
		want   string
	}{
		{"grpc serving", ReadinessChecks{Ping: ok, GRPC: func() string { return GRPCServing }, Drops: idle}, 200, "grpc", GRPCServing},
		{"grpc disabled", ReadinessChecks{Ping: ok, GRPC: func() string { return GRPCDisabled }}, 200, "grpc", GRPCDisabled},
		{"grpc down", ReadinessChecks{Ping: ok, GRPC: func() string { return GRPCNotServing }, Drops: idle}, 503, "grpc", GRPCNotServing},
		{"no ping configured", ReadinessChecks{}, 503, "database", "unavailable"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			status, checks, _ := readinessResponse(t, tc.checks)
			if status != tc.status || checks[tc.key] != tc.want {
				t.Fatalf("status=%d checks=%v", status, checks)
			}
		})
	}

	t.Run("writer drops", func(t *testing.T) {
		clock := time.Unix(1_000_000, 0)
		w := NewDropWatch(func() uint64 { return drops.Load() }, time.Minute)
		w.now = func() time.Time { return clock }
		drops.Store(10) // drops before the watch started are the baseline
		w.Observe()
		checks := ReadinessChecks{Ping: ok, Drops: w}
		if status, c, _ := readinessResponse(t, checks); status != 200 || c["decision_writer"] != "ready" {
			t.Fatalf("baseline drops must not fail readiness: %d %v", status, c)
		}
		drops.Add(1)
		clock = clock.Add(10 * time.Second)
		if status, c, _ := readinessResponse(t, checks); status != 503 || c["decision_writer"] != "dropping" {
			t.Fatalf("rising drops must fail readiness: %d %v", status, c)
		}
		clock = clock.Add(59 * time.Second)
		if status, _, _ := readinessResponse(t, checks); status != 503 {
			t.Fatalf("still inside the window: %d", status)
		}
		clock = clock.Add(2 * time.Second)
		if status, _, _ := readinessResponse(t, checks); status != 200 {
			t.Fatalf("window passed without new drops: %d", status)
		}
	})
}

func TestDropWatchRunSamples(t *testing.T) {
	var v atomic.Uint64
	w := NewDropWatch(func() uint64 { return v.Load() }, time.Minute)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { w.Run(ctx, 5*time.Millisecond); close(done) }()
	time.Sleep(20 * time.Millisecond)
	v.Store(3)
	deadline := time.Now().Add(2 * time.Second)
	for {
		w.mu.Lock()
		rose := !w.lastRise.IsZero()
		w.mu.Unlock()
		if rose {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("Run never observed the rise")
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	<-done
}
