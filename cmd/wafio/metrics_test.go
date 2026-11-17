package main

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/wafio/wafio-cp-backend/internal/agentserver"
	"github.com/wafio/wafio-cp-backend/internal/config"
	"github.com/wafio/wafio-cp-backend/shared/metrics"
)

// The control-plane series render without a gRPC server (disabled or
// failed to start) and without a pool; every expected series is
// present.
func TestControlPlaneMetricsRender(t *testing.T) {
	reg := metrics.NewRegistry()
	registerControlPlaneMetrics(reg, nil, nil, agentserver.NewDecisionBroker())
	var out strings.Builder
	if err := reg.Write(&out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"wafio_decisions_queued_total 0",
		"wafio_decisions_written_total 0",
		"wafio_decisions_dropped_total 0",
		"wafio_decisions_pending 0",
		"wafio_decision_batch_retries_total 0",
		"wafio_block_queue_dropped_total 0",
		"wafio_block_window_evicted_total 0",
		`wafio_agent_streams{kind="waf"} 0`,
		`wafio_agent_streams{kind="host"} 0`,
		"wafio_agent_push_failures_total 0",
		"wafio_agent_grpc_serving 0",
		"wafio_grpc_panics_recovered_total ",
		"wafio_decision_sse_subscribers 0",
		"wafio_audit_write_failures_total ",
		"wafio_decisions_foreign_app_rejected_total ",
		"wafio_trace_repeats_dropped_total ",
		"wafio_agent_recv_charged_bytes_total 0",
		`wafio_agent_recv_waits_total{reason="account"} 0`,
		`wafio_agent_recv_waits_total{reason="fair_share"} 0`,
		"wafio_agent_recv_wait_seconds_total 0",
		"wafio_agent_recv_liveness_touches_total 0",
		"wafio_agent_recv_active_accounts 0",
		"wafio_agent_recv_throttled_accounts 0",
		"wafio_agent_recv_debt_bytes 0",
		"wafio_agent_recv_share_bytes_per_second 0",
		`wafio_agent_recv_limit_bytes_per_second{scope="total"} 0`,
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q", want)
		}
	}
}

// With a gRPC server the receive budget series show the configured limits;
// the config defaults are the agentserver defaults.
func TestControlPlaneRecvBudgetMetrics(t *testing.T) {
	account, total := config.ServerConfig{}.AgentRecvLimits()
	if account != agentserver.DefaultRecvAccountRate || total != agentserver.DefaultRecvTotalRate {
		t.Fatalf("config defaults %d/%d, agentserver defaults %d/%d", account, total,
			agentserver.DefaultRecvAccountRate, agentserver.DefaultRecvTotalRate)
	}
	srv := agentserver.NewServer(nil, nil, nil)
	srv.SetRecvLimits(32<<20, 256<<20)
	reg := metrics.NewRegistry()
	registerControlPlaneMetrics(reg, nil, srv, nil)
	var out strings.Builder
	if err := reg.Write(&out); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`wafio_agent_recv_limit_bytes_per_second{scope="account"} 3.3554432e+07`,
		`wafio_agent_recv_limit_bytes_per_second{scope="total"} 2.68435456e+08`,
		"wafio_agent_recv_share_bytes_per_second 3.3554432e+07",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in\n%s", want, out.String())
		}
	}
}

func TestMetricsListenerLoopbackOnly(t *testing.T) {
	t.Setenv(metrics.EnvAddr, "0.0.0.0:0")
	if _, err := startMetricsListener(metrics.NewRegistry()); !errors.Is(err, metrics.ErrNotLoopback) {
		t.Fatalf("public address accepted: %v", err)
	}

	t.Setenv(metrics.EnvAddr, "")
	closeFn, err := startMetricsListener(metrics.NewRegistry())
	if err != nil || closeFn == nil {
		t.Fatalf("unset address must be a no-op: %v", err)
	}
	closeFn()

	reg := metrics.NewRegistry()
	reg.Gauge("wafio_test_up", "", func() float64 { return 1 })
	ln, err := metrics.Listen("127.0.0.1:0", nil)
	if err != nil {
		t.Fatal(err)
	}
	stop := metrics.Serve(ln, reg, t.Logf)
	defer stop()
	resp, err := http.Get("http://" + ln.Addr().String() + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), "wafio_test_up 1") || resp.Header.Get("Content-Type") != metrics.ContentType {
		t.Fatalf("scrape: %s", body)
	}
}
