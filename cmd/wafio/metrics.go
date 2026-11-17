package main

import (
	"log"
	"os"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/agentserver"
	"github.com/wafio/wafio-cp-backend/internal/application"
	"github.com/wafio/wafio-cp-backend/shared/metrics"
)

// registerControlPlaneMetrics adds the control-plane series that
// cmd/wafio can see: decision writer, block work, agent streams and pushes,
// the decision broker, recovered gRPC panics, audit and ingest rejections, the
// trace repeat cap, and the database pool. The HTTP adapter adds its own via httpadapter.WithMetrics.
// srv and broker may be nil (gRPC disabled); their series then read 0.
func registerControlPlaneMetrics(reg *metrics.Registry, pool *pgxpool.Pool, srv *agentserver.Server, broker *agentserver.DecisionBroker) {
	u := func(v uint64) float64 { return float64(v) }
	writer := func(pick func(agentserver.DecisionWriterStats) uint64) func() float64 {
		return func() float64 { return u(pick(srv.DecisionWriterStats())) }
	}

	reg.Counter("wafio_decisions_queued", "WAF decisions accepted into the write queue.",
		writer(func(s agentserver.DecisionWriterStats) uint64 { return s.Queued }))
	reg.Counter("wafio_decisions_written", "WAF decisions written to waf_decisions.",
		writer(func(s agentserver.DecisionWriterStats) uint64 { return s.Written }))
	reg.Counter("wafio_decisions_dropped", "WAF decisions dropped because the write queue was full (the project holding the most rows loses one).",
		writer(func(s agentserver.DecisionWriterStats) uint64 { return s.Dropped }))
	reg.Counter("wafio_decisions_dropped_stalled", "Part of wafio_decisions_dropped lost while the writer was backing off a database error (watched by /ready).",
		writer(func(s agentserver.DecisionWriterStats) uint64 { return s.DroppedStalled }))
	reg.Counter("wafio_decisions_dropped_overload", "Part of wafio_decisions_dropped lost while several projects each held no more than an equal share of the full queue (watched by /ready).",
		writer(func(s agentserver.DecisionWriterStats) uint64 { return s.DroppedOverload }))
	reg.Counter("wafio_decisions_failed", "WAF decisions the database refused or shutdown gave up on.",
		writer(func(s agentserver.DecisionWriterStats) uint64 { return s.Failed }))
	reg.Counter("wafio_decisions_gone_agent", "WAF decisions discarded because their agent no longer exists (part of failed).",
		writer(func(s agentserver.DecisionWriterStats) uint64 { return s.GoneAgent }))
	reg.Counter("wafio_decision_batch_retries", "Decision batch attempts that hit a connection or timeout error.",
		writer(func(s agentserver.DecisionWriterStats) uint64 { return s.Retries }))
	reg.Gauge("wafio_decisions_pending", "WAF decisions waiting in the write queue.",
		func() float64 { return float64(srv.DecisionWriterStats().Pending) })

	reg.Counter("wafio_block_queue_dropped", "Block decisions not recorded in the block window because the queue was full.",
		func() float64 { return u(srv.BlockQueueDropped()) })
	reg.Counter("wafio_block_window_evicted", "Block-window entries evicted by the per-agent cap.",
		func() float64 { return u(srv.BlockWindowEvicted()) })

	reg.GaugeVec("wafio_agent_streams", "Connected agent gRPC streams by agent kind.", func() []metrics.Sample {
		counts := srv.StreamCounts()
		return []metrics.Sample{
			{Labels: []metrics.Label{{Name: "kind", Value: "waf"}}, Value: float64(counts["waf"])},
			{Labels: []metrics.Label{{Name: "kind", Value: "host"}}, Value: float64(counts["host"])},
		}
	})
	reg.Counter("wafio_agent_push_failures", "Pushed messages to agents that failed or missed their send deadline.",
		func() float64 { return u(srv.PushFailures()) })
	reg.Gauge("wafio_agent_grpc_serving", "1 while the agent gRPC server accepts connections.", func() float64 {
		if srv.Serving() {
			return 1
		}
		return 0
	})
	// Agent receive budget.
	recv := func(pick func(agentserver.RecvBudgetStats) float64) func() float64 {
		return func() float64 { return pick(srv.RecvBudgetStats()) }
	}
	reg.Counter("wafio_agent_recv_charged_bytes", "Bytes charged to the agent receive budget (every message received; gzip telemetry again at its inflated size).",
		recv(func(s agentserver.RecvBudgetStats) float64 { return u(s.ChargedBytes) }))
	reg.CounterVec("wafio_agent_recv_waits", "Agent streams that had to wait for the receive budget: at their account's own rate (account) or at a fair share below it while the process-wide total was contended (fair_share).", func() []metrics.Sample {
		st := srv.RecvBudgetStats()
		return []metrics.Sample{
			{Labels: []metrics.Label{{Name: "reason", Value: "account"}}, Value: u(st.WaitsAccount)},
			{Labels: []metrics.Label{{Name: "reason", Value: "fair_share"}}, Value: u(st.WaitsShare)},
		}
	})
	reg.Counter("wafio_agent_recv_wait_seconds", "Time agent streams spent waiting for the receive budget.",
		recv(func(s agentserver.RecvBudgetStats) float64 { return s.WaitSeconds }))
	reg.Counter("wafio_agent_recv_liveness_touches", "last_seen updates made for agents whose streams waited for the receive budget past a heartbeat interval.",
		recv(func(s agentserver.RecvBudgetStats) float64 { return u(s.LivenessTouches) }))
	reg.Gauge("wafio_agent_recv_active_accounts", "Accounts whose agent streams were charged in the last two seconds.",
		recv(func(s agentserver.RecvBudgetStats) float64 { return float64(s.ActiveAccounts) }))
	reg.Gauge("wafio_agent_recv_throttled_accounts", "Active accounts whose agent streams had to wait for the receive budget in the last two seconds.",
		recv(func(s agentserver.RecvBudgetStats) float64 { return float64(s.ThrottledAccounts) }))
	reg.Gauge("wafio_agent_recv_debt_bytes", "Bytes the active accounts in debt owe the receive budget.",
		recv(func(s agentserver.RecvBudgetStats) float64 { return s.DebtBytes }))
	reg.Gauge("wafio_agent_recv_share_bytes_per_second", "Rate every account's receive budget refills at: the per-account limit, or the fair share below it while the total is contended.",
		recv(func(s agentserver.RecvBudgetStats) float64 { return s.ShareRate }))
	reg.GaugeVec("wafio_agent_recv_limit_bytes_per_second", "Configured agent receive budget: per account and process-wide total.", func() []metrics.Sample {
		st := srv.RecvBudgetStats()
		return []metrics.Sample{
			{Labels: []metrics.Label{{Name: "scope", Value: "account"}}, Value: st.AccountRate},
			{Labels: []metrics.Label{{Name: "scope", Value: "total"}}, Value: st.TotalRate},
		}
	})
	reg.Counter("wafio_grpc_panics_recovered", "Panics recovered in the agent gRPC server and its background work.",
		func() float64 { return float64(agentserver.PanicsRecovered()) })
	reg.Gauge("wafio_decision_sse_subscribers", "Open live-decision SSE subscribers (decision broker).", func() float64 {
		if broker == nil {
			return 0
		}
		return float64(broker.SubscriberCount())
	})

	reg.Counter("wafio_audit_write_failures", "Audit log rows that could not be written.",
		func() float64 { return float64(repository.AuditWriteFailures()) })
	reg.Counter("wafio_decisions_foreign_app_rejected", "Agent decisions rejected for naming an app outside the agent's project.",
		func() float64 { return float64(repository.ForeignAppDecisionsRejected()) })
	reg.Counter("wafio_decisions_gone_agent_rejected", "Agent decisions rejected at ingest because the agent was deleted.",
		func() float64 { return float64(repository.GoneAgentDecisionsRejected()) })
	reg.Counter("wafio_trace_repeats_dropped", "Host trace rows left out of storage because the same event repeated more than 20 times in 60 seconds for one agent (a summary row is stored per window).",
		func() float64 { return float64(application.TraceRepeatsDropped()) })

	if pool == nil {
		return
	}
	reg.Gauge("wafio_db_pool_acquired_conns", "Database connections currently in use.",
		func() float64 { return float64(pool.Stat().AcquiredConns()) })
	reg.Gauge("wafio_db_pool_idle_conns", "Idle database connections.",
		func() float64 { return float64(pool.Stat().IdleConns()) })
	reg.Gauge("wafio_db_pool_total_conns", "Open database connections.",
		func() float64 { return float64(pool.Stat().TotalConns()) })
	reg.Gauge("wafio_db_pool_max_conns", "Configured maximum database connections.",
		func() float64 { return float64(pool.Stat().MaxConns()) })
	reg.Counter("wafio_db_pool_acquires", "Successful connection acquires.",
		func() float64 { return float64(pool.Stat().AcquireCount()) })
	reg.Counter("wafio_db_pool_empty_acquires", "Acquires that had to wait because no connection was idle.",
		func() float64 { return float64(pool.Stat().EmptyAcquireCount()) })
	reg.Counter("wafio_db_pool_canceled_acquires", "Acquires canceled by their context.",
		func() float64 { return float64(pool.Stat().CanceledAcquireCount()) })
	reg.Counter("wafio_db_pool_acquire_wait_seconds", "Total time acquires spent waiting for a connection.",
		func() float64 { return pool.Stat().EmptyAcquireWaitTime().Seconds() })
}

// startMetricsListener serves reg on WAFIO_METRICS_ADDR when it is set. The
// address must be a loopback IP literal (same rule as WAFIO_PPROF_ADDR); an
// invalid one fails startup. The returned close function is never nil.
func startMetricsListener(reg *metrics.Registry) (func(), error) {
	addr := os.Getenv(metrics.EnvAddr)
	if addr == "" {
		return func() {}, nil
	}
	ln, err := metrics.Listen(addr, nil)
	if err != nil {
		return nil, err
	}
	log.Printf("metrics (OpenMetrics) listening on %s/metrics", ln.Addr())
	return metrics.Serve(ln, reg, log.Printf), nil
}
