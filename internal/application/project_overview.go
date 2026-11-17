package application

// ProjectOverview computes the project Overview dashboard (moved from
// WAFAgentHandler.computeOverview in internal/adapter/http/handlers).

import (
	"context"
	"encoding/json"
	"log"
	"sync"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/dashboard"
	"github.com/wafio/wafio-cp-backend/internal/domain"
)

// ProjectOverview reads the Overview widgets through the domain ports. Geo
// is optional; without it the top-countries widget has no country codes.
type ProjectOverview struct {
	WAF      domain.WAFOverviewStore
	Hosts    domain.HostOverviewStore
	HostList domain.HostListStore
	Geo      domain.GeoEnricher
}

// OverviewWidget is the load state of one Overview widget.
type OverviewWidget struct {
	State   string `json:"state"`
	Message string `json:"message,omitempty"`
}

// OverviewResult is the GET /api/projects/:id/overview response.
type OverviewResult struct {
	WAFWindowStart      time.Time                 `json:"waf_window_start"`
	WAFWindowEnd        time.Time                 `json:"waf_window_end"`
	GeneratedAt         time.Time                 `json:"generated_at"`
	Widgets             map[string]OverviewWidget `json:"widgets"`
	WAFSummary          any                       `json:"waf_summary"`
	WAFSummaryPrev      any                       `json:"waf_summary_prev"`
	WAFTimeline         any                       `json:"waf_timeline"`
	WAFTopIPs           any                       `json:"waf_top_ips"`
	WAFTopCategories    any                       `json:"waf_top_categories"`
	WAFTopCountries     any                       `json:"waf_top_countries"`
	WAFAgents           any                       `json:"waf_agents"`
	HostAggStatus       any                       `json:"host_agg_status"`
	HostAggMetrics      any                       `json:"host_agg_metrics"`
	HostFWDropsWindowed int64                     `json:"host_fw_drops_windowed"`
	HostFWDropReasons   map[string]int64          `json:"host_fw_drop_reasons"`
	HostFirewallEvents  any                       `json:"host_firewall_events"`
	HostTraceStats      any                       `json:"host_trace_stats"`
	HostTraceEvents     any                       `json:"host_trace_events"`
	Hosts               any                       `json:"hosts"`
}

// Compute fetches all Overview widgets in parallel goroutines. A failed
// query marks its widget "unavailable"; Compute itself does not fail.
func (s *ProjectOverview) Compute(projectID, hostID, wafAgentID string, minutes, bucketSecs, limit int) (*OverviewResult, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	windowEnd := time.Now().UTC()
	ctx = domain.WithWAFWindowEnd(ctx, windowEnd)

	// Adaptive bucket size: avoid 8640-bucket GROUP BY for 30-day windows.
	if bucketSecs <= 0 || bucketSecs == 300 {
		switch {
		case minutes > 10080: // >7 days → 1-day buckets (max ~42)
			bucketSecs = 86400
		case minutes > 1440: // >1 day → 1-hour buckets (max 30)
			bucketSecs = 3600
		case minutes > 360: // >6 hours → 15-min buckets (max 96)
			bucketSecs = 900
		default:
			bucketSecs = 300
		}
	}

	// Resolve host agents once; reused by status, metrics, events goroutines.
	var hostAgents []domain.EBPFAgent
	var hostAgentsErr error
	if hostID != "" {
		// hostID reaches here from the request; scope it to the project or a
		// host id from another tenant resolves to that tenant's agent.
		hostAgents, hostAgentsErr = s.Hosts.ListNonWAFAgentsByHostInProject(ctx, hostID, projectID)
	} else {
		hostAgents, hostAgentsErr = s.Hosts.ListAgentsByProject(ctx, projectID)
	}
	hostAgentIDs := make([]string, len(hostAgents))
	for i, a := range hostAgents {
		hostAgentIDs[i] = a.ID
	}

	var (
		res OverviewResult
		mu  sync.Mutex
		wg  sync.WaitGroup
	)
	set := func(dst *any, v any) { mu.Lock(); *dst = v; mu.Unlock() }
	res.GeneratedAt = time.Now().UTC()
	res.WAFWindowEnd = windowEnd
	res.WAFWindowStart = windowEnd.Add(-time.Duration(minutes) * time.Minute)
	res.Widgets = make(map[string]OverviewWidget)
	status := func(key string, err error, empty bool) {
		value := OverviewWidget{State: "ok"}
		if err != nil {
			value = OverviewWidget{State: "unavailable", Message: "Data query failed"}
		} else if empty {
			value.State = "empty"
		}
		mu.Lock()
		res.Widgets[key] = value
		mu.Unlock()
	}

	// goTimed launches fn in a goroutine and logs if it exceeds 200ms.
	goTimed := func(name string, fn func()) {
		go func() {
			t0 := time.Now()
			fn()
			if elapsed := time.Since(t0); elapsed > 200*time.Millisecond {
				log.Printf("[overview-timing] %s took %s (minutes=%d)", name, elapsed.Round(time.Millisecond), minutes)
			}
		}()
	}

	wg.Add(11)

	goTimed("waf-summary", func() { // WAF summary: current + previous queries share fixed window boundaries
		defer wg.Done()
		cur, prev, err := s.WAF.SummarizeProjectBoth(ctx, projectID, wafAgentID, minutes, hostID)
		currentErr := err
		if cur != nil {
			currentErr = nil
		}
		status("waf_summary", currentErr, cur != nil && cur.Requests == 0)
		status("waf_summary_prev", err, prev != nil && prev.Requests == 0)
		if cur != nil {
			set(&res.WAFSummary, cur)
		}
		if prev != nil {
			set(&res.WAFSummaryPrev, prev)
		} else {
			set(&res.WAFSummaryPrev, map[string]any{})
		}
	})
	goTimed("waf-timeline", func() { // WAF timeline
		defer wg.Done()
		rows, err := s.WAF.TimelineForProject(ctx, projectID, wafAgentID, minutes, bucketSecs, hostID)
		status("waf_timeline", err, len(rows) == 0)
		if err == nil {
			set(&res.WAFTimeline, map[string]any{"buckets": rows})
		} else {
			set(&res.WAFTimeline, map[string]any{"buckets": []any{}})
		}
	})
	goTimed("waf-top-categories", func() { // WAF top categories
		defer wg.Done()
		rows, err := s.WAF.TopCategoriesForProject(ctx, projectID, wafAgentID, minutes, 5, hostID)
		status("waf_top_categories", err, len(rows) == 0)
		if err == nil {
			set(&res.WAFTopCategories, map[string]any{"dimension": "categories", "rows": rows})
		} else {
			set(&res.WAFTopCategories, map[string]any{"dimension": "categories", "rows": []any{}})
		}
	})
	goTimed("waf-top-ips-countries", func() { // WAF top countries (enrich top IPs with GeoIP); also sets WAFTopIPs from same query
		defer wg.Done()
		ips, err := s.WAF.TopIPsForProject(ctx, projectID, wafAgentID, minutes, 50, true, hostID)
		status("waf_top_ips", err, len(ips) == 0)
		status("waf_top_countries", err, len(ips) == 0)
		if err != nil || len(ips) == 0 {
			set(&res.WAFTopIPs, map[string]any{"dimension": "ips", "rows": []any{}})
			set(&res.WAFTopCountries, map[string]any{"dimension": "countries", "rows": []any{}})
			return
		}
		// Top-5 IPs directly from the same result (no extra query).
		top5 := ips
		if len(top5) > 5 {
			top5 = top5[:5]
		}
		set(&res.WAFTopIPs, map[string]any{"dimension": "ips", "rows": top5})

		rows := dashboard.SummarizeCountries(ips, func(ip string) string {
			if s.Geo == nil {
				return ""
			}
			_, country, _, _, _ := s.Geo.Enrich(ip)
			return country
		}, 10)
		set(&res.WAFTopCountries, map[string]any{"dimension": "countries", "rows": rows})
	})
	goTimed("waf-agents", func() { // WAF agents
		defer wg.Done()
		rows, err := s.Hosts.ListAgentsForUser(ctx, "", projectID, "waf")
		status("waf_agents", err, len(rows) == 0)
		if err == nil {
			set(&res.WAFAgents, map[string]any{"agents": rows, "count": len(rows)})
		} else {
			set(&res.WAFAgents, map[string]any{"agents": []any{}, "count": 0})
		}
	})
	goTimed("host-agg-status", func() { // Host aggregate status (reuses hostAgents from above, no extra PG query)
		defer wg.Done()
		const livenessWindow = 90 * time.Second
		statusMap, err := s.Hosts.BatchLatestStatus(ctx, hostAgentIDs)
		if hostAgentsErr != nil {
			err = hostAgentsErr
		}
		status("host_agg_status", err, len(statusMap) == 0)
		if err != nil {
			return
		}
		var online, fwRun, fwCap, trRun, trCap int
		for _, a := range hostAgents {
			isOnline := a.LastSeen != nil && time.Since(*a.LastSeen) <= livenessWindow
			var fw, tr bool
			if payload := statusMap[a.ID]; len(payload) > 0 {
				var wrapper map[string]json.RawMessage
				if json.Unmarshal(payload, &wrapper) == nil {
					if b, ok2 := wrapper["ebpf"]; ok2 {
						var o struct {
							Running bool `json:"running"`
						}
						if json.Unmarshal(b, &o) == nil && o.Running {
							fw = true
						}
					}
					if b, ok2 := wrapper["trace"]; ok2 {
						var o struct {
							Running bool `json:"running"`
						}
						if json.Unmarshal(b, &o) == nil && o.Running {
							tr = true
						}
					}
				}
			}
			if isOnline {
				online++
			}
			if fw {
				fwCap++
			}
			if tr {
				trCap++
			}
			if isOnline && fw {
				fwRun++
			}
			if isOnline && tr {
				trRun++
			}
		}
		set(&res.HostAggStatus, map[string]any{
			"total_agents":     len(hostAgents),
			"agents_online":    online,
			"firewall_running": fwRun,
			"firewall_capable": fwCap,
			"trace_running":    trRun,
			"trace_capable":    trCap,
		})
	})
	goTimed("host-agg-metrics", func() { // Host aggregate metrics
		defer wg.Done()
		m, err := s.Hosts.AggregateMetrics(ctx, hostAgentIDs)
		if hostAgentsErr != nil {
			err = hostAgentsErr
		}
		status("host_agg_metrics", err, len(hostAgentIDs) == 0)
		if err != nil {
			return
		}
		set(&res.HostAggMetrics, m)
	})
	goTimed("host-fw-drops", func() { // Host firewall drops + per-reason breakdown
		defer wg.Done()
		reasons, err := s.Hosts.FirewallDropsSummaryByMinutes(ctx, hostAgentIDs, minutes)
		if hostAgentsErr != nil {
			err = hostAgentsErr
		}
		status("host_fw_drops", err, len(reasons) == 0)
		if err != nil {
			return
		}
		if err != nil || reasons == nil {
			reasons = map[string]int64{}
		}
		var total int64
		for _, v := range reasons {
			total += v
		}
		mu.Lock()
		res.HostFWDropsWindowed = total
		res.HostFWDropReasons = reasons
		mu.Unlock()
	})
	goTimed("host-fw-events", func() { // Host firewall events
		defer wg.Done()
		events, err := s.Hosts.RecentEventsMulti(ctx, hostAgentIDs, limit)
		if hostAgentsErr != nil {
			err = hostAgentsErr
		}
		status("host_firewall_events", err, len(events) == 0)
		if err != nil || events == nil {
			events = []domain.EBPFEventRow{}
		}
		set(&res.HostFirewallEvents, map[string]any{"events": events, "count": len(events)})
	})
	goTimed("host-trace-stats", func() { // Host trace stats (time-windowed via host_security_events)
		defer wg.Done()
		payload, err := s.Hosts.AggregateTraceStatsSince(ctx, hostAgentIDs, minutes)
		if hostAgentsErr != nil {
			err = hostAgentsErr
		}
		status("host_trace_stats", err, len(hostAgentIDs) == 0)
		if err == nil {
			set(&res.HostTraceStats, json.RawMessage(payload))
		} else {
			set(&res.HostTraceStats, map[string]any{})
		}
	})
	goTimed("host-trace-events+hosts", func() { // Host trace events + hosts list
		defer wg.Done()
		var innerWg sync.WaitGroup
		innerWg.Add(2)
		go func() {
			defer innerWg.Done()
			events, err := s.Hosts.RecentTraceEventsMulti(ctx, hostAgentIDs, 3, limit)
			if hostAgentsErr != nil {
				err = hostAgentsErr
			}
			status("host_trace_events", err, len(events) == 0)
			if err != nil || events == nil {
				events = []domain.TraceEventRow{}
			}
			set(&res.HostTraceEvents, events)
		}()
		go func() {
			defer innerWg.Done()
			rows, err := s.HostList.ListByProject(ctx, projectID)
			status("hosts", err, len(rows) == 0)
			if err != nil || rows == nil {
				rows = []domain.Host{}
			}
			set(&res.Hosts, map[string]any{"hosts": rows, "count": len(rows)})
		}()
		innerWg.Wait()
	})

	wg.Wait()
	return &res, nil
}
