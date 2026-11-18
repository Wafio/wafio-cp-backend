package application

// HostTelemetryIngest stores the telemetry an eBPF host agent pushes, over
// the agent gRPC stream or the legacy HTTP ingest route (moved from
// internal/adapter/http/handlers/host_ingest.go).

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"sync"
	"time"

	gojson "github.com/goccy/go-json"
	"github.com/wafio/wafio-cp-backend/internal/domain"
)

// resyncInFlight prevents two heartbeats from triggering concurrent
// policy replays for the same agent.
var resyncInFlight sync.Map // map[string]struct{}

// HostTelemetryIngest writes one agent telemetry batch through the domain
// ports. Every store field is required. Policies is the live agent gRPC
// server; nil makes the trace-policy resync log a warning instead.
type HostTelemetryIngest struct {
	Telemetry    domain.HostTelemetryStore
	Hosts        domain.HostHeartbeatStore
	Rules        domain.TraceRuleStore
	Incidents    domain.IncidentStore
	FirewallHits domain.FirewallRuleHitMerger
	Policies     domain.TracePolicyPusher
	// ForwardFilters delivers trace forwarding filters to host agents: the live agent gRPC
	// server; nil (HTTP ingest) sends
	// none, so those agents send every event.
	ForwardFilters domain.TraceForwardFilterPusher

	// forward tracks which filter each agent should hold
	// (trace_forward_filter.go).
	forward traceForwardSync

	// hostTouch: host id → unix nanos of the last TouchHeartbeat from a
	// batch (hostHeartbeatTouchEvery).
	hostTouch sync.Map

	// repeats is the trace repeat cap's state (trace_repeat_cap.go); nil
	// uses the state every such service shares.
	repeats *traceRepeatCap

	// Test hooks replacing InsertTraceEvents / InsertEnforcementLog.
	traceAdmission       func(context.Context, string, []domain.TraceEventRow) error
	enforcementAdmission func(context.Context, string, []domain.EnforcementLogRow) error
}

// hostHeartbeatTouchEvery is how often telemetry batches mark their host
// seen (hosts.last_seen). Every batch used to, about one UPDATE a second per
// host while events flow; the offline sweep waits 90 s
// (repository.HostOfflineThreshold) and the stream heartbeat marks the host
// seen every 30 s as well.
const hostHeartbeatTouchEvery = 15 * time.Second

// claimHostTouch reports whether a batch at now marks hostID seen (none in
// the last hostHeartbeatTouchEvery) and the claim it recorded.
func (s *HostTelemetryIngest) claimHostTouch(hostID string, now time.Time) (int64, bool) {
	n := now.UnixNano()
	for {
		v, loaded := s.hostTouch.LoadOrStore(hostID, n)
		if !loaded {
			return n, true
		}
		last := v.(int64)
		if n-last < int64(hostHeartbeatTouchEvery) {
			return 0, false
		}
		if s.hostTouch.CompareAndSwap(hostID, last, n) {
			return n, true
		}
	}
}

// PreparedHostTelemetry keeps the original bytes for retry identity while
// letting v2 receipt handling reuse the decoded fields.
type PreparedHostTelemetry struct {
	svc  *HostTelemetryIngest
	data HostTelemetryPayload
	body []byte
}

func (p *PreparedHostTelemetry) BatchID() string { return p.data.BatchID }

func (p *PreparedHostTelemetry) Ingest(ctx context.Context, projectID, agentID, hostID string) error {
	return p.svc.ingestWithBody(ctx, projectID, agentID, hostID, &p.data, p.body)
}

// Prepare decodes a host telemetry batch once and retains its exact bytes for
// idempotency checks in storage.
func (s *HostTelemetryIngest) Prepare(payloadJSON []byte) (*PreparedHostTelemetry, error) {
	var p HostTelemetryPayload
	if err := gojson.Unmarshal(payloadJSON, &p); err != nil {
		return nil, fmt.Errorf("decode payload: %w", err)
	}
	return &PreparedHostTelemetry{svc: s, data: p, body: payloadJSON}, nil
}

// IngestJSON stores eBPF telemetry received as raw JSON (the agent gRPC
// path). hostID may be empty when the agent is not host-scoped.
func (s *HostTelemetryIngest) IngestJSON(ctx context.Context, projectID, agentID, hostID string, payloadJSON []byte) error {
	prepared, err := s.Prepare(payloadJSON)
	if err != nil {
		return err
	}
	return prepared.Ingest(ctx, projectID, agentID, hostID)
}

// IngestDecoded stores a batch the HTTP route already decoded; the canonical
// JSON re-encoding is its identity for batch retries.
func (s *HostTelemetryIngest) IngestDecoded(ctx context.Context, projectID, agentID, hostID string, p *HostTelemetryPayload) error {
	body, _ := gojson.Marshal(p)
	return s.ingestWithBody(ctx, projectID, agentID, hostID, p, body)
}

// HostTelemetryPayload mirrors the agent's PushPayload.
type HostTelemetryPayload struct {
	BatchID               string               `json:"batch_id,omitempty"`
	TelemetryDelivery     json.RawMessage      `json:"telemetry_delivery,omitempty"`
	TelemetrySendFailures uint64               `json:"telemetry_send_failures,omitempty"`
	HostInfo              *AgentHostInfo       `json:"host_info,omitempty"`
	EBPFStatus            json.RawMessage      `json:"ebpf_status,omitempty"`
	TraceStatus           json.RawMessage      `json:"trace_status,omitempty"`
	Metrics               json.RawMessage      `json:"metrics,omitempty"`
	Events                []eventPayload       `json:"events,omitempty"`
	Connections           []connPayload        `json:"connections,omitempty"`
	Bandwidth             []bwPayload          `json:"bandwidth,omitempty"`
	TraceEvents           []TraceEventPayload  `json:"trace_events,omitempty"`
	TraceStats            json.RawMessage      `json:"trace_stats,omitempty"`
	Enforcement           []enforcementPayload `json:"enforcement,omitempty"`
	// RuleStats carries live BPF hit counts reported by the agent every 3s.
	RuleStats *domain.HostRuleStats `json:"rule_stats,omitempty"`
	// TraceForward: the forwarding filter state of an agent that handles
	// domain.TraceForwardFilterCommandID; absent from older
	// agents and on the HTTP push path.
	TraceForward *TraceForwardReport `json:"trace_forward,omitempty"`
}

// AgentHostInfo mirrors agentcore.HostInfo (shared/agentcore). Kept local so the
// control plane doesn't depend on the agent package.
type AgentHostInfo struct {
	Hostname     string  `json:"hostname"`
	OS           string  `json:"os"`
	OSVersion    string  `json:"os_version"`
	KernelName   string  `json:"kernel_name"`
	KernelRel    string  `json:"kernel_release"`
	Arch         string  `json:"arch"`
	CPUCount     int     `json:"cpu_count"`
	CPUModel     string  `json:"cpu_model,omitempty"`
	CPUMHz       float64 `json:"cpu_mhz,omitempty"`
	MemoryTotal  uint64  `json:"memory_total_bytes"`
	MemoryUsed   uint64  `json:"memory_used_bytes,omitempty"`
	MemoryFree   uint64  `json:"memory_free_bytes,omitempty"`
	LoadAvg1     float64 `json:"load_avg_1,omitempty"`
	LoadAvg5     float64 `json:"load_avg_5,omitempty"`
	LoadAvg15    float64 `json:"load_avg_15,omitempty"`
	UptimeSec    int64   `json:"uptime_seconds"`
	BootTime     int64   `json:"boot_time"`
	AgentVersion string  `json:"agent_version"`
	AgentKind    string  `json:"agent_kind"`
	Distro       string  `json:"distro,omitempty"`
	VirtType     string  `json:"virt_type,omitempty"`

	Timezone         string `json:"timezone,omitempty"`
	PrimaryIP        string `json:"primary_ip,omitempty"`
	PrimaryInterface string `json:"primary_interface,omitempty"`
	SELinuxMode      string `json:"selinux_mode,omitempty"`
	AppArmor         string `json:"apparmor,omitempty"`
	ContainerRuntime string `json:"container_runtime,omitempty"`
	DiskTotalBytes   uint64 `json:"disk_total_bytes,omitempty"`
	DiskFreeBytes    uint64 `json:"disk_free_bytes,omitempty"`

	// raw is the object as the agent sent it. agents.host_info stores it
	// unchanged: the fields above only feed the denormalised columns, and
	// re-encoding them dropped every key this mirror lacks — ssh_ports
	// (firewall lockout guard) and firewall_features (geo allow,
	// allowlist_ports) — each telemetry push overwriting the heartbeat's copy.
	raw json.RawMessage
}

// UnmarshalJSON decodes the mirrored fields and keeps the original object.
func (h *AgentHostInfo) UnmarshalJSON(b []byte) error {
	type plain AgentHostInfo
	var p plain
	if err := json.Unmarshal(b, &p); err != nil {
		return err
	}
	*h = AgentHostInfo(p)
	h.raw = append(json.RawMessage(nil), b...)
	return nil
}

// StoredJSON is the host_info object to persist: the agent's own bytes when
// decoded from JSON, else the mirrored fields.
func (h *AgentHostInfo) StoredJSON() []byte {
	if len(h.raw) > 0 {
		return h.raw
	}
	b, _ := json.Marshal(h)
	return b
}

// ingestWithBody stores the decoded telemetry, using body for retry identity.
func (s *HostTelemetryIngest) ingestWithBody(ctx context.Context, projectID, agentID, hostID string, p *HostTelemetryPayload, body []byte) error {
	progress, release, err := s.Telemetry.BeginTelemetryBatch(ctx, projectID, agentID, p.BatchID, body)
	if err != nil {
		return err
	}
	defer release()
	var lastErr error

	// ── Resolve host_id if not provided (gRPC path without --host-key) ──
	// When the agent connects via mTLS gRPC without a host key, hostID is
	// populated from the agents.host_id DB column by validateHello. But for
	// older code paths or race conditions where it's still empty, look it up
	// here so TouchHeartbeat always runs.
	if hostID == "" && agentID != "" {
		hostID = s.Telemetry.GetAgentHostID(ctx, agentID)
	}

	// ── Touch host heartbeat — keeps status=online in the UI ──
	// The first batch after a connect (or after a quiet spell) marks the
	// host seen, so its card turns green at once even without an explicit
	// host-key handshake; later batches at most every hostHeartbeatTouchEvery.
	if hostID != "" {
		if at, ok := s.claimHostTouch(hostID, time.Now()); ok {
			if err := s.Hosts.TouchHeartbeat(ctx, projectID, hostID); err != nil {
				s.hostTouch.CompareAndDelete(hostID, at) // retry on the next batch
				log.Printf("[ingest] host heartbeat error: %v", err)
			}
		}
	}

	// ── Host info ──
	if p.HostInfo != nil {
		row := domain.AgentHostInfoRow{
			Raw:         p.HostInfo.StoredJSON(),
			Hostname:    p.HostInfo.Hostname,
			OS:          p.HostInfo.OS,
			OSVersion:   p.HostInfo.OSVersion,
			Kernel:      p.HostInfo.KernelRel,
			Arch:        p.HostInfo.Arch,
			CPUCount:    p.HostInfo.CPUCount,
			MemoryTotal: int64(p.HostInfo.MemoryTotal),
			VirtType:    p.HostInfo.VirtType,
			Version:     p.HostInfo.AgentVersion,
			Kind:        p.HostInfo.AgentKind,
			BootUnix:    p.HostInfo.BootTime,
		}
		if err := s.Telemetry.UpdateAgentHostInfo(ctx, projectID, agentID, row); err != nil {
			log.Printf("[ingest] host info update error: %v", err)
		}
		// Propagate to parent host row whenever host_id is known (covers both
		// HTTP host-key path and gRPC mTLS path resolved above).
		if hostID != "" {
			if err := s.Hosts.UpdateHostInfo(ctx, projectID, hostID, row); err != nil {
				log.Printf("[ingest] host row host_info update error: %v", err)
			}
		}
	}

	// ── Status ──
	if len(p.EBPFStatus) > 0 || len(p.TraceStatus) > 0 {
		combined := make(map[string]json.RawMessage)
		if len(p.EBPFStatus) > 0 {
			combined["ebpf"] = withTelemetryDelivery(p.EBPFStatus, p.TelemetryDelivery, p.TelemetrySendFailures)
		}
		if len(p.TraceStatus) > 0 {
			combined["trace"] = withTelemetryDelivery(p.TraceStatus, p.TelemetryDelivery, p.TelemetrySendFailures)
		}
		b, _ := json.Marshal(combined)
		if err := s.Telemetry.InsertStatus(ctx, projectID, agentID, b); err != nil {
			lastErr = err
			log.Printf("[ingest] status insert error: %v", err)
		}

		// Auto-resync: if the agent reports fewer loaded policies than the
		// server has persisted, replay each persisted policy to the agent.
		// This recovers the in-memory PolicyEngine after an agent restart
		// (BPF objects are pinned and survive, but PolicyEngine is not).
		if len(p.TraceStatus) > 0 {
			s.maybeResyncPolicies(agentID, p.TraceStatus)
		}
	}

	// ── Metrics ──
	if len(p.Metrics) > 0 {
		var m metricsPayload
		if err := json.Unmarshal(p.Metrics, &m); err == nil {
			row := &domain.EBPFMetricsRow{
				RxPackets:           m.RxPackets,
				RxBytes:             m.RxBytes,
				TxPackets:           m.TxPackets,
				TxBytes:             m.TxBytes,
				DroppedPackets:      m.DroppedPackets,
				DroppedBytes:        m.DroppedBytes,
				WouldDropPackets:    m.WouldDropPackets,
				WouldDropBytes:      m.WouldDropBytes,
				StateTableFull:      m.StateTableFull,
				PacketParseFailures: m.PacketParseFailures,
				RatelimitedPackets:  m.RatelimitedPackets,
				SynfloodDrops:       m.SynfloodDrops,
				BlocklistDrops:      m.BlocklistDrops,
				AllowlistPasses:     m.AllowlistPasses,
				GeoblockDrops:       m.GeoblockDrops,
				ConntrackEntries:    m.ConntrackEntries,
				PortScanDrops:       m.PortScanDrops,
				PortPolicyDrops:     m.PortPolicyDrops,
				EgressIPDrops:       m.EgressIPDrops,
				PPS:                 int64(m.PPS + 0.5),
				BPS:                 int64(m.BPS + 0.5),
				DropRatePct:         m.DropRatePct,
			}
			if err := s.Telemetry.InsertMetrics(ctx, projectID, agentID, row); err != nil {
				lastErr = err
				log.Printf("[ingest] metrics insert error: %v", err)
			}
		}
	}

	// ── Events ──
	if len(p.Events) > 0 && !progress.Done("firewall") {
		var rows []domain.EBPFEventRow
		for i := range p.Events {
			e := &p.Events[i]
			ts, _ := time.Parse(time.RFC3339Nano, e.Timestamp)
			rows = append(rows, domain.EBPFEventRow{
				SrcIP:     e.SrcIP,
				DstIP:     e.DstIP,
				SrcPort:   e.SrcPort,
				DstPort:   e.DstPort,
				Proto:     e.Proto,
				Action:    e.Action,
				Reason:    e.Reason,
				TCPFlags:  e.TCPFlags,
				PktLen:    e.PktLen,
				RuleID:    e.RuleID,
				EventTime: ts,
			})
		}
		if err := s.Telemetry.InsertEvents(ctx, agentID, rows); err != nil {
			lastErr = err
			log.Printf("[ingest] events insert error (%d): %v", len(rows), err)
		} else {
			progress.Mark("firewall")
		}
	}

	// ── Connections ──
	if len(p.Connections) > 0 {
		var rows []domain.EBPFConnectionRow
		for i := range p.Connections {
			c := &p.Connections[i]
			fs, _ := time.Parse(time.RFC3339Nano, c.FirstSeen)
			ls, _ := time.Parse(time.RFC3339Nano, c.LastSeen)
			rows = append(rows, domain.EBPFConnectionRow{
				SrcIP:     c.SrcIP,
				DstIP:     c.DstIP,
				SrcPort:   c.SrcPort,
				DstPort:   c.DstPort,
				Proto:     c.Proto,
				State:     c.State,
				FirstSeen: fs,
				LastSeen:  ls,
				Packets:   c.Packets,
				Bytes:     c.Bytes,
			})
		}
		if err := s.Telemetry.InsertConnections(ctx, agentID, rows); err != nil {
			lastErr = err
			log.Printf("[ingest] connections insert error: %v", err)
		}
	}

	// ── Bandwidth ──
	if len(p.Bandwidth) > 0 {
		var rows []domain.EBPFBandwidthRow
		for i := range p.Bandwidth {
			b := &p.Bandwidth[i]
			rows = append(rows, domain.EBPFBandwidthRow{
				IP:             b.IP,
				IngressBytes:   b.IngressBytes,
				EgressBytes:    b.EgressBytes,
				IngressPackets: b.IngressPackets,
				EgressPackets:  b.EgressPackets,
				IngressBPS:     b.IngressBPS,
				EgressBPS:      b.EgressBPS,
			})
		}
		if err := s.Telemetry.InsertBandwidth(ctx, agentID, rows); err != nil {
			lastErr = err
			log.Printf("[ingest] bandwidth insert error: %v", err)
		}
	}

	// ── Trace events ──
	// Filter noise: always keep process and security events (they are
	// infrequent and diagnostically important). For file/network events,
	// only keep severity >= medium (2) or enforced (action != 0).
	// info=0, low=1, medium=2, high=3, critical=4; action monitor=0.
	//
	// A host agent with a forwarding filter does not send the
	// events this loop would discard with no effect, and reports the rule
	// hits they carried (p.TraceForward). Any new use of an event in this
	// loop before storeTraceEvent, or a change to what decides it, must be
	// reflected in TraceForwardFilter.decide with a TraceForwardRevision
	// bump.
	//
	// Detection rules are loaded once for the whole batch (30s cached).
	traceProjectID, traceHostID := "", ""
	var detectionRules []domain.DetectionRule
	var detectionRulesErr error
	traceRulesLoaded := false
	loadTraceRules := func() {
		if traceRulesLoaded {
			return
		}
		traceRulesLoaded = true
		traceProjectID = s.Telemetry.GetAgentProjectID(ctx, agentID)
		traceHostID = s.Telemetry.GetAgentHostID(ctx, agentID)
		if traceProjectID != "" && traceHostID != "" {
			detectionRules, detectionRulesErr = s.Rules.ListRules(ctx, traceProjectID, traceHostID)
		}
	}
	forwardHits := p.TraceForward != nil && len(p.TraceForward.RuleHits) > 0
	if (len(p.TraceEvents) > 0 || forwardHits) && !progress.Done("trace") {
		loadTraceRules()
		projectID := traceProjectID
		evaluator := NewTraceRuleEvaluator(detectionRules)

		var rows []domain.TraceEventRow
		// ruleIDs[i] is the detection rule that matched rows[i], for the repeat cap.
		var ruleIDs []string
		// incident candidates aggregated per "technique\x00comm" for this batch
		type incAgg struct {
			technique, tactic, comm, sevName, sample string
			severity                                 int
			count                                    int64
		}
		incCandidates := map[string]*incAgg{}
		detectionHits := map[string]int{}
		// Hits of the events the agent's filter dropped.
		for id, n := range forwardedRuleHits(p.TraceForward, evaluator) {
			detectionHits[id] += n
		}
		for i := range p.TraceEvents {
			t := &p.TraceEvents[i]
			preRuleSeverity := t.Severity
			matched := ""
			if !t.OutcomeUpdate {
				// Phases 0-2: paths, lineage context, detection rules.
				suppressed, matchedID, pre := ClassifyTraceEvent(t, evaluator)
				preRuleSeverity = pre
				matched = matchedID
				if suppressed {
					if matchedID != "" {
						if !t.OutcomeUpdate {
							detectionHits[matchedID]++
						}
					}
					continue // event suppressed by rule
				} else if matchedID != "" {
					if !t.OutcomeUpdate {
						detectionHits[matchedID]++
					}
				}

				// Multi-stage temporal correlation:
				// a completed attack chain escalates this event to CRITICAL
				// so the incident surfaces as an active compromise.
				tsC, _ := time.Parse(time.RFC3339Nano, t.Timestamp)
				if completed := Correlations().EvaluateRules(projectID, toCorrelationEvent(t, tsC)); len(completed) > 0 {
					applyCorrelation(t, completed)
				}
			}
			if !storeTraceEvent(t, preRuleSeverity) {
				continue // drop info/low file/network noise
			}
			ts, _ := time.Parse(time.RFC3339Nano, t.Timestamp)
			rows = append(rows, domain.TraceEventRow{
				PID:          t.PID,
				TID:          t.TID,
				PPID:         t.PPID,
				UID:          t.UID,
				GID:          t.GID,
				EventType:    t.EventType,
				EventName:    t.EventName,
				Category:     t.Category,
				Severity:     t.Severity,
				SeverityName: t.SeverityName,
				Comm:         t.Comm,
				Filename:     t.Filename,
				Args:         t.Args,
				Flags:        t.Flags,
				RetVal:       t.RetVal,
				Detail:       t.Detail,
				Port:         t.Port,
				AddrFamily:   t.AddrFamily,
				Addr:         t.Addr,
				Description:  t.Description,
				Action:       t.Action,
				ActionName:   t.ActionName,
				EventID:      t.EventID, OutcomeUpdate: t.OutcomeUpdate, SignalOutcome: t.SignalOutcome, SignalError: t.SignalError, ActivityOutcome: t.ActivityOutcome, ProcessStartNS: t.ProcessStartNS,
				PolicyID:        t.PolicyID,
				EventTime:       ts,
				ParentComm:      t.ParentComm,
				GrandparentComm: t.GrandparentComm,
				ContainerID:     t.ContainerID,
				ContainerImage:  t.ContainerImage,
				ContainerName:   t.ContainerName,
				IsContainer:     t.IsContainer,
				IsPrivileged:    t.IsPrivileged,
				K8sPod:          t.K8sPod,
				K8sNamespace:    t.K8sNamespace,
			})
			ruleIDs = append(ruleIDs, matched)
			if t.Severity >= 3 && !t.OutcomeUpdate { // only initial event creates incident
				tech, tac := incidentMITRE(t)
				key := tech + "\x00" + t.Comm
				ag := incCandidates[key]
				if ag == nil {
					ag = &incAgg{technique: tech, tactic: tac, comm: t.Comm,
						severity: t.Severity, sevName: t.SeverityName, sample: t.Description}
					incCandidates[key] = ag
				}
				ag.count++
				if t.Severity > ag.severity {
					ag.severity = t.Severity
					ag.sevName = t.SeverityName
					ag.sample = t.Description
				}
			}
		}
		// Rule hits and incidents above counted every event; the repeat cap
		// bounds only what is stored.
		repeat := s.repeatCap().begin(agentID, len(rows) > 0)
		defer repeat.finish(false)
		rows = repeat.apply(rows, ruleIDs)
		traceErr := s.admitTrace(ctx, agentID, rows)
		repeat.finish(traceErr == nil)
		if traceErr != nil {
			lastErr = traceErr
			log.Printf("[ingest] trace events admission failed")
		}
		// Upsert incidents for high/critical events (best-effort; never fail
		// telemetry storage on incident errors).
		if traceErr == nil {
			s.Rules.IncrementHitCounts(ctx, projectID, detectionHits)
			if projectID != "" {
				for _, ag := range incCandidates {
					inc := domain.HostIncident{
						ProjectID: projectID, AgentID: agentID,
						TechniqueID: ag.technique, Tactic: ag.tactic, Comm: ag.comm,
						Severity: ag.severity, SeverityName: ag.sevName, SampleDesc: ag.sample,
					}
					if err := s.Incidents.Upsert(ctx, inc, ag.count); err != nil {
						log.Printf("[ingest] incident upsert error (tech=%s comm=%s): %v", ag.technique, ag.comm, err)
					}
				}
			}
			progress.Mark("trace")
		}
	} else if len(p.TraceEvents) == 0 && !forwardHits {
		// An idle agent's status batch still closes the windows that ended.
		s.flushTraceRepeats(ctx, agentID)
	}

	// ── Trace forwarding filter ──
	if p.TraceForward != nil && s.ForwardFilters != nil {
		loadTraceRules()
		if detectionRulesErr == nil { // never a filter built from a failed read
			s.syncTraceForwardFilter(projectID, agentID, traceProjectID, traceHostID, detectionRules, p.TraceForward.Digest)
		}
	}

	// ── Trace stats ──
	if len(p.TraceStats) > 0 {
		if err := s.Telemetry.InsertTraceStats(ctx, projectID, agentID, p.TraceStats); err != nil {
			lastErr = err
			log.Printf("[ingest] trace stats insert error: %v", err)
		}
	}

	// ── Enforcement log ──
	if len(p.Enforcement) > 0 && !progress.Done("enforcement") {
		var rows []domain.EnforcementLogRow
		type policyHit struct {
			name  string
			delta int64
		}
		hitIncr := make(map[int]*policyHit)
		for i := range p.Enforcement {
			e := &p.Enforcement[i]
			ts, _ := time.Parse(time.RFC3339Nano, e.Timestamp)
			evtData, _ := gojson.Marshal(e.Event)
			mode := e.Mode
			if mode == "" {
				mode = "userspace"
			}
			rows = append(rows, domain.EnforcementLogRow{
				PolicyID:      e.PolicyID,
				PolicyName:    e.PolicyName,
				Action:        e.Action,
				Success:       e.Success,
				Mode:          mode,
				FailureReason: e.FailureReason,
				EventData:     evtData,
				EventTime:     ts,
				// MITRE denormalization — empty strings are fine, the
				// repo stores them and the UI treats empty as "n/a".
				MITRETechniqueID:   e.MITRETechniqueID,
				MITRETechniqueName: e.MITRETechniqueName,
				MITRETactic:        e.MITRETactic,
				Severity:           e.Severity,
				Tags:               e.Tags,
			})
			if e.PolicyID > 0 && e.Mode != "deferred_outcome" {
				if h := hitIncr[e.PolicyID]; h == nil {
					hitIncr[e.PolicyID] = &policyHit{name: e.PolicyName, delta: 1}
				} else {
					h.delta++
				}
			}
		}
		enforcementErr := s.admitEnforcement(ctx, agentID, rows)
		if enforcementErr != nil {
			lastErr = enforcementErr
			log.Printf("[ingest] enforcement admission failed")
		}
		// Persist hit counts into ebpf_trace_policies so the UI shows live totals.
		// Policy IDs are agent-assigned and can change across restarts, so we try
		// to match by policy_id first and fall back to name-based matching which
		// also resyncs the policy_id column for future lookups.
		if enforcementErr == nil {
			for pid, hit := range hitIncr {
				if err := s.Telemetry.IncrementTracePolicyHitCount(ctx, agentID, pid, hit.name, hit.delta); err != nil {
					log.Printf("[ingest] trace policy hit count increment error: %v", err)
				}
			}
			progress.Mark("enforcement")
		}
	}

	// ── Rule hit counts ──
	if p.RuleStats != nil {
		s.updateRuleHitCounts(ctx, projectID, agentID, p.RuleStats)
	}

	return lastErr
}

// updateRuleHitCounts merges live BPF hit counts from the agent into the
// persisted desired state so the UI can display them. It only updates the DB;
// it does NOT push a new state bundle to the agent (hit counts don't need to
// round-trip through the agent — the BPF pre-Lookup in Add* functions ensures
// the live counter is preserved across desired-state syncs).
func (s *HostTelemetryIngest) updateRuleHitCounts(ctx context.Context, projectID, agentID string, stats *domain.HostRuleStats) {
	// The firewall desired state is merged by its owner; an unreadable or
	// unencodable state stops here, as it always has.
	if s.FirewallHits == nil {
		return
	}
	if err := s.FirewallHits.MergeFirewallRuleHits(ctx, projectID, agentID, stats); err != nil {
		return
	}

	// Update trace policy hit counts separately (stored in ebpf_trace_policies table).
	// This runs independently of whether the EBPF desired state changed.
	if len(stats.TracePolicies) > 0 {
		hitMap := make(map[uint32]uint64, len(stats.TracePolicies))
		for _, tp := range stats.TracePolicies {
			if tp.HitCount > 0 {
				hitMap[tp.PolicyID] = tp.HitCount
			}
		}
		if len(hitMap) > 0 {
			if err := s.Telemetry.UpdateTracePolicyHitCounts(ctx, agentID, hitMap); err != nil {
				log.Printf("[ingest] trace policy hit count update error: %v", err)
			}
		}
	}
}

// ── Payload types (match agent-side JSON) ───────────────────────────────────

// metricsPayload accepts the JSON shape emitted by the agent. The agent
// computes PPS/BPS/DropRate as float64 derivatives; we accept float here
// and round to int when writing into bigint columns. Using int64 here would
// cause json.Unmarshal to fail whenever the agent sends a fractional rate,
// silently dropping every subsequent metrics snapshot.
type metricsPayload struct {
	RxPackets           int64   `json:"rx_packets"`
	RxBytes             int64   `json:"rx_bytes"`
	TxPackets           int64   `json:"tx_packets"`
	TxBytes             int64   `json:"tx_bytes"`
	DroppedPackets      int64   `json:"dropped_packets"`
	DroppedBytes        int64   `json:"dropped_bytes"`
	WouldDropPackets    int64   `json:"would_drop_packets"`
	WouldDropBytes      int64   `json:"would_drop_bytes"`
	StateTableFull      int64   `json:"state_table_full"`
	PacketParseFailures int64   `json:"packet_parse_failures"`
	RatelimitedPackets  int64   `json:"ratelimited_packets"`
	SynfloodDrops       int64   `json:"synflood_drops"`
	BlocklistDrops      int64   `json:"blocklist_drops"`
	AllowlistPasses     int64   `json:"allowlist_passes"`
	GeoblockDrops       int64   `json:"geoblock_drops"`
	ConntrackEntries    int     `json:"conntrack_entries"`
	PortScanDrops       int64   `json:"port_scan_drops"`
	PortPolicyDrops     int64   `json:"port_policy_drops"`
	EgressIPDrops       int64   `json:"egress_ip_drops"`
	PPS                 float64 `json:"pps"`
	BPS                 float64 `json:"bps"`
	DropRatePct         float32 `json:"drop_rate_pct"`
}

type eventPayload struct {
	Timestamp string `json:"timestamp"`
	SrcIP     string `json:"src_ip"`
	DstIP     string `json:"dst_ip"`
	SrcPort   int    `json:"src_port"`
	DstPort   int    `json:"dst_port"`
	Proto     string `json:"proto"`
	Action    string `json:"action"`
	Reason    string `json:"reason"`
	TCPFlags  string `json:"tcp_flags"`
	PktLen    int    `json:"pkt_len"`
	RuleID    int    `json:"rule_id"`
}

type connPayload struct {
	SrcIP     string `json:"src_ip"`
	DstIP     string `json:"dst_ip"`
	SrcPort   int    `json:"src_port"`
	DstPort   int    `json:"dst_port"`
	Proto     string `json:"proto"`
	State     string `json:"state"`
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
	Packets   int64  `json:"packets"`
	Bytes     int64  `json:"bytes"`
}

type bwPayload struct {
	IP             string `json:"ip"`
	IngressBytes   int64  `json:"ingress_bytes"`
	EgressBytes    int64  `json:"egress_bytes"`
	IngressPackets int64  `json:"ingress_packets"`
	EgressPackets  int64  `json:"egress_packets"`
	IngressBPS     int64  `json:"ingress_bps"`
	EgressBPS      int64  `json:"egress_bps"`
}

// applyCorrelation escalates an event that completed correlation chains to
// CRITICAL, names the chains in its description and records the first
// chain's MITRE attribution for the incident it opens.
func applyCorrelation(t *TraceEventPayload, completed []*CorrelationRule) {
	if t.Severity < 4 {
		t.Severity = 4
		t.SeverityName = "critical"
	}
	labels := make([]string, len(completed))
	for i, r := range completed {
		labels[i] = r.Label()
		if technique, _ := t.Correlation(); technique == "" && r.Technique != "" {
			t.SetCorrelation(r.Technique, r.Tactic)
		}
	}
	t.Description += " [correlation:" + strings.Join(labels, ",") + "]"
}

// incidentMITRE is the technique/tactic an event's incident groups under: a
// completed chain's attribution, else the event type's mapping.
func incidentMITRE(t *TraceEventPayload) (technique, tactic string) {
	if technique, tactic := t.Correlation(); technique != "" {
		return technique, tactic
	}
	return mitreForEvent(t.EventName)
}

type enforcementPayload struct {
	Timestamp     string          `json:"timestamp"`
	PolicyID      int             `json:"policy_id"`
	PolicyName    string          `json:"policy_name"`
	Action        string          `json:"action"`
	Success       bool            `json:"success"`
	Mode          string          `json:"mode"`
	FailureReason string          `json:"failure_reason"`
	Event         json.RawMessage `json:"event"`

	// MITRE ATT&CK attribution (optional — older agents don't send these).
	// The manager stamps these onto each enforcement record at match time so
	// that downstream SIEM/XDR tools can filter by technique without needing
	// to join against the in-agent policy store.
	MITRETechniqueID   string          `json:"mitre_technique_id,omitempty"`
	MITRETechniqueName string          `json:"mitre_technique_name,omitempty"`
	MITRETactic        string          `json:"mitre_tactic,omitempty"`
	Severity           string          `json:"severity,omitempty"`
	Tags               json.RawMessage `json:"tags,omitempty"`
}

// ── Policy auto-resync ──────────────────────────────────────────────────────

// maybeResyncPolicies pushes every persisted Runtime Security policy back to
// the agent when the agent reports a smaller loaded count than the server
// has on record. Triggered on every heartbeat that carries a trace_status
// snapshot, so the recovery happens within one push interval (~1s) of an
// agent restart.
//
// The replay is best-effort and runs in a background goroutine so the
// ingest path never blocks on the agent's local API.
func (s *HostTelemetryIngest) maybeResyncPolicies(agentID string, traceStatus json.RawMessage) {
	var ts struct {
		PoliciesTotal int `json:"policies_total"`
	}
	if err := json.Unmarshal(traceStatus, &ts); err != nil {
		return
	}

	if _, busy := resyncInFlight.LoadOrStore(agentID, struct{}{}); busy {
		return
	}
	go func() {
		defer resyncInFlight.Delete(agentID)
		s.resyncPolicies(agentID, ts.PoliciesTotal)
	}()
}

func (s *HostTelemetryIngest) resyncPolicies(agentID string, agentLoaded int) {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	stored, err := s.Telemetry.CountTracePolicies(ctx, agentID)
	if err != nil {
		log.Printf("[trace policy resync] count failed: %v", err)
		return
	}
	// Resync when agent has fewer policies than DB (covers both restart=0
	// and the case where new policies were added while agent was connected).
	if stored == 0 || agentLoaded >= stored {
		return
	}

	// Resolve project_id for this agent (needed by PushTracePoliciesViaGRPC).
	agent, aerr := s.Telemetry.GetAgentByID(ctx, agentID)
	if aerr != nil || agent == nil {
		log.Printf("[trace policy resync] agent lookup failed: %v", aerr)
		return
	}

	// Use gRPC bundle push — no HTTP callback needed.
	if s.Policies != nil {
		log.Printf("[trace policy resync] pushing %d policies to agent=%s via gRPC", stored-agentLoaded, agentID)
		s.Policies.PushTracePoliciesViaGRPC(agentID, agent.ProjectID)
		return
	}

	log.Printf("[trace policy resync] no gRPC server available for agent=%s", agentID)
}

// Delivery snapshots describe the agent memory queue, never a database commit.
func withTelemetryDelivery(status, delivery json.RawMessage, sendFailures uint64) json.RawMessage {
	if len(delivery) == 0 {
		return status
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(status, &fields) != nil || fields == nil {
		return status
	}
	fields["telemetry_delivery"] = delivery
	fields["telemetry_send_failures"], _ = json.Marshal(sendFailures)
	out, err := json.Marshal(fields)
	if err != nil {
		return status
	}
	return out
}

func (s *HostTelemetryIngest) admitTrace(ctx context.Context, agentID string, rows []domain.TraceEventRow) error {
	if s.traceAdmission != nil {
		return s.traceAdmission(ctx, agentID, rows)
	}
	return s.Telemetry.InsertTraceEvents(ctx, agentID, rows)
}

// flushTraceRepeats stores the summaries of windows that ended for an agent
// whose batch carries no trace events. A failed store is retried by the next
// batch and never fails this one.
func (s *HostTelemetryIngest) flushTraceRepeats(ctx context.Context, agentID string) {
	repeat := s.repeatCap().begin(agentID, false)
	defer repeat.finish(false)
	rows := repeat.apply(nil, nil)
	var err error
	if len(rows) > 0 {
		err = s.admitTrace(ctx, agentID, rows)
	}
	repeat.finish(err == nil)
	if err != nil {
		log.Printf("[ingest] trace repeat summary admission failed")
	}
}

func (s *HostTelemetryIngest) admitEnforcement(ctx context.Context, agentID string, rows []domain.EnforcementLogRow) error {
	if s.enforcementAdmission != nil {
		return s.enforcementAdmission(ctx, agentID, rows)
	}
	return s.Telemetry.InsertEnforcementLog(ctx, agentID, rows)
}
