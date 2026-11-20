// Package agentserver implements the bidirectional gRPC stream between the
// control plane and each running WAF agent. It replaces the legacy model
// where agents listened on :18090 and the server called back over HTTP.
//
// Authentication: mTLS only. The client cert's SHA-256 fingerprint is
// looked up in mtls_credentials (purpose='agent_grpc') to resolve the
// project_id. There is no second auth layer — owning a valid client cert
// (signed by the wafio agent CA) is sufficient.
//
// Lifecycle:
//
//  1. agent dials with client cert
//  2. server's TLS handler verifies cert via ClientCAs pool
//  3. unary auth interceptor extracts the cert, looks up project_id,
//     and stores it in the request context
//  4. Stream() runs: receives Hello, replies with Welcome + initial bundle,
//     then loops on agent messages while a per-stream goroutine pushes
//     server messages from the dispatcher
//
// Live WAF decisions flow into the broker so the HTTP SSE handler can
// fan them out to the dashboard in real time.
package agentserver

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"math"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/domain"
	"github.com/wafio/wafio-cp-backend/internal/engine"
	"github.com/wafio/wafio-cp-backend/internal/fairshare"
	"github.com/wafio/wafio-cp-backend/internal/otp"
	"github.com/wafio/wafio-cp-backend/internal/validate"
	agentv1 "github.com/wafio/wafio-cp-backend/shared/agentpb"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/keepalive"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
)

// ProjectIDKey is the context key under which the resolved project_id from
// the client cert is stored. Used by the Stream RPC and any future RPCs.
type contextKey string

const (
	ctxKeyProjectID    contextKey = "agentserver.project_id"
	ctxKeyCredentialID contextKey = "agentserver.credential_id"
	ctxKeyFingerprint  contextKey = "agentserver.fingerprint"
	// ctxKeyBinding carries the credentialBinding of a credential enrolled
	// for one host (migration 000108); absent for project-wide credentials.
	ctxKeyBinding contextKey = "agentserver.binding"
)

// AgentComponentInfo holds the installation status and metadata for a single
// security-data component as reported by a connected WAF agent.
type AgentComponentInfo struct {
	Exists     bool   `json:"exists"`
	SizeBytes  int64  `json:"size_bytes"`
	ModifiedAt string `json:"modified_at"` // RFC3339 or empty
	Path       string `json:"path"`        // absolute path on the agent host
}

// BundleLoader returns the WAF bundle JSON + generation for a given project.
// We deliberately accept []byte (raw JSON) so the gRPC layer doesn't have
// to know the schema — keeps the existing bundle code path untouched.
type BundleLoader interface {
	LoadBundle(ctx context.Context, projectID, agentName string) (json []byte, generation int64, err error)
}

// Server is the gRPC AgentControl service implementation.
type Server struct {
	// MalwareDatabasePath is the shared corpus served over authenticated gRPC.
	MalwareDatabasePath string
	tracePush           tracePushScheduler
	tracePushGeneration atomic.Int64
	telemetryReceipts   hostTelemetryReceipts
	agentv1.UnimplementedAgentControlServer

	Repo         *repository.Repository
	BundleLoader BundleLoader
	Broker       *DecisionBroker

	// GeoLookup enriches incoming WAF decisions with country codes before persistence.
	GeoLookup domain.GeoLookup

	// EBPFIngest is called when an eBPF agent sends a telemetry batch over
	// the gRPC stream. Wired in cmd/wafio/serve.go to avoid an import cycle
	// (handlers imports agentserver for DecisionBroker).
	EBPFIngest func(ctx context.Context, projectID, agentID, hostID string, payload []byte) error
	// EBPFPrepare decodes a v2 batch once before receipt deduplication. If
	// decoding fails, the legacy callback preserves malformed-batch behavior.
	EBPFPrepare func(payload []byte) (PreparedHostTelemetry, error)

	// KeyCrypto opens the sealed private keys of uploaded certificates for delivery to an agent
	// (certificate_install.go). With none, no key can be opened and no delivery happens.
	KeyCrypto *otp.Encryptor
	// certInstalls holds the CertificateInstall messages that wait for their ack, by command id.
	certMu       sync.Mutex
	certInstalls map[string]*certInstall
	// certs, audit and clock replace the TLS repository, the audit repository and the wall clock,
	// certTimeout the time an install waits for its ack, and afterWipe is called with the key buffer
	// once it was zeroed after a send (tests only); nil or 0 means Repo.TLS, Repo.Audit, time.Now,
	// 30 seconds and nothing.
	certs       certificateStore
	audit       auditSink
	clock       func() time.Time
	certTimeout time.Duration
	afterWipe   func(key []byte)

	// BlockWindow tracks active block events so operators can see and clear them.
	BlockWindow *BlockWindowStore
	unblockMu   sync.Mutex
	unblocks    map[string]*UnblockOperation
	// unblockLedger counts unblocks per project for the fair share of the
	// table; unblockCapacity overrides the cap (tests).
	unblockLedger   fairshare.Tiered
	unblockCapacity int
	// blocks is the bounded queue for block-window work; lockouts
	// caches parsed login-protection rules per (project, app).
	blocks   blockQueue
	lockouts lockoutCache

	// ownerOf replaces the project -> owning account lookup (tests only);
	// nil means Repo.Project (see projectOwner).
	ownerOf func(projectID string) string

	// wafHealth overrides the heartbeat health-counter store (tests only);
	// nil means Repo.EBPF.
	wafHealth wafHealthWriter

	// writer batches decisions into waf_decisions. Nil until NewServer runs,
	// and nil-safe throughout, so a Server built as a bare literal in a test
	// simply does not persist.
	writer *decisionWriter

	// Connections holds active streams keyed by credential_id so we can
	// fan out commands (e.g. force bundle refresh on UI action). For now
	// only used for monitoring; future PRs can add command push.
	// Pushes copy handles under mu and send after releasing it.
	mu      sync.RWMutex
	streams map[string]*streamHandle // key: credential_id
	// pushSendTimeout bounds one pushed Send; 0 means defaultPushSendTimeout.
	pushSendTimeout time.Duration
	// pushFailed counts pushed Sends that failed or missed their deadline;
	// serving is true while the gRPC server accepts connections.
	pushFailed atomic.Uint64
	serving    atomic.Bool
	// GracefulStopWait bounds GracefulStop on shutdown before streams are
	// cut; 0 means defaultGracefulStopWait.
	GracefulStopWait time.Duration

	// live tracks every open Stream per credential_id (not only the push
	// target in streams) so DisconnectCredential can end all of them.
	liveMu sync.Mutex
	live   map[string]map[*liveStream]struct{}
	// credentialRecheck is how often an open stream re-reads its credential;
	// 0 means defaultCredentialRecheck.
	credentialRecheck time.Duration
	// credLookup and helloValidator replace the database lookups (tests
	// only); nil means Repo.AgentGRPC and validateHello.
	credLookup     func(ctx context.Context, fp string) (*repository.MTLSCredential, error)
	helloValidator func(ctx context.Context, projectID string, hello *agentv1.Hello) (agentKind, agentID, hostID string, err error)
	// hostRevokedLookup replaces Repo.Host.HostRevoked and agentHostLookup
	// Repo.EBPF.GetAgentHostID (tests only).
	hostRevokedLookup func(ctx context.Context, projectID, hostID string) (bool, error)
	agentHostLookup   func(agentID string) string

	// agentCompStatus caches the last component-status report received from
	// each connected agent (keyed by credentialID).
	agentCompMu     sync.RWMutex
	agentCompStatus map[string]map[string]AgentComponentInfo // credentialID → component → info

	// Lookup caches for live-decision enrichment + persistence.
	// listenCache maps project_id → (host:port → app_id) so we can resolve
	// the canonical app_id when an agent in --static-upstream mode reports
	// app_id="static" (or empty). Refreshed per project on a TTL.
	listenMu     sync.RWMutex
	listenCache  map[string]listenCacheEntry
	agentIDMu    sync.RWMutex
	agentIDCache map[string]string // key: project_id|agent_name

	// recvBudget limits the decompressed bytes each owning account's agent
	// streams hand the control plane, and shares a process-wide total among
	// the active accounts (ingest_budget.go).
	recvBudget recvBudget
	// liveDemand: when a viewer last asked for live snapshots of an agent,
	// per "project|agent" (telemetry_demand.go).
	liveDemand sync.Map
	// liveStatus: when a viewer last asked for live status and metrics of
	// an agent (a live snapshot request counts too), per "project|agent".
	liveStatus sync.Map
	liveSweeps atomic.Uint64
}

type listenCacheEntry struct {
	hosts    map[string]string
	loadedAt time.Time
}

const (
	listenCacheTTL = 30 * time.Second
)

type streamHandle struct {
	agentID      string
	bundleMu     sync.Mutex
	bundleSendMu sync.Mutex
	bundleStates map[string]HostBundleApplyStatus
	projectID    string
	credentialID string
	agentName    string
	hostname     string
	agentVersion string
	connectedAt  time.Time
	send         func(*agentv1.ServerMessage) error
	// agentKind is "waf" (default) or "ebpf". Set after Hello validation.
	agentKind string
	// ebpfAgentID / hostID are only set for eBPF agents (resolved during
	// validateHello via UpsertAgentForHost).
	ebpfAgentID string
	hostID      string
	// linkedHost is the host the stream's periodic re-check found the agent
	// linked to after a host-less Hello (nil: hostID still holds); read by
	// other goroutines (TraceForwardAgents).
	linkedHost atomic.Pointer[string]
	// disconnect ends this stream (its Stream handler returns); used when a
	// pushed Send misses its deadline. Nil for handles built in tests.
	disconnect func()
	// features is Hello.features: capabilities the agent binary reports
	// (script_rules, no_script_rules; see engine.AgentScriptRules).
	features []string
	// legacyLogged holds the legacy-setting rewrites already logged on this
	// connection (one line per scope and rewrite).
	legacyLogged sync.Map
	// binding and bound are what the mTLS credential of the stream was enrolled for (host, kind and
	// name), taken from the authenticated context when the stream was made; bound is false for a
	// project-wide credential. hostID above does not tell: a project-wide credential connecting
	// under the name of an agent that has a host carries that host too. Only these decide whether
	// the stream may be sent a private key (certificate_install.go).
	binding credentialBinding
	bound   bool
	// peerIP is the address of the agent as the transport saw it, for audit rows.
	peerIP string
	// The worker that delivers keys on this stream is started by the first request and ended with the
	// stream (certificate_install.go). queued counts the requests that wait or are being served.
	workerMu        sync.Mutex
	deliveries      chan deliveryRequest
	workerCancel    context.CancelFunc
	workerDone      chan struct{}
	workerStopped   bool
	queued          atomic.Int64
	queueFullLogged atomic.Bool
	// tlsApps are the ids of the apps whose entry in the last WAF bundle sent on this stream turns TLS
	// on, under bundleMu. A status for any other app is dropped before it costs a query.
	tlsApps map[string]struct{}
	// open reports whether the stream is still taking part: not ended, revoked, or cut after a push
	// that missed its deadline. Nil for handles built in tests, which count as open.
	open func() bool
	// certClaims tracks the certificates already sent on this stream (claimCertificateDelivery).
	certMu     sync.Mutex
	certClaims map[string]certClaim
	// statusBudgets limits the statuses and chain parses per app (certificate_status.go).
	statusMu      sync.Mutex
	statusBudgets map[string]*appBudget
}

func NewServer(repo *repository.Repository, loader BundleLoader, broker *DecisionBroker) *Server {
	s := &Server{
		Repo:            repo,
		BundleLoader:    loader,
		Broker:          broker,
		BlockWindow:     NewBlockWindowStore(),
		writer:          newDecisionWriterFor(repo),
		streams:         make(map[string]*streamHandle),
		listenCache:     make(map[string]listenCacheEntry),
		agentIDCache:    make(map[string]string),
		agentCompStatus: make(map[string]map[string]AgentComponentInfo),
	}
	if s.writer != nil {
		s.writer.onGoneAgent = s.ForgetAgent
		s.writer.onWritten = s.notifyStored
	}
	return s
}

// notifyStored signals the stored-decision subscribers (the Decisions tab of
// an app) of every (project, app) among rows, which the decision writer has
// just written. Signalling after the write, not on receipt, means a tab that
// fetches on the signal finds the rows.
func (s *Server) notifyStored(rows []repository.WAFDecision) {
	if s.Broker == nil || !s.Broker.HasStoredSubscribers() {
		return
	}
	byProject := make(map[string]map[string]struct{}, 1)
	for _, r := range rows {
		if !looksLikeUUID(r.AppID) {
			continue // stored without an app; no app's Decisions tab shows it
		}
		apps := byProject[r.ProjectID]
		if apps == nil {
			apps = make(map[string]struct{}, 1)
			byProject[r.ProjectID] = apps
		}
		apps[strings.ToLower(r.AppID)] = struct{}{}
	}
	for projectID, apps := range byProject {
		s.Broker.NotifyStored(projectID, apps)
	}
}

// ForgetAgent drops every cached (project, name) → agentID entry pointing at
// agentID, so decisions from a still-connected stream of a deleted agent stop
// resolving to it. Called by the agent delete handler and by the
// decision writer when the database reports the agent gone.
func (s *Server) ForgetAgent(agentID string) {
	if s == nil || agentID == "" {
		return
	}
	s.agentIDMu.Lock()
	for k, v := range s.agentIDCache {
		if v == agentID {
			delete(s.agentIDCache, k)
		}
	}
	s.agentIDMu.Unlock()
}

// touchAgentLastSeen runs a non-blocking UPDATE on agents.last_seen for the
// (project_id, agent_name) pair. Called on connect and every heartbeat so
// the dashboard ONLINE indicator stays accurate when only the gRPC stream
// is active (no HTTP bundle pull).
func (s *Server) touchAgentLastSeen(projectID, agentName string) {
	if s == nil || s.Repo == nil || s.Repo.EBPF == nil {
		return
	}
	if projectID == "" || agentName == "" {
		return
	}
	go func(pid, name string) {
		defer recoverPanic("touch-last-seen")
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		if err := s.Repo.EBPF.TouchAgentLastSeenByName(ctx, pid, name); err != nil {
			log.Printf("[agentserver] touch last_seen failed project=%s name=%q: %v", pid, name, err)
		}
	}(projectID, agentName)
}

// touchStreamLiveness marks a connected agent as seen: agents.last_seen by
// id for host agents (by project and name for WAF agents), and
// hosts.last_seen when the stream is bound to a host. Runs non-blocking.
func (s *Server) touchStreamLiveness(projectID, ebpfAgentID, agentName, hostID string) {
	if s == nil || s.Repo == nil {
		return
	}
	if ebpfAgentID == "" {
		s.touchAgentLastSeen(projectID, agentName)
	} else if s.Repo.EBPF != nil {
		go func() {
			defer recoverPanic("touch-last-seen")
			tCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_ = s.Repo.EBPF.TouchAgentLastSeen(tCtx, projectID, ebpfAgentID)
		}()
	}
	if hostID != "" && s.Repo.Host != nil {
		go func() {
			defer recoverPanic("touch-host-heartbeat")
			tCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()
			_ = s.Repo.Host.TouchHeartbeat(tCtx, projectID, hostID)
		}()
	}
}

// storeAgentHostInfo decodes a JSON HostInfo blob sent in a Heartbeat and
// persists it via UpdateAgentHostInfo. Runs non-blocking. Called at most
// once per 5 minutes (rate controlled by the agent).
func (s *Server) storeAgentHostInfo(projectID, agentName, kind string, hostInfoJSON []byte) {
	if s == nil || s.Repo == nil || s.Repo.EBPF == nil || len(hostInfoJSON) == 0 {
		return
	}
	agentID := s.resolveAgentID(projectID, agentName)
	if agentID == "" {
		return
	}
	if kind == "" {
		kind = "waf"
	}
	go func(id string, raw []byte) {
		defer recoverPanic("store-host-info")
		var hi struct {
			Hostname     string `json:"hostname"`
			OS           string `json:"os"`
			OSVersion    string `json:"os_version"`
			KernelRel    string `json:"kernel_release"`
			Arch         string `json:"arch"`
			CPUCount     int    `json:"cpu_count"`
			MemoryTotal  uint64 `json:"memory_total_bytes"`
			VirtType     string `json:"virt_type"`
			AgentVersion string `json:"agent_version"`
			BootTime     int64  `json:"boot_time"`
		}
		if err := json.Unmarshal(raw, &hi); err != nil {
			log.Printf("[agentserver] decode host_info_json: %v", err)
			return
		}
		row := repository.AgentHostInfoRow{
			Raw:         raw,
			Hostname:    hi.Hostname,
			OS:          hi.OS,
			OSVersion:   hi.OSVersion,
			Kernel:      hi.KernelRel,
			Arch:        hi.Arch,
			CPUCount:    hi.CPUCount,
			MemoryTotal: int64(min(hi.MemoryTotal, math.MaxInt64)), //nolint:gosec // clamped to MaxInt64 by min
			VirtType:    hi.VirtType,
			Version:     hi.AgentVersion,
			Kind:        kind,
			BootUnix:    hi.BootTime,
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := s.Repo.EBPF.UpdateAgentHostInfo(ctx, projectID, id, row); err != nil {
			log.Printf("[agentserver] update host_info agent=%s: %v", id, err)
		}
		// Auto-link unattached agent to host if hostname matches a registered host in the project
		if hi.Hostname != "" && s.Repo.EBPF.GetAgentHostID(ctx, id) == "" {
			if host, err := s.Repo.Host.GetByName(ctx, projectID, hi.Hostname); err == nil && host != nil {
				_ = s.Repo.EBPF.LinkAgentToHost(ctx, projectID, id, host.ID)
			} else if siblingHostID := s.Repo.EBPF.GetHostIDByHostname(ctx, projectID, hi.Hostname); siblingHostID != "" {
				_ = s.Repo.EBPF.LinkAgentToHost(ctx, projectID, id, siblingHostID)
			}
		}
	}(agentID, hostInfoJSON)
}

// uuidPattern matches the canonical 8-4-4-4-12 UUID layout. Used to detect
// the "static" sentinel and other non-UUID app_id values reported by agents.
func looksLikeUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		switch i {
		case 8, 13, 18, 23:
			if c != '-' {
				return false
			}
		default:
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') && (c < 'A' || c > 'F') {
				return false
			}
		}
	}
	return true
}

// listenTargets returns a cached host:port → app_id lookup for the project.
// Refreshed on a 30 s TTL — short enough to react to new app routes, long
// enough to avoid hot-pathing a SQL query on every WAF decision.
func (s *Server) listenTargets(projectID string) map[string]string {
	if s == nil || s.Repo == nil || s.Repo.App == nil || projectID == "" {
		return nil
	}
	s.listenMu.RLock()
	entry, ok := s.listenCache[projectID]
	s.listenMu.RUnlock()
	if ok && time.Since(entry.loadedAt) < listenCacheTTL {
		return entry.hosts
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	hosts, err := s.Repo.App.ListListenTargets(ctx, projectID)
	if err != nil {
		log.Printf("[agentserver] listen-target lookup failed project=%s: %v", projectID, err)
		// Fall back to the previous cached value if any.
		return entry.hosts
	}
	s.listenMu.Lock()
	s.listenCache[projectID] = listenCacheEntry{hosts: hosts, loadedAt: time.Now()}
	s.listenMu.Unlock()
	return hosts
}

// enrichDecision fills dec.AppId when the agent reported it as empty or as
// the "static" sentinel (used by --static-upstream mode). The lookup is
// host-based: dec.Host is matched against apps.listen_host:listen_port for
// the project. If no match is found the field is left as-is.
func (s *Server) enrichDecision(projectID string, dec *agentv1.WAFDecisionEvent) {
	if dec == nil {
		return
	}
	if looksLikeUUID(dec.GetAppId()) {
		return
	}
	hosts := s.listenTargets(projectID)
	if len(hosts) == 0 {
		return
	}
	if id, ok := hosts[dec.GetHost()]; ok {
		dec.AppId = id
	}
}

// resolveAgentID returns the agent_id row for (project_id, agent_name) with
// a per-process cache. Returns "" if the agent isn't registered yet.
func (s *Server) resolveAgentID(projectID, agentName string) string {
	if projectID == "" || agentName == "" || s.Repo == nil || s.Repo.EBPF == nil {
		return ""
	}
	key := projectID + "|" + agentName
	s.agentIDMu.RLock()
	id, ok := s.agentIDCache[key]
	s.agentIDMu.RUnlock()
	if ok && id != "" {
		return id
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	resolved, err := s.Repo.EBPF.LookupAgentIDByName(ctx, projectID, agentName)
	if err != nil || resolved == "" {
		return ""
	}
	s.agentIDMu.Lock()
	s.agentIDCache[key] = resolved
	s.agentIDMu.Unlock()
	return resolved
}

// persistDecision writes a single live WAF decision to waf_decisions so the
// dashboard's periodic poll reflects the same numbers as the SSE stream.
// Runs in a goroutine — never blocks the gRPC receive loop.
func (s *Server) persistDecision(projectID, agentName string, dec *agentv1.WAFDecisionEvent) {
	if s == nil || s.Repo == nil || s.Repo.WAF == nil || dec == nil {
		return
	}
	agentID := s.resolveAgentID(projectID, agentName)
	if agentID == "" {
		return // agent row not yet registered; the next decision after a host-keyed
		// telemetry call will succeed.
	}
	// Resolve country code from remote IP using the control-plane GeoLookup.
	cc := ""
	if s.GeoLookup != nil {
		remoteIP := dec.GetRemoteIp()
		// Strip port if present.
		if host, _, err := net.SplitHostPort(remoteIP); err == nil {
			remoteIP = host
		}
		if remoteIP != "" {
			cc, _ = s.GeoLookup.Country(remoteIP)
		}
	}
	// Queued rather than written here: one goroutine and one round trip per
	// decision is what this path used to do, and it does not survive the
	// traffic a WAF exists to handle. See decisionWriter.
	s.writer.EnqueueOwned(s.projectOwner(projectID), decisionRowFromEvent(projectID, agentID, cc, dec))
}

// redactDecisionAtIngest removes credentials from a decision in place before
// it is stored, streamed or recorded in the block window: the
// same redaction a current WAF agent applies, again here for older agents.
// Idempotent. It returns the URI as received, for the block window's
// login-scope lookups.
func redactDecisionAtIngest(dec *agentv1.WAFDecisionEvent) (rawURI string) {
	if dec == nil {
		return ""
	}
	rawURI = dec.GetUri()
	// match_source_exact is unset (false) from agents that predate it: their
	// match sources are treated as guesses and exempt no secret-named value.
	m := domain.DecisionMatch(dec.GetMatchSource(), dec.GetMatchSourceExact(), dec.GetCategories())
	dec.RequestHeaders = domain.RedactDecisionHeaders(dec.GetRequestHeaders(), m)
	dec.QueryParams = domain.RedactDecisionQuery(dec.GetQueryParams(), m)
	dec.Uri = domain.RedactDecisionURI(rawURI, m)
	// The flagged value never reaches the control plane: a body copy shorter
	// than the request body may hide another value of the target past the cut.
	size := int(dec.GetBodySize())
	dec.BodyPreview = domain.RedactDecisionBodyCopy(dec.GetBodyPreview(), dec.GetContentType(), m, domain.BodyCopyComplete(dec.GetBodyPreview(), size, domain.DecisionBodyPreviewMax))
	dec.RequestBody = domain.RedactDecisionBodyCopy(dec.GetRequestBody(), dec.GetContentType(), m, domain.BodyCopyComplete(dec.GetRequestBody(), size, domain.DecisionRequestBodyMax))
	return rawURI
}

// decisionRowFromEvent maps a WAFDecisionEvent to a waf_decisions row. Fields an older agent does not
// send (coverage, status) arrive as zero values and are stored NULL; rule_based and hybrid are stored as
// semantic.
func decisionRowFromEvent(projectID, agentID, countryCode string, dec *agentv1.WAFDecisionEvent) repository.WAFDecision {
	return repository.WAFDecision{
		ProjectID:      projectID,
		AgentID:        agentID,
		AppID:          dec.GetAppId(),
		Host:           dec.GetHost(),
		Method:         dec.GetMethod(),
		URI:            dec.GetUri(),
		RemoteAddr:     dec.GetRemoteIp(),
		CountryCode:    countryCode,
		UserAgent:      dec.GetUserAgent(),
		Action:         dec.GetAction(),
		Score:          int(dec.GetScore()),
		Categories:     dec.GetCategories(),
		MatchDetail:    dec.GetMatchDetail(),
		AnalyzeMethod:  domain.CanonicalAnalyzeMethod(dec.GetAnalyzeMethod()),
		ContentType:    dec.GetContentType(),
		BodySize:       int(dec.GetBodySize()),
		BodyPreview:    dec.GetBodyPreview(),
		CWE:            dec.GetCwe(),
		LatencyUS:      int(dec.GetLatencyUs()),
		EventTime:      time.Unix(dec.GetTsUnix(), 0).UTC(),
		MatchSource:    dec.GetMatchSource(),
		RequestHeaders: dec.GetRequestHeaders(),
		RequestBody:    dec.GetRequestBody(),
		QueryParams:    dec.GetQueryParams(),
		PayloadType:    dec.GetPayloadType(),
		Coverage:       dec.GetCoverage(),
		Status:         int(dec.GetStatus()),
	}
}

// wafHealthWriter is the slice of the repository that stores heartbeat
// health counters. Narrow so ingestion can be tested without a database.
type wafHealthWriter interface {
	UpdateAgentWAFHealth(ctx context.Context, projectID, agentID string, h repository.AgentWAFHealth) error
	UpdateAgentFeatures(ctx context.Context, projectID, agentID string, scriptRules, maintenance, tlsCertificates *bool, hostBound bool) error
}

// wafHealthFromHeartbeat extracts the inspection-health fields (5-8, 11-20)
// from a heartbeat. ok is false when the agent reported none of them (pre-v1.2
// WAF agent, or a host/eBPF agent), so stored values are left untouched.
func wafHealthFromHeartbeat(hb *agentv1.Heartbeat) (h repository.AgentWAFHealth, ok bool) {
	if hb == nil {
		return h, false
	}
	h = repository.AgentWAFHealth{
		AnalyzePanicsTotal:        clampCounter(hb.AnalyzePanicsTotal),
		EnginePanicsTotal:         clampCounter(hb.EnginePanicsTotal),
		PartialCoverageTotal:      clampCounter(hb.PartialCoverageTotal),
		ParseBudgetExhaustedTotal: clampCounter(hb.ParseBudgetExhaustedTotal),
		// Fields 11-19.
		ScriptIncompleteTotal:    clampCounter(hb.ScriptIncompleteTotal),
		ScriptErrorsTotal:        clampCounter(hb.ScriptErrorsTotal),
		ScriptRulesRejectedTotal: clampCounter(hb.ScriptRulesRejectedTotal),
		ScriptRunsInFlight:       nonNegative(hb.ScriptRunsInFlight),
		AgentPanicsTotal:         clampCounter(hb.AgentPanicsTotal),
		AnalyzeLatencyP50Us:      clampCounter(hb.AnalyzeLatencyP50Us),
		AnalyzeLatencyP95Us:      clampCounter(hb.AnalyzeLatencyP95Us),
		AnalyzeLatencyP99Us:      clampCounter(hb.AnalyzeLatencyP99Us),
		AnalyzeLatencySamples:    clampCounter(hb.AnalyzeLatencySamples),
		// Field 20.
		RegexRulesDroppedTotal: clampCounter(hb.RegexRulesDroppedTotal),
		// Fields 9-10.
		BundleSource:     bundleSource(hb.BundleSource),
		BundleGeneration: nonNegative(hb.BundleGeneration),
	}
	return h, h.Reported()
}

// bundleSource keeps a heartbeat's bundle_source to the values the agent
// defines; anything else (a newer agent, a garbled value) is stored as
// "unknown" so the column never holds agent-chosen text. nil stays nil.
func bundleSource(v *string) *string {
	if v == nil {
		return nil
	}
	s := *v
	switch s {
	case "", "live", "cache", "cache_stale":
	default:
		s = "unknown"
	}
	return &s
}

// nonNegative copies an optional gauge, clamping a negative value to 0.
func nonNegative(v *int64) *int64 {
	if v == nil {
		return nil
	}
	n := max(*v, 0)
	return &n
}

// clampCounter converts an optional uint64 counter to the BIGINT column type,
// saturating at MaxInt64. nil stays nil (not reported).
func clampCounter(v *uint64) *int64 {
	if v == nil {
		return nil
	}
	n := int64(math.MaxInt64)
	if *v < math.MaxInt64 {
		n = int64(*v)
	}
	return &n
}

// healthWriter returns the store for heartbeat counters: the test seam when
// set, otherwise the agents repository. nil when neither is available.
func (s *Server) healthWriter() wafHealthWriter {
	if s.wafHealth != nil {
		return s.wafHealth
	}
	if s.Repo != nil && s.Repo.EBPF != nil {
		return s.Repo.EBPF
	}
	return nil
}

// storeWAFHealth persists the heartbeat's inspection-health counters on the
// agent row. Synchronous; the receive loop calls it in a goroutine.
func (s *Server) storeWAFHealth(projectID, agentName string, hb *agentv1.Heartbeat) {
	defer recoverPanic("store-waf-health") // started as a goroutine per heartbeat
	h, ok := wafHealthFromHeartbeat(hb)
	if !ok {
		return
	}
	w := s.healthWriter()
	if w == nil {
		return
	}
	agentID := s.resolveAgentID(projectID, agentName)
	if agentID == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := w.UpdateAgentWAFHealth(ctx, projectID, agentID, h); err != nil {
		log.Printf("[agentserver] store waf health failed project=%s agent=%s: %v", projectID, agentID, err)
	}
}

// storeAgentFeatures records whether the agent can run script rules, whether it supports
// maintenance mode and whether it serves TLS certificates, as reported in its Hello. hostBound
// says that the stream's credential is bound to a host: only such a stream writes the TLS flag of
// an agent row that has a host (UpdateAgentFeatures).
// Synchronous; Stream calls it before it registers the stream, so a CertificateStatus that the
// agent sends after its first bundle finds the flag written. A failure is logged, since without the
// flag no key is sent and nothing else says why.
func (s *Server) storeAgentFeatures(projectID, agentID string, features []string, hostBound bool) {
	defer recoverPanic("store-agent-features")
	if agentID == "" {
		log.Printf("[agentserver] agent features not stored, the agent has no row yet project=%s", projectID)
		return
	}
	w := s.healthWriter()
	if w == nil {
		log.Printf("[agentserver] agent features not stored, no store project=%s agent=%s", projectID, agentID)
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := w.UpdateAgentFeatures(ctx, projectID, agentID, engine.AgentScriptRules(features), engine.AgentMaintenanceMode(features),
		engine.AgentTLSCertificates(features), hostBound); err != nil {
		log.Printf("[agentserver] store agent features failed project=%s agent=%s: %v", projectID, agentID, err)
	}
}

// DecisionWriterStats exposes the writer's counters for monitoring. Dropped is
// the number the queue could not accept; a non-zero value means the database
// could not keep up with live traffic and decisions were lost.
func (s *Server) DecisionWriterStats() DecisionWriterStats {
	if s == nil {
		return DecisionWriterStats{}
	}
	return s.writer.Stats()
}

// StopDecisionWriter flushes queued decisions and stops the writer. Call it on
// shutdown, before the process exits, or the last batch is lost.
func (s *Server) StopDecisionWriter() {
	if s == nil {
		return
	}
	s.writer.Stop()
}

// ─── Block Window ──────────────────────────────────────────────────────────

// recordBlockWindowEntry is called (in a goroutine) when a block decision
// arrives from a WAF agent. All block actions are recorded: LoginProtection
// and BlockPolicy have a persistent unblock mechanism; all other categories
// (the semantic detections) are recorded as informational-only entries.
//
// rawURI is the URI before ingest redaction: the lockout TTL
// lookup and an old agent's URI-keyed login scope need it; the entry's Path
// shows the redacted one.
func (s *Server) recordBlockWindowEntry(projectID, agentName string, dec *agentv1.WAFDecisionEvent, rawURI string) {
	// Callers run this on its own goroutine; a panic must not kill the process.
	defer recoverPanic("record-block-window")
	if s == nil || s.BlockWindow == nil {
		return
	}
	categories := dec.GetCategories()
	if len(categories) == 0 {
		return
	}

	agentID := s.resolveAgentID(projectID, agentName)
	if agentID == "" {
		return
	}

	ip := dec.GetRemoteIp()
	uri := rawURI

	var unblockType, unblockScope, unblockKey, reason string
	var ttl time.Duration

	// Skip body_limit blocks — these are technical size rejections, not security events.
	for _, cat := range categories {
		if cat == "body_limit" {
			return
		}
	}

	// Check for persistent-block categories (LoginProtection takes priority).
	for _, cat := range categories {
		if cat == "LoginProtection" {
			reason = "LoginProtection"
			break
		}
		if cat == "BlockPolicy" {
			reason = "BlockPolicy"
		}
	}

	switch reason {
	case "LoginProtection":
		unblockType = "login_scope"
		unblockScope = loginUnblockScopeURI(projectID, dec, uri)
		unblockKey = ip
		ttl = s.lookupLoginLockoutTTL(projectID, dec.GetAppId(), uri, loginMatchPattern(dec))
	case "BlockPolicy":
		unblockType = "blockpolicy"
		unblockScope = ""
		unblockKey = ip
		ttl = 1 * time.Hour
	default:
		// Semantic block: no persistent agent state.
		// UnblockType is intentionally empty; Delete handler will only
		// remove the entry from the list without sending an unblock command.
		reason = strings.Join(categories, ", ")
		ttl = 1 * time.Hour
	}

	entry := BlockEntry{
		ID:           newBlockEntryID(),
		ProjectID:    projectID,
		AgentID:      agentID,
		Key:          ip,
		KeyType:      "ip",
		Reason:       reason,
		Path:         dec.GetUri(),
		ExpiresAt:    time.Now().Add(ttl),
		BlockedAt:    time.Now(),
		UnblockType:  unblockType,
		UnblockScope: unblockScope,
		UnblockKey:   unblockKey,
	}
	s.BlockWindow.Record(entry)
}

// loginUnblockScope is the rate-limit scope whose buckets an unblock of a
// LoginProtection block clears on the agent. A current agent keys
// them by the matched path exception and names it in match_source
// ("path:<pattern>"); an older agent sends no match source and keys them by
// the request URI.
func loginUnblockScope(projectID string, dec *agentv1.WAFDecisionEvent) string {
	return loginUnblockScopeURI(projectID, dec, dec.GetUri())
}

// loginUnblockScopeURI is loginUnblockScope with the request URI as the agent
// sent it (before ingest redaction).
func loginUnblockScopeURI(projectID string, dec *agentv1.WAFDecisionEvent, uri string) string {
	if pattern := loginMatchPattern(dec); pattern != "" {
		return engine.LoginProtectionScope(projectID, pattern)
	}
	return "login:" + projectID + ":" + uri
}

// loginMatchPattern is the path exception pattern a LoginProtection block
// names in match_source ("path:<pattern>"), or "" (an older agent).
func loginMatchPattern(dec *agentv1.WAFDecisionEvent) string {
	if pattern, ok := strings.CutPrefix(dec.GetMatchSource(), "path:"); ok {
		return pattern
	}
	return ""
}

// loginLockoutException finds the path exception whose login protection
// produced a block: the one with the reported pattern, else (older agent) the
// exception matching the request URI.
func loginLockoutException(exceptions []engine.PathExceptionConfig, uri, pattern string) *engine.PathExceptionConfig {
	if pattern != "" {
		for i := range exceptions {
			if exc := &exceptions[i]; !exc.Disabled && exc.Path == pattern && exc.LoginProtection != nil {
				return exc
			}
		}
	}
	return engine.MatchPathException(uri, exceptions)
}

// lookupLoginLockoutTTL attempts to find the actual lockout_sec for the
// path exception that blocked (loginLockoutException) from the app or project
// rules. Falls back to 30 minutes if the config cannot be read or no matching
// rule is found.
func (s *Server) lookupLoginLockoutTTL(projectID, appID, uri, pattern string) time.Duration {
	const fallback = 30 * time.Minute
	if s.Repo == nil {
		return fallback
	}
	key := projectID + "|" + appID
	now := time.Now()
	exceptions, cached := s.lockouts.get(key, now)
	if !cached {
		exceptions = s.loadLoginExceptions(projectID, appID)
		s.lockouts.put(key, exceptions, now)
	}
	exc := loginLockoutException(exceptions, uri, pattern)
	if exc == nil || exc.LoginProtection == nil || exc.LoginProtection.LockoutSec <= 0 {
		return fallback
	}
	return time.Duration(exc.LoginProtection.LockoutSec) * time.Second
}

// loadLoginExceptions reads and parses the path exceptions that apply to an
// app (its own rules, else the project's). nil on any failure; the caller
// caches that too, so a broken rules JSON is not re-read per block.
func (s *Server) loadLoginExceptions(projectID, appID string) []engine.PathExceptionConfig {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()

	var rulesJSON []byte
	// Prefer per-app rules when appID is known — only an app of the agent's
	// own project; the agent-reported id is not trusted.
	if appID != "" && s.Repo.WAF != nil {
		if ac, err := s.Repo.WAF.GetAppConfigForProject(ctx, projectID, appID); err == nil && ac != nil && len(ac.RulesJSON) > 0 {
			rulesJSON = ac.RulesJSON
		}
	}
	// Fall back to project-level rules.
	if len(rulesJSON) == 0 && s.Repo.Project != nil {
		if pc, err := s.Repo.Project.GetConfig(ctx, projectID); err == nil && pc != nil {
			rulesJSON = pc.RulesJSON
		}
	}
	if len(rulesJSON) == 0 {
		return nil
	}

	result, err := engine.LoadRuleMapFromJSON(rulesJSON)
	if err != nil || result == nil {
		return nil
	}
	return result.PathExceptions
}

// UnblockEntry mirrors the type in the agent package so the server can build
// management bundles without importing the agent package (cycle-free).
type UnblockEntry struct {
	Type  string `json:"type"`
	Scope string `json:"scope,omitempty"`
	Key   string `json:"key"`
}

// ─── Hello validation ──────────────────────────────────────────────────────

// validateHello rejects any agent whose Hello credentials don't pass all of:
//
//  0. a credential enrolled with a host key (host-bound, migration 000108)
//     is held to its one agent on its one host instead
//     (validateBoundHello); the rules below are for project-wide
//     credentials.
//  1. agent_name (mandatory) — an agent already registered in this project
//     reconnects under its row; an unknown name is registered automatically
//     (both kinds; the install scripts rely on it), at most
//     repository.MaxAgentsPerProject agents per project (ResourceExhausted
//     past it).
//  2. host_key (optional for both kinds) — when non-empty, must verify
//     against the hosts table (a revoked host's key does not) and the host's
//     project_id must match, for a known agent too (it used to be
//     ignored for a known host agent). Providing it binds the agent to that
//     host row; omitting it registers an unattached agent instead.
//  3. host — an agent bound to a revoked host, or (bound to none) reporting
//     the hostname of a revoked host, is refused with PermissionDenied
//     "host revoked".
//
// Returns (agentKind, agentID, hostID, err). agentID is only non-empty for
// host agents. WAF agents resolve their agentID lazily via resolveAgentID.
func (s *Server) validateHello(ctx context.Context, projectID string, hello *agentv1.Hello) (agentKind, agentID, hostID string, err error) {
	if s == nil || s.Repo == nil {
		return "", "", "", status.Error(codes.Internal, "server not initialized")
	}
	// A credential enrolled with a host key speaks for one agent on one
	// host only (hello_enrolled.go).
	if b, ok := bindingFrom(ctx); ok {
		return s.validateBoundHello(ctx, projectID, hello, b)
	}

	keyCtx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	name := strings.TrimSpace(hello.GetAgentName())
	if name == "" {
		// Fallback: use hostname@ebpf if the agent didn't supply a name.
		// This only works for eBPF agents that provide a host_key.
		name = hello.GetHostname() + "@ebpf"
	}
	// An unknown name is registered below and then shown in the dashboard
	// (and by anything printing agent names): no control, format or bidi
	// characters, at most agents.name's 255.
	if len(name) > 255 || !validate.PlainText(name) {
		return "", "", "", status.Error(codes.InvalidArgument, "agent_name must be at most 255 characters without control, formatting or bidi characters")
	}
	hostKey := strings.TrimSpace(hello.GetHostKey())
	hostname := hello.GetHostname()

	// verifyHostKey checks a presented host_key: valid, not revoked (a
	// revoked host's key does not verify) and of this project.
	verifyHostKey := func() (*repository.Host, error) {
		host, herr := s.Repo.Host.VerifyKey(keyCtx, hostKey)
		if errors.Is(herr, repository.ErrHostKeyInvalid) {
			return nil, status.Error(codes.PermissionDenied, "invalid host_key")
		}
		if herr != nil {
			// A database error or no verification slot before the Hello
			// deadline says nothing about the key: the agent retries
			// (a WAF agent exits on PermissionDenied at start).
			log.Printf("[agentserver] host_key check failed project=%s: %v", projectID, herr)
			return nil, status.Error(codes.Unavailable, "host_key check unavailable; retry")
		}
		if host.ProjectID != projectID {
			return nil, status.Error(codes.PermissionDenied, "host_key not valid for this project")
		}
		return host, nil
	}

	// ── Determine agent kind by looking up the name in the agents table ───
	existingID, existingKind, _ := s.Repo.EBPF.LookupAgentByName(keyCtx, projectID, name)

	// ── Known agent ───────────────────────────────────────────────────────
	// kind='waf' (or legacy rows with no kind) is a WAF agent; kind='ebpf'
	// and kind='host' are both host/eBPF agents ('host' is the
	// post-migration 000031 name for what was 'ebpf'). The existing row is
	// reused, never re-upserted.
	if existingID != "" && (existingKind == "waf" || existingKind == "ebpf" || existingKind == "host") {
		kind := "host"
		if existingKind == "waf" {
			kind = "waf"
		}
		var boundHost string
		if hostKey != "" {
			host, verr := verifyHostKey()
			if verr != nil {
				return "", "", "", verr
			}
			boundHost = host.ID
			// Persist host_id on the agent row so ON DELETE CASCADE removes
			// the agent when its host is deleted (and a revoke finds it).
			go func() { //nolint:gosec // G118: best-effort link must outlive the Hello request context
				defer recoverPanic("link-agent-host")
				lCtx, lCancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer lCancel()
				_ = s.Repo.EBPF.SetAgentHostID(lCtx, projectID, existingID, host.ID)
			}()
		} else {
			// Resolve the linked host_id so the heartbeat path can call
			// TouchHeartbeat even when no --host-key is passed on the CLI.
			boundHost = s.Repo.EBPF.GetAgentHostID(keyCtx, existingID)
			if rerr := s.refuseRevokedHost(keyCtx, projectID, boundHost, hostname); rerr != nil {
				return "", "", "", rerr
			}
			// If still unlinked, try to bind to a host by hostname match so
			// that future host deletions cascade to this agent.
			if boundHost == "" {
				s.linkAgentByNameAsync(projectID, existingID, hostname)
			}
		}
		if kind == "waf" {
			return "waf", "", boundHost, nil
		}
		s.agentIDMu.Lock()
		s.agentIDCache[projectID+"|"+name] = existingID
		s.agentIDMu.Unlock()
		return "host", existingID, boundHost, nil
	}

	// Agent not yet in DB — auto-register using the kind hint from Hello.
	// host_key is OPTIONAL: mTLS already proves project membership.
	// When provided, the agent is bound to the registered host row (enables
	// the host detail page and host-level telemetry). When omitted, the agent
	// auto-registers as an unattached agent scoped to the project.
	//
	// WAF agents self-identify by sending agent_kind="waf" in Hello.
	// Host/eBPF agents send "host" or "ebpf" (or omit the field entirely).
	hintKind := strings.TrimSpace(hello.GetAgentKind())
	if hintKind != "waf" && hintKind != "host" && hintKind != "ebpf" {
		hintKind = "host" // default: treat unknown as host
	}
	if hintKind == "ebpf" {
		hintKind = "host" // normalise legacy name
	}

	var aid, linkedHostID string
	if hostKey != "" {
		// With host_key: verify and bind to the host row.
		host, verr := verifyHostKey()
		if verr != nil {
			return "", "", "", verr
		}
		var uerr error
		aid, uerr = s.Repo.EBPF.UpsertAgentForHost(keyCtx, host.ID, host.UserID, host.ProjectID, hintKind, name)
		if uerr != nil {
			return "", "", "", registerErr("upsert agent", uerr)
		}
		linkedHostID = host.ID
	} else {
		// Without host_key: an agent of a revoked host does not get to
		// register afresh under a new name.
		if rerr := s.refuseRevokedHost(keyCtx, projectID, "", hostname); rerr != nil {
			return "", "", "", rerr
		}
		var uerr error
		aid, uerr = s.Repo.EBPF.UpsertUnattachedAgent(keyCtx, projectID, name, hintKind)
		if uerr != nil {
			return "", "", "", registerErr("register agent", uerr)
		}
		// Try to link this agent to a registered (not revoked) host whose
		// name matches the agent's hostname. Linking enables ON DELETE
		// CASCADE so future host deletions clean up the agent.
		if linkedHostID = s.linkableHostByName(keyCtx, projectID, hostname); linkedHostID != "" {
			_ = s.Repo.EBPF.LinkAgentToHost(keyCtx, projectID, aid, linkedHostID)
		}
	}
	s.agentIDMu.Lock()
	s.agentIDCache[projectID+"|"+name] = aid
	s.agentIDMu.Unlock()
	if hintKind == "waf" {
		return "waf", "", linkedHostID, nil
	}
	return "host", aid, linkedHostID, nil
}

// ─── TLS / auth plumbing ────────────────────────────────────────────────────

// BuildTLSConfig produces a tls.Config with ClientCAs = caPool and
// ClientAuth = RequireAndVerifyClientCert. server cert must be valid for
// the listening address.
func BuildTLSConfig(provider *CertProvider, caPool *x509.CertPool) *tls.Config {
	return &tls.Config{
		GetCertificate: provider.GetCertificate,
		ClientAuth:     tls.RequireAndVerifyClientCert,
		ClientCAs:      caPool,
		// TLS 1.3 floor: all agents are Go binaries (TLS 1.3 capable) on a
		// private VPN, so there is no legacy-client compatibility concern.
		MinVersion: tls.VersionTLS13,
		NextProtos: []string{"h2"},
	}
}

// CertProvider holds the current server TLS certificate and allows it to be
// swapped atomically at runtime (for auto-renew without gRPC server restart).
type CertProvider struct {
	mu   sync.RWMutex
	cert *tls.Certificate
}

// NewCertProvider creates a CertProvider with an initial certificate.
func NewCertProvider(cert tls.Certificate) *CertProvider {
	return &CertProvider{cert: &cert}
}

// Set atomically replaces the active certificate.
func (p *CertProvider) Set(cert tls.Certificate) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.cert = &cert
}

// GetCertificate implements the tls.Config.GetCertificate callback.
func (p *CertProvider) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.cert, nil
}

// authUnaryInterceptor / authStreamInterceptor extract project_id from the
// peer's TLS certificate fingerprint and inject it into ctx.
func (s *Server) authStreamInterceptor() grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) error {
		ctx, err := s.authenticate(ss.Context())
		if err != nil {
			return err
		}
		return handler(srv, &authedServerStream{ServerStream: ss, ctx: ctx})
	}
}

type authedServerStream struct {
	grpc.ServerStream
	ctx context.Context
}

func (s *authedServerStream) Context() context.Context { return s.ctx }

func (s *Server) authenticate(ctx context.Context) (context.Context, error) {
	p, ok := peer.FromContext(ctx)
	if !ok || p == nil {
		return nil, status.Error(codes.Unauthenticated, "no peer info")
	}
	tlsInfo, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil, status.Error(codes.Unauthenticated, "non-TLS connection")
	}
	if len(tlsInfo.State.PeerCertificates) == 0 {
		return nil, status.Error(codes.Unauthenticated, "client cert required")
	}
	cert := tlsInfo.State.PeerCertificates[0]
	sum := sha256.Sum256(cert.Raw)
	fp := hex.EncodeToString(sum[:])

	cred, err := s.lookupCredential(ctx, fp)
	if err != nil {
		log.Printf("[agentserver] stream rejected: client cert %s: %v", fp[:16], err)
		return nil, status.Error(codes.Unauthenticated, "unknown client certificate")
	}
	ctx = context.WithValue(ctx, ctxKeyProjectID, cred.ProjectID)
	ctx = context.WithValue(ctx, ctxKeyCredentialID, cred.ID)
	ctx = context.WithValue(ctx, ctxKeyFingerprint, fp)
	if cred.HostBound() {
		ctx = withBinding(ctx, credentialBinding{hostID: cred.HostID, kind: cred.AgentKind, name: cred.AgentName})
	}
	return ctx, nil
}

// projectIDFrom returns the project_id from a context populated by the
// auth interceptor, or "" if missing.
func projectIDFrom(ctx context.Context) string {
	v, _ := ctx.Value(ctxKeyProjectID).(string)
	return v
}
func credentialIDFrom(ctx context.Context) string {
	v, _ := ctx.Value(ctxKeyCredentialID).(string)
	return v
}

// ─── Stream RPC ────────────────────────────────────────────────────────────

// Stream is the bidirectional connection. The first message MUST be Hello.
func (s *Server) Stream(stream agentv1.AgentControl_StreamServer) error {
	ctx := stream.Context()
	projectID := projectIDFrom(ctx)
	credID := credentialIDFrom(ctx)
	if projectID == "" || credID == "" {
		return status.Error(codes.Unauthenticated, "missing project context")
	}

	// Track the stream before anything else so a revoke from now on ends it, then re-read the
	// credential: a revoke that landed between the
	// interceptor's lookup and the tracking would otherwise be missed.
	live, untrack := s.trackLive(credID, projectID)
	defer untrack()
	fp, _ := ctx.Value(ctxKeyFingerprint).(string)
	if !s.credentialStillValid(ctx, fp, credID, projectID) {
		return errCredentialRevoked
	}
	rx := s.newStreamReceiver(stream, live, fp, credID, projectID)
	defer rx.close()

	// Wait for Hello.
	first, err := rx.recv()
	if err != nil {
		return err
	}
	hello := first.GetHello()
	if hello == nil {
		return status.Error(codes.InvalidArgument, "first message must be Hello")
	}

	// Validate Hello credentials before doing anything else. The mTLS
	// handshake already proved this stream belongs to projectID, but the
	// caller still has to prove its identity (agent_name for WAF agents;
	// host_key for eBPF/host agents).
	validate := s.validateHello
	if s.helloValidator != nil {
		validate = s.helloValidator
	}
	agentKind, ebpfAgentID, hostID, vErr := validate(ctx, projectID, hello)
	if vErr != nil {
		log.Printf("[agentserver] hello rejected project=%s name=%q: %v",
			projectID, hello.GetAgentName(), vErr)
		return vErr
	}
	// A revoke (or project delete) that landed while Hello was being
	// validated must not still get a Welcome and a bundle: look at the
	// disconnect signal and re-read the credential once more.
	if live.isRevoked() || !s.credentialStillValid(ctx, fp, credID, projectID) {
		log.Printf("[agentserver] credential revoked during hello, closing stream project=%s credential=%s", projectID, credID)
		return errCredentialRevoked
	}
	// Likewise for the host: bind the stream to it first, so a
	// revoke from now on reaches it, then re-read the host once.
	s.bindLive(live, hostID, ebpfAgentID)
	rx.hostID = hostID
	if live.hostRevokedNow() || !s.hostStillActive(ctx, projectID, hostID) {
		log.Printf("[agentserver] host revoked during hello, closing stream project=%s host=%s", projectID, hostID)
		return errHostRevoked
	}

	// The agent's id as the dashboard and the API show it (agents.id), not the credential's. A WAF
	// agent's row is resolved from its name; a host agent's was resolved by the Hello validation.
	resolvedAgentID := ebpfAgentID
	if resolvedAgentID == "" {
		resolvedAgentID = s.resolveAgentID(projectID, hello.GetAgentName())
	}

	// Send Welcome.
	now := time.Now().Unix()
	if err := stream.Send(&agentv1.ServerMessage{
		Kind: &agentv1.ServerMessage_Welcome{Welcome: &agentv1.Welcome{
			AgentId:          resolvedAgentID,
			ServerTimeUnix:   now,
			HeartbeatSeconds: 30,
		}},
	}); err != nil {
		return err
	}

	// Register stream so the server can push commands to it.
	sendMu := &sync.Mutex{}
	send := func(m *agentv1.ServerMessage) error {
		sendMu.Lock()
		defer sendMu.Unlock()
		return stream.Send(m)
	}
	if ebpfAgentID == "" {
		// DisconnectHost also matches streams by the host's agent ids.
		s.bindLive(live, hostID, resolvedAgentID)
	}
	rx.agentID = resolvedAgentID
	binding, bound := bindingFrom(ctx)
	if ebpfAgentID == "" {
		s.storeAgentFeatures(projectID, resolvedAgentID, hello.GetFeatures(), bound)
	}
	handle := &streamHandle{
		agentID:      resolvedAgentID,
		projectID:    projectID,
		credentialID: credID,
		agentName:    hello.GetAgentName(),
		hostname:     hello.GetHostname(),
		agentVersion: hello.GetAgentVersion(),
		connectedAt:  time.Now(),
		send:         send,
		agentKind:    agentKind,
		ebpfAgentID:  ebpfAgentID,
		hostID:       hostID,
		disconnect:   live.markStuck,
		features:     hello.GetFeatures(),
		binding:      binding,
		bound:        bound,
		peerIP:       peerIP(ctx),
		open:         func() bool { return ctx.Err() == nil && !live.ending() },
	}
	defer handle.stopDeliveries()
	// Register before loading the first bundle so a push that lands in between
	// reaches this connection rather than a predecessor with the same
	// credential. sendHostBundle rejects an older generation, so the initial
	// bundle cannot overwrite a newer pushed one.
	rx.handle = handle
	s.registerStream(handle)
	defer s.unregisterStream(handle)
	s.announceTelemetryDemand(handle)

	// Send initial bundle for WAF agents only. Host/eBPF agents don't need routing
	// config; sending a WAF bundle to them would be wasteful/confusing.
	if agentKind == "waf" && s.BundleLoader != nil {
		bundleJSON, gen, berr := s.BundleLoader.LoadBundle(ctx, projectID, hello.GetAgentName())
		if live.isRevoked() {
			// Revoked between Welcome and here: send no bundle; the receive
			// loop below returns Unauthenticated.
			bundleJSON = nil
		}
		if berr == nil && len(bundleJSON) > 0 {
			initMsg := &agentv1.ServerMessage{
				Kind: &agentv1.ServerMessage_Bundle{Bundle: &agentv1.BundleUpdate{
					CommandId:  fmt.Sprintf("init-%d", now),
					Generation: gen,
					BundleJson: handle.bundleForAgent(bundleJSON),
				}},
			}
			// Bounded like every push: a stuck initial Send marks the stream
			// stuck and the receive loop below ends it.
			_ = s.sendBounded(handle, func() error { return handle.sendHostBundle("waf_config", initMsg) })
		} else if berr != nil {
			log.Printf("[agentserver] bundle load for project=%s failed: %v", projectID, berr)
		}
	}

	log.Printf("[agentserver] agent connected: project=%s kind=%s credential=%s name=%q host=%q",
		projectID, agentKind, credID, hello.GetAgentName(), hello.GetHostname())

	// Push desired eBPF state on reconnect so the agent restores its configuration.
	// Delivery is retried until the agent acks "applied": a fire-and-forget
	// push here meant an agent that restarted under a deny-by-default port
	// policy came back with an empty rule table — every allow-listed port
	// stayed unreachable until the next config edit.
	if (agentKind == "host" || agentKind == "ebpf") && ebpfAgentID != "" {
		go func() {
			defer recoverPanic("push-ebpf-state-retry")
			const maxAttempts = 10
			for attempt := 1; attempt <= maxAttempts; attempt++ {
				ctx2, cancel := context.WithTimeout(context.Background(), 5*time.Second)
				state, err := s.Repo.EBPF.GetDesiredState(ctx2, ebpfAgentID)
				cancel()
				// An empty desired state ("{}") is pushed too: delivery spells
				// it out as an explicit reset (desiredStateForDelivery), so an
				// agent drops a saved policy the control plane no longer has
				// (e.g. a host deleted and re-registered).
				if err != nil {
					log.Printf("[agentserver] desired-state read failed agent=%s attempt=%d: %v", ebpfAgentID, attempt, err)
				} else {
					s.SendEBPFStateViaGRPC(ebpfAgentID, projectID, state)
				}
				time.Sleep(3 * time.Second)
				if s.EBPFStateApplied(ebpfAgentID, projectID) {
					log.Printf("[agentserver] ebpf state applied agent=%s attempt=%d", ebpfAgentID, attempt)
					return
				}
			}
			log.Printf("[agentserver] ebpf state push unconfirmed after %d attempts agent=%s", maxAttempts, ebpfAgentID)
		}()
	}

	// Touch agents.last_seen (and hosts.last_seen when bound to a host) on
	// connect so the dashboard flips ONLINE immediately, on every heartbeat,
	// and while the stream waits for the receive budget.
	touchLive := func() {
		s.touchStreamLiveness(projectID, ebpfAgentID, hello.GetAgentName(), hostID)
	}
	touchLive()
	rx.onStall = touchLive

	// Receive loop. Stops on EOF, context cancellation or revocation.
	lastBundleSource := ""
	badPayloadLogged := false
	for {
		msg, err := rx.recv()
		if err != nil {
			if errors.Is(err, errCredentialRevoked) {
				log.Printf("[agentserver] stream closed, credential revoked: project=%s credential=%s name=%q",
					projectID, credID, hello.GetAgentName())
				return err
			}
			if errors.Is(err, errStreamStuck) {
				log.Printf("[agentserver] stream closed, push send deadline exceeded: project=%s credential=%s name=%q",
					projectID, credID, hello.GetAgentName())
				return err
			}
			if errors.Is(err, context.Canceled) || ctx.Err() != nil {
				return nil
			}
			log.Printf("[agentserver] recv error project=%s: %v", projectID, err)
			return err
		}
		if hb := msg.GetHeartbeat(); hb != nil {
			// Heartbeats keep agents.last_seen (and hosts.last_seen) fresh
			// so the dashboard online indicator stays green.
			touchLive()
			// When the agent includes a HostInfo snapshot, persist it so
			// the dashboard's Host Info tab stays current.
			if len(hb.GetHostInfoJson()) > 0 {
				s.storeAgentHostInfo(projectID, hello.GetAgentName(), agentKind, hb.GetHostInfoJson())
			}
			// WAF agents report inspection-health counters (panics, partial
			// coverage, parse budget) for the WAF Agents page.
			if ebpfAgentID == "" {
				if _, ok := wafHealthFromHeartbeat(hb); ok {
					go s.storeWAFHealth(projectID, hello.GetAgentName(), hb)
				}
				// Bundle provenance is stored with the health counters
				// (migration 000099) and logged when it changes. Only the
				// sanitized value is logged: the raw field is agent-sent text
				// of any length and content.
				if src := bundleSource(hb.BundleSource); src != nil && *src != lastBundleSource {
					lastBundleSource = *src
					log.Printf("[agentserver] agent bundle source=%q generation=%d project=%s name=%q",
						lastBundleSource, hb.GetBundleGeneration(), projectID, hello.GetAgentName())
				}
			}
			continue
		}
		if dec := msg.GetDecision(); dec != nil {
			s.enrichDecision(projectID, dec)
			rawURI := redactDecisionAtIngest(dec)
			s.persistDecision(projectID, hello.GetAgentName(), dec)
			s.Broker.Publish(projectID, dec)
			if dec.GetAction() == "block" {
				s.enqueueBlockRaw(projectID, hello.GetAgentName(), dec, rawURI)
			}
			continue
		}
		if ack := msg.GetAck(); ack != nil {
			if ack.GetCommandId() == hostPolicySourceCommandID {
				handle.recordPolicySource(ack.GetError())
				continue
			}
			handle.recordHostBundleAck(ack)
			s.recordUnblockAck(handle, ack)
			s.recordCertificateInstallAck(handle, ack)
			// eBPF telemetry batches are sent as CommandAck with a special
			// command_id so we can reuse the existing proto message without
			// a schema change.
			if (ack.GetCommandId() == "ebpf:telemetry" || ack.GetCommandId() == "ebpf:telemetry:v2") && (agentKind == "ebpf" || agentKind == "host") && s.EBPFIngest != nil {
				payload := []byte(ack.GetError()) // Error field carries the JSON payload
				if gz := ack.GetPayload(); len(gz) > 0 && ack.GetCommandId() == "ebpf:telemetry:v2" {
					// gzip of the JSON: charged at its
					// inflated size before it is inflated. Accepted only on
					// a host-agent stream whose Hello claimed the
					// telemetry_demand feature — the streams
					// announceTelemetryDemand offers gzip to. This checks
					// the agent's own claim, not that an announcement was
					// sent or received: an agent claiming the feature may
					// send gzip at once, and it is charged like any other.
					// A batch on any other stream is dropped uninflated and
					// uncharged.
					var ierr error
					if !handle.supportsTelemetryDemand() {
						payload, ierr = nil, errBadTelemetryPayload
					} else {
						payload, ierr = rx.inflateTelemetry(gz)
					}
					if ierr != nil {
						if !errors.Is(ierr, errBadTelemetryPayload) {
							return ierr // revoked, stuck or ended while waiting
						}
						if !badPayloadLogged {
							badPayloadLogged = true
							log.Printf("[agentserver] dropped a malformed compressed telemetry batch project=%s agent=%s (logged once per stream)", projectID, ebpfAgentID)
						}
						continue
					}
				}
				if len(payload) > 0 {
					ingestCtx, ingestCancel := context.WithTimeout(context.Background(), 5*time.Second)
					s.ingestHostTelemetry(ingestCtx, handle, projectID, ebpfAgentID, hostID, payload, ack.GetCommandId() == "ebpf:telemetry:v2")
					ingestCancel()
				}
			}
			// Agents send a component-status report on connect so the
			// dashboard can display their installed security-data files.
			if ack.GetCommandId() == "secdata:status" {
				payload := ack.GetError() // Error field carries the JSON payload (same pattern as eBPF telemetry)
				if payload != "" {
					var status map[string]AgentComponentInfo
					if jsonErr := json.Unmarshal([]byte(payload), &status); jsonErr == nil {
						s.setAgentComponentStatus(handle, status)
						log.Printf("[agentserver] agent %q reported component status: %v", handle.agentName, status)
					}
				}
			}
			continue
		}
		if cs := msg.GetCertificateStatus(); cs != nil {
			s.handleCertificateStatus(handle, cs)
			continue
		}
		// Unknown messages are tolerated for forward-compat.
	}
}

// ─── Listen / Serve ────────────────────────────────────────────────────────

// ListenAndServe binds to addr with the supplied TLS config and serves
// the AgentControl service until ctx is canceled.
func (s *Server) ListenAndServe(ctx context.Context, addr string, tlsCfg *tls.Config) error {
	gs := s.newGRPCServer(tlsCfg)
	agentv1.RegisterAgentControlServer(gs, s)

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return fmt.Errorf("agentserver listen %s: %w", addr, err)
	}
	log.Printf("agent gRPC mTLS listening on %s", addr)
	return s.serve(ctx, gs, ln)
}

func (s *Server) newGRPCServer(tlsCfg *tls.Config) *grpc.Server {
	return grpc.NewServer(
		grpc.Creds(credentials.NewTLS(tlsCfg)),
		// Recovery first so it also covers auth.
		grpc.ChainStreamInterceptor(recoveryStreamInterceptor(), s.authStreamInterceptor()),
		grpc.ChainUnaryInterceptor(recoveryUnaryInterceptor()),
		// 8 MB after decompression (grpc-go applies it to the decompressed
		// size): host telemetry batches and rule hit-count lists.
		grpc.MaxRecvMsgSize(8<<20),
		// An agent needs its Stream plus a few downloads per connection;
		// more streams only multiply what one connection can hold
		// (receive budget).
		grpc.MaxConcurrentStreams(16),
		// Backstop for credential revocation: every connection is
		// re-authenticated at least once a day.
		grpc.KeepaliveParams(keepalive.ServerParameters{
			MaxConnectionAge:      grpcMaxConnectionAge,
			MaxConnectionAgeGrace: grpcMaxConnectionAgeGrace,
			// Ping an agent that has gone quiet, and drop the
			// connection if it does not answer, so a dead path (NAT or LB
			// timeout, host gone) does not hold a stream slot forever.
			Time:    grpcServerKeepaliveTime,
			Timeout: grpcServerKeepaliveTimeout,
		}),
		// Agents ping every 30 s (shared/agentcore/grpc_reconnect.go); allow
		// that with margin, and close a client pinging far faster.
		grpc.KeepaliveEnforcementPolicy(keepalive.EnforcementPolicy{
			MinTime:             grpcKeepaliveMinClientPing,
			PermitWithoutStream: true,
		}),
	)
}

// Serve is ListenAndServe on an existing listener (tests bind port 0).
func (s *Server) Serve(ctx context.Context, ln net.Listener, tlsCfg *tls.Config) error {
	gs := s.newGRPCServer(tlsCfg)
	agentv1.RegisterAgentControlServer(gs, s)
	return s.serve(ctx, gs, ln)
}

func (s *Server) serve(ctx context.Context, gs *grpc.Server, ln net.Listener) error {
	stopped := make(chan struct{})
	go func() {
		defer recoverPanic("grpc-graceful-stop")
		defer close(stopped)
		<-ctx.Done()
		stopGRPC(gs, s.gracefulStopWait())
	}()
	s.serving.Store(true)
	err := gs.Serve(ln)
	s.serving.Store(false)
	if ctx.Err() != nil {
		// Serve returns as soon as the listener closes; wait until the open
		// streams are gone too, so the caller can drain the writers behind
		// them.
		<-stopped
	}
	if err != nil && !errors.Is(err, grpc.ErrServerStopped) {
		return err
	}
	return nil
}

// defaultGracefulStopWait bounds GracefulStop. Agent streams are long-lived
// and never finish on their own, so an unbounded GracefulStop waited forever
// while shutdown closed the writers and the pool underneath them.
const defaultGracefulStopWait = 10 * time.Second

// gRPC keepalive.
const (
	grpcServerKeepaliveTime    = 60 * time.Second
	grpcServerKeepaliveTimeout = 20 * time.Second
	grpcKeepaliveMinClientPing = 15 * time.Second
)

func (s *Server) gracefulStopWait() time.Duration {
	if s != nil && s.GracefulStopWait > 0 {
		return s.GracefulStopWait
	}
	return defaultGracefulStopWait
}

// stopGRPC tries GracefulStop for up to wait, then forces Stop.
func stopGRPC(gs *grpc.Server, wait time.Duration) {
	done := make(chan struct{})
	go func() {
		gs.GracefulStop()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(wait):
		log.Printf("agent gRPC: graceful stop exceeded %v, closing remaining streams", wait)
		gs.Stop()
		<-done
	}
}

// BroadcastFetchSecurityData sends a FetchSecurityData command to all connected agents.
// Returns the number of agents that received the command.
func (s *Server) BroadcastFetchSecurityData(components []string, force bool) int {
	if s == nil {
		return 0
	}

	msg := &agentv1.ServerMessage{
		Kind: &agentv1.ServerMessage_FetchSecurityData{
			FetchSecurityData: &agentv1.FetchSecurityData{
				CommandId:               fmt.Sprintf("fsd-%d", time.Now().UnixNano()),
				Components:              strings.Join(components, ","),
				Force:                   force,
				MalwareFromControlPlane: true,
			},
		},
	}

	handles := s.streamsWhere(func(*streamHandle) bool { return true })
	return s.fanOut(handles, "fetch-security-data", func(h *streamHandle) error { return h.send(msg) })
}

// PushSelfUpdateToAgent, BroadcastSelfUpdate and the connected-version helpers
// were removed with the SelfUpdate proto message: the control-plane push-update
// path never had a caller and shipped full binaries over the wire.
// Agents update via the signed wafio.cloud release channel + operator install.

// registerStream makes h the push target for its credential. A newer
// connection with the same credential (tableflip reload, replicas sharing a
// certificate) replaces an older one.
func (s *Server) registerStream(h *streamHandle) {
	s.mu.Lock()
	s.streams[h.credentialID] = h
	s.mu.Unlock()
}

// unregisterStream removes h and its cached component status, but only while
// h still owns the credential's slot: an older connection closing after a
// newer one registered must not unhook the newer one.
//
// Lock order agentCompMu -> mu, as in GetAgentComponentStatusPerAgent.
func (s *Server) unregisterStream(h *streamHandle) {
	// An ack can no longer come from this stream, so its installs need not wait out their timeout.
	s.dropCertInstallsOf(h)
	s.agentCompMu.Lock()
	defer s.agentCompMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.streams[h.credentialID] != h {
		return
	}
	delete(s.streams, h.credentialID)
	delete(s.agentCompStatus, h.credentialID)
}

// setAgentComponentStatus caches a component-status report from h. A report
// from a connection that no longer owns the credential is dropped so it
// cannot overwrite the current connection's report.
func (s *Server) setAgentComponentStatus(h *streamHandle, status map[string]AgentComponentInfo) {
	s.agentCompMu.Lock()
	defer s.agentCompMu.Unlock()
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.streams[h.credentialID] != h {
		return
	}
	// A v1 agent still lists the "crs" component (the rule set it downloaded);
	// no component of that name is shown.
	delete(status, "crs")
	s.agentCompStatus[h.credentialID] = status
}

// GetAgentComponentStatus returns a merged map of component info across all
// connected agents.  For each component, the entry from the most-recently
// connected agent that has it installed wins.
func (s *Server) GetAgentComponentStatus() map[string]AgentComponentInfo {
	s.agentCompMu.RLock()
	defer s.agentCompMu.RUnlock()
	merged := make(map[string]AgentComponentInfo)
	for _, status := range s.agentCompStatus {
		for comp, info := range status {
			if info.Exists {
				merged[comp] = info
			}
		}
	}
	return merged
}

// AgentComponentReport holds per-agent component status for multi-agent display.
type AgentComponentReport struct {
	AgentID      string                        `json:"agent_id"`
	ProjectID    string                        `json:"project_id"`
	AgentName    string                        `json:"agent_name"`
	CredentialID string                        `json:"credential_id"`
	AgentKind    string                        `json:"agent_kind"` // "waf" | "ebpf"
	Components   map[string]AgentComponentInfo `json:"components"`
}

// GetAgentComponentStatusPerAgent returns per-agent component status reports
// for all currently connected agents.
func (s *Server) GetAgentComponentStatusPerAgent() []AgentComponentReport {
	s.agentCompMu.RLock()
	defer s.agentCompMu.RUnlock()
	s.mu.RLock()
	defer s.mu.RUnlock()

	reports := make([]AgentComponentReport, 0, len(s.agentCompStatus))
	for credID, comps := range s.agentCompStatus {
		h, ok := s.streams[credID]
		if !ok || h.agentID == "" {
			continue
		}
		reports = append(reports, AgentComponentReport{AgentID: h.agentID, ProjectID: h.projectID, AgentName: h.agentName, CredentialID: credID, AgentKind: h.agentKind, Components: comps})
	}

	return reports
}

// ConnectionStats returns a snapshot of currently-connected agents for
// dashboard display.
type ConnectionStats struct {
	CredentialID string    `json:"credential_id"`
	ProjectID    string    `json:"project_id"`
	AgentName    string    `json:"agent_name"`
	Hostname     string    `json:"hostname"`
	ConnectedAt  time.Time `json:"connected_at"`
}

func (s *Server) Connections(projectID string) []ConnectionStats {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []ConnectionStats
	for _, h := range s.streams {
		if projectID != "" && h.projectID != projectID {
			continue
		}
		out = append(out, ConnectionStats{
			CredentialID: h.credentialID,
			ProjectID:    h.projectID,
			AgentName:    h.agentName,
			Hostname:     h.hostname,
			ConnectedAt:  h.connectedAt,
		})
	}
	return out
}

// PushTracePoliciesViaGRPC pushes all persisted trace policies for the given
// agent to the connected host agent stream as a BundleUpdate whose bundle_json
// contains {"trace_policies": [...]}. This is the gRPC replacement for the
// old HTTP-callback resync mechanism (which broke after callback_url removal).
//
// Pushes are serialised per agent and coalesced (a request arriving while a
// push for the agent is in progress causes one more push, which reads the
// rows afresh), and at most tracePushPerProject pushes of one project load
// and send at once (push_trace.go): a multi-host apply never queues its
// pushes in front of another tenant's.
func (s *Server) PushTracePoliciesViaGRPC(agentID, projectID string) {
	// Callers run this on its own goroutine; a panic must not kill the process.
	defer recoverPanic("push-trace-policies")
	if s == nil || agentID == "" {
		return
	}
	s.scheduleTracePush(agentID, projectID)
}

// pushTracePoliciesOnce loads the agent's trace policies and sends them.
func (s *Server) pushTracePoliciesOnce(agentID, projectID string) {
	defer recoverPanic("push-trace-policies")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	rows, err := s.Repo.EBPF.ListTracePoliciesByAgent(ctx, agentID)
	if err != nil {
		return
	}

	// Build a minimal slice of policy maps for the agent to consume.
	type policyEntry struct {
		ID                 int      `json:"id"`
		Name               string   `json:"name"`
		Description        string   `json:"description"`
		Enabled            bool     `json:"enabled"`
		EventTypes         []string `json:"event_types"`
		MinSeverity        string   `json:"min_severity"`
		MatchComm          string   `json:"match_comm"`
		MatchCommMode      string   `json:"match_comm_mode,omitempty"` // absent = legacy substring on the agent
		MatchFilename      string   `json:"match_filename"`
		MatchUID           *uint32  `json:"match_uid,omitempty"`
		MatchDestPort      string   `json:"match_dest_port"`
		MatchDestIP        string   `json:"match_dest_ip,omitempty"`
		Action             string   `json:"action"`
		KillAcknowledged   bool     `json:"kill_acknowledged,omitempty"`
		KernelEnforce      bool     `json:"kernel_enforce"`
		MITRETechniqueID   string   `json:"mitre_technique_id,omitempty"`
		MITRETechniqueName string   `json:"mitre_technique_name,omitempty"`
		MITRETactic        string   `json:"mitre_tactic,omitempty"`
		Severity           string   `json:"severity,omitempty"`
		Tags               []string `json:"tags,omitempty"`
	}
	policies := make([]policyEntry, 0, len(rows))
	for _, r := range rows {
		if r.PolicyID == nil || *r.PolicyID <= 0 {
			log.Printf("[agentserver] refuse invalid trace policy snapshot for agent=%s", agentID)
			return
		}
		var uid *uint32
		if r.MatchUID != nil {
			v := uint32(*r.MatchUID)
			uid = &v
		}
		policies = append(policies, policyEntry{
			ID:                 *r.PolicyID,
			Name:               r.Name,
			Description:        r.Description,
			Enabled:            r.Enabled,
			EventTypes:         r.EventTypes,
			MinSeverity:        r.MinSeverity,
			MatchComm:          r.MatchComm,
			MatchCommMode:      r.MatchCommMode,
			MatchFilename:      r.MatchFilename,
			MatchUID:           uid,
			MatchDestPort:      r.MatchDestPort,
			MatchDestIP:        r.MatchDestIP,
			Action:             r.Action,
			KillAcknowledged:   r.KillAcknowledged,
			KernelEnforce:      r.KernelEnforce || r.KernelEnforceRequested,
			MITRETechniqueID:   r.MITRETechniqueID,
			MITRETechniqueName: r.MITRETechniqueName,
			MITRETactic:        r.MITRETactic,
			Severity:           r.Severity,
			Tags:               r.Tags,
		})
	}

	bundle := map[string]any{"trace_policies": policies}
	bundleJSON, jerr := json.Marshal(bundle)
	if jerr != nil {
		return
	}

	nextGeneration := s.nextTracePushGeneration()
	msg := &agentv1.ServerMessage{
		Kind: &agentv1.ServerMessage_Bundle{Bundle: &agentv1.BundleUpdate{
			CommandId:  fmt.Sprintf("trace-policy-push-%d", time.Now().UnixNano()),
			Generation: nextGeneration,
			BundleJson: bundleJSON,
		}},
	}

	handles := s.streamsWhere(func(h *streamHandle) bool {
		return h.projectID == projectID && isHostAgentKind(h.agentKind) && h.ebpfAgentID == agentID
	})
	pushed := s.fanOut(handles, "push-trace-policies", func(h *streamHandle) error {
		if err := h.sendHostBundle("trace_policies", msg); err != nil {
			return err
		}
		log.Printf("[agentserver] pushed %d trace policies to agent=%s", len(policies), h.agentName)
		return nil
	})
	if pushed == 0 {
		log.Printf("[agentserver] no connected host agent found for agentID=%s to push policies", agentID)
	}
}

// PushBundleToProject loads the current bundle for projectID and pushes it
// to every connected WAF agent in that project. Called after any operation
// that changes the bundle (route creation/deletion, app update, etc.) so
// agents pick up changes immediately without waiting for a reconnect.
//
// Handles are copied under s.mu; loads and sends happen after it is
// released. The bundle is per agent name (each agent only gets its own
// routes), so it is loaded once per distinct name, not once per connection.
// Host/eBPF agents never receive a WAF bundle.
func (s *Server) PushBundleToProject(projectID string) {
	// Callers run this on its own goroutine; a panic must not kill the process.
	defer recoverPanic("push-bundle")
	if s == nil || s.BundleLoader == nil || projectID == "" {
		return
	}
	handles := s.streamsWhere(func(h *streamHandle) bool {
		return h.projectID == projectID && h.agentKind == "waf"
	})
	if len(handles) == 0 {
		return
	}
	// One message per agent name: the bundle does not depend on the agent, so two connections with the
	// same name (a tableflip upgrade overlapping its predecessor) get the same one.
	type loaded struct {
		msg *agentv1.ServerMessage
		ok  bool
	}
	msgs := make(map[string]loaded, len(handles))
	changed := make(map[string][]string, len(handles))
	for _, h := range handles {
		if _, done := msgs[h.agentName]; done {
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		agentBundle, agentGen, loadErr := s.BundleLoader.LoadBundle(ctx, projectID, h.agentName)
		cancel()
		if loadErr != nil {
			log.Printf("[agentserver] push-bundle load failed agent=%s: %v", h.agentName, loadErr)
			msgs[h.agentName] = loaded{}
			continue
		}
		bundle, legacy := engine.NormalizeBundle(agentBundle)
		changed[h.agentName] = legacy
		msgs[h.agentName] = loaded{ok: true, msg: &agentv1.ServerMessage{
			Kind: &agentv1.ServerMessage_Bundle{Bundle: &agentv1.BundleUpdate{
				CommandId:  fmt.Sprintf("push-%d", time.Now().UnixNano()),
				Generation: agentGen,
				BundleJson: bundle,
			}},
		}}
	}
	targets := handles[:0]
	for _, h := range handles {
		if msgs[h.agentName].ok {
			targets = append(targets, h)
		}
	}
	s.fanOut(targets, "push-bundle", func(h *streamHandle) error {
		msg := msgs[h.agentName].msg
		if err := h.sendHostBundle("waf_config", msg); err != nil {
			return err
		}
		h.noteChanges(changed[h.agentName])
		log.Printf("[agentserver] pushed bundle gen=%d to agent=%s", msg.GetBundle().GetGeneration(), h.agentName)
		return nil
	})
}

// isHostAgentKind reports whether kind is a host/eBPF agent.
func isHostAgentKind(kind string) bool { return kind == "host" || kind == "ebpf" }

// SendEBPFStateViaGRPC sends the full desired eBPF state (config, blocklist,
// allowlist, geo_blocked, port_policies, egress_blocklist) to the connected
// eBPF/host agent for agentID as a BundleUpdate message. The bundle_json
// payload has the form {"ebpf_state": {...}}. Fire-and-forget — the agent acks
// asynchronously via CommandAck.
func (s *Server) SendEBPFStateViaGRPC(agentID, projectID string, state json.RawMessage) {
	// Callers run this on its own goroutine; a panic must not kill the process.
	defer recoverPanic("push-ebpf-state")
	if s == nil || agentID == "" || len(state) == 0 {
		return
	}
	revision, revisionErr := repository.DesiredStateRevision(state)
	if revisionErr != nil {
		log.Printf("[agentserver] invalid desired-state revision agent=%s", agentID)
		return
	}
	if revision == 0 {
		if s.Repo == nil {
			return
		}
		initCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		stored, err := s.Repo.EBPF.CompareAndSwapDesiredState(initCtx, projectID, agentID, 0, state)
		if errors.Is(err, repository.ErrDesiredStateConflict) {
			stored, err = s.Repo.EBPF.GetDesiredState(initCtx, agentID)
		}
		cancel()
		if err != nil {
			log.Printf("[agentserver] desired-state revision initialization failed agent=%s: %v", agentID, err)
			return
		}
		state = stored
		revision, revisionErr = repository.DesiredStateRevision(state)
		if revisionErr != nil || revision <= 0 {
			return
		}
	}
	state, revisionErr = desiredStateForDelivery(state)
	if revisionErr != nil {
		return
	}
	bundle := make(map[string]json.RawMessage)
	bundle["ebpf_state"] = state
	bundleJSON, err := json.Marshal(bundle)
	if err != nil {
		return
	}
	msg := &agentv1.ServerMessage{
		Kind: &agentv1.ServerMessage_Bundle{Bundle: &agentv1.BundleUpdate{
			CommandId:  fmt.Sprintf("ebpf-state-%d", time.Now().UnixNano()),
			Generation: revision,
			BundleJson: bundleJSON,
		}},
	}
	handles := s.streamsWhere(func(h *streamHandle) bool {
		return h.projectID == projectID && isHostAgentKind(h.agentKind) && h.ebpfAgentID == agentID
	})
	s.fanOut(handles, "send-ebpf-state", func(h *streamHandle) error {
		if err := h.sendHostBundle("ebpf_state", msg); err != nil {
			return err
		}
		log.Printf("[agentserver] sent ebpf state to agent=%s", h.agentName)
		return nil
	})
}
