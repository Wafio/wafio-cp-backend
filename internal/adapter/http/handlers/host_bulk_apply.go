package handlers

// Multi-host apply: a
// one-shot fan-out of the same per-host write the single-host endpoints do.
// The request names hosts, or a label resolved once, now; each
// host's desired state stays its only policy source. The lockout guard runs
// per host with that host's sshd ports and features, there is no force flag,
// and a refusal stays on that host. Partial failure is reported per host in
// a 200; re-sending the request, or only the failed hosts, is safe.

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"maps"
	"strings"
	"sync"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/google/uuid"
	"github.com/wafio/wafio-cp-backend/internal/adapter/http/auth"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	"github.com/wafio/wafio-cp-backend/internal/domain"
	"github.com/wafio/wafio-cp-backend/shared/hostpolicy"
)

// Execution bounds (variables so tests can shrink them).
var (
	bulkApplyWorkers  = 8
	bulkApplyDeadline = 25 * time.Second // inside the 30 s request context
	bulkAuditTimeout  = 5 * time.Second
	// bulkBeforeStore runs between a host's guard and its CAS store (tests
	// only: forcing conflicts and slow hosts); nil in production.
	bulkBeforeStore func(agentID string)
)

// Item caps per request.
const (
	maxApplyIPEntries   = 10000
	maxApplyPortRules   = 100
	maxApplyPolicyItems = 50
)

// Per-host result statuses.
const (
	applyApplied    = "applied"
	applyWouldApply = "would_apply"
	applyUnchanged  = "unchanged"
	applyFailed     = "failed"
	applySkipped    = "skipped"
)

// applyLocks holds one entry per project with an apply or dry run in flight
// (the control plane is a single instance): a project runs one
// apply request at a time, dry runs included, so parallel dry runs cannot
// multiply its workers.
var applyLocks sync.Map

// bulkApplySlots bounds the hosts being applied at once across every project
// and request (one slot per host in progress). A worker waits for a slot until
// the request's deadline; a host that gets none is skipped with DEADLINE, as a
// host not started in time.
var bulkApplySlots = make(chan struct{}, 16)

// acquireApplySlot takes a process-wide slot, waiting until deadline or the
// end of ctx; ok is false when none came free.
func acquireApplySlot(ctx context.Context, deadline time.Time) (release func(), ok bool) {
	select {
	case bulkApplySlots <- struct{}{}:
		return func() { <-bulkApplySlots }, true
	default:
	}
	wait := time.Until(deadline)
	if wait <= 0 {
		return nil, false
	}
	timer := time.NewTimer(wait)
	defer timer.Stop()
	select {
	case bulkApplySlots <- struct{}{}:
		return func() { <-bulkApplySlots }, true
	case <-timer.C:
		return nil, false
	case <-ctx.Done():
		return nil, false
	}
}

// tryLockApply takes the project's apply lock; ok is false when another
// apply of the project is running.
func tryLockApply(projectID string) (unlock func(), ok bool) {
	if _, busy := applyLocks.LoadOrStore(projectID, struct{}{}); busy {
		return nil, false
	}
	return func() { applyLocks.Delete(projectID) }, true
}

// bulkReqError is a request-level refusal of an apply (no host touched).
type bulkReqError struct {
	status int
	code   string
	msg    string
	extra  fiber.Map
}

func (e *bulkReqError) Error() string { return e.msg }

func bulkBadRequest(code string, err error, fallback string) *bulkReqError {
	return &bulkReqError{status: fiber.StatusBadRequest, code: code, msg: clientText(err, fallback)}
}

var (
	errApplyHostNotFound = &bulkReqError{status: fiber.StatusNotFound, code: "HOST_NOT_FOUND", msg: "Host not found."}
	errApplyInProgress   = &bulkReqError{status: fiber.StatusConflict, code: "APPLY_IN_PROGRESS",
		msg: "Another apply or preview is running in this project; wait for it to finish and retry."}
)

// writeBulkError answers a bulkReqError, or a generic 500 for anything else.
func writeBulkError(c *fiber.Ctx, err error) error {
	var be *bulkReqError
	if errors.As(err, &be) {
		if be.status == fiber.StatusBadRequest {
			slog.Info("request_rejected", "path", c.Path(), "status", be.status, "code", be.code)
		}
		body := fiber.Map{"error": be.msg, "code": be.code}
		maps.Copy(body, be.extra)
		return c.Status(be.status).JSON(body)
	}
	slog.Error("bulk_apply_failed", "path", c.Path(), "err", err)
	return c.Status(fiber.StatusInternalServerError).JSON(fiber.Map{"error": "internal error", "code": "INTERNAL_ERROR"})
}

// hostTargetsReq is the target selector: exactly one of host_ids or label.
type hostTargetsReq struct {
	HostIDs []string          `json:"host_ids"`
	Label   *labelSelectorReq `json:"label"`
}

type labelSelectorReq struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// checkTargets validates the selector's shape (no database access).
func checkTargets(t hostTargetsReq) (ids []string, label *domain.LabelSelector, err error) {
	if (t.HostIDs == nil) == (t.Label == nil) {
		return nil, nil, bulkBadRequest("INVALID_TARGETS", errors.New("targets must name exactly one of host_ids or label"), "")
	}
	if t.Label != nil {
		if err := validateHostLabelKey(t.Label.Key); err != nil {
			return nil, nil, bulkBadRequest("INVALID_LABELS", err, "The label is invalid.")
		}
		v, err := normalizeHostLabelValue(t.Label.Key, t.Label.Value)
		if err != nil {
			return nil, nil, bulkBadRequest("INVALID_LABELS", err, "The label is invalid.")
		}
		return nil, &domain.LabelSelector{Key: t.Label.Key, Value: v}, nil
	}
	ids, perr := parseTargetHostIDs(t.HostIDs)
	if perr != nil {
		return nil, nil, bulkBadRequest("INVALID_TARGETS", perr, "")
	}
	return ids, nil, nil
}

// resolveTargets turns a checked selector into hosts of the project: an id
// outside the project is a 404 for the whole request; a label matching no
// non-revoked host is NO_TARGETS, more than 1,000 TOO_MANY_TARGETS.
func resolveTargets(ctx context.Context, repo *repository.Repository, projectID string, ids []string, label *domain.LabelSelector) ([]domain.ApplyTarget, error) {
	targets, matched, err := repo.HostFleet.ApplyTargets(ctx, projectID, ids, label, domain.MaxApplyTargets)
	if err != nil {
		return nil, err
	}
	if label != nil {
		switch {
		case matched == 0:
			return nil, &bulkReqError{status: fiber.StatusBadRequest, code: "NO_TARGETS", msg: "No host of this project carries that label."}
		case matched > domain.MaxApplyTargets:
			return nil, &bulkReqError{status: fiber.StatusBadRequest, code: "TOO_MANY_TARGETS",
				msg:   fmt.Sprintf("The label matches more than %d hosts; narrow the selection.", domain.MaxApplyTargets),
				extra: fiber.Map{"matched": matched}}
		}
		return targets, nil
	}
	if len(targets) != len(ids) {
		return nil, errApplyHostNotFound
	}
	return targets, nil
}

// targetsAuditMeta describes the selector for the summary audit row.
func targetsAuditMeta(ids []string, label *domain.LabelSelector, n int) map[string]any {
	if label != nil {
		return map[string]any{"label": map[string]string{"key": label.Key, "value": label.Value}, "hosts": n}
	}
	return map[string]any{"host_ids": ids, "hosts": n}
}

// bulkActor is who sent the request, captured before the workers start
// (a fiber.Ctx must not be used from other goroutines).
type bulkActor struct {
	userID, ip, userAgent string
}

func actorOf(c *fiber.Ctx) bulkActor {
	userID, _ := c.Locals(auth.UserIDKey).(string)
	return bulkActor{userID: userID, ip: c.IP(), userAgent: string(c.Request().Header.UserAgent())}
}

// auditDetached writes an audit row on a context detached from the request,
// so a host whose state was written gets its row even past the deadline.
func auditDetached(ctx context.Context, repo *repository.Repository, ev repository.AuditEvent) {
	if repo == nil || repo.Audit == nil {
		return
	}
	actx, cancel := context.WithTimeout(context.WithoutCancel(ctx), bulkAuditTimeout)
	defer cancel()
	_ = repo.Audit.Log(actx, ev)
}

// hostApplyResult is one host's outcome.
type hostApplyResult struct {
	HostID      string                       `json:"host_id"`
	HostName    string                       `json:"host_name"`
	AgentID     string                       `json:"agent_id,omitempty"`
	AgentOnline *bool                        `json:"agent_online,omitempty"`
	Status      string                       `json:"status"`
	Code        string                       `json:"code"`
	Error       string                       `json:"error"`
	Warnings    []hostpolicy.FirewallWarning `json:"warnings"`
	Count       *int                         `json:"count,omitempty"`
	Created     *int                         `json:"created,omitempty"`
	Replaced    *int                         `json:"replaced,omitempty"`
	Existing    *int                         `json:"existing,omitempty"`
}

func newApplyResult(t domain.ApplyTarget, now time.Time) hostApplyResult {
	r := hostApplyResult{HostID: t.HostID, HostName: t.HostName, Warnings: []hostpolicy.FirewallWarning{}}
	if t.AgentID != "" {
		r.AgentID = t.AgentID
		online := domain.AgentOnlineAt(t.AgentLastSeen, now)
		r.AgentOnline = &online
	}
	return r
}

func (r hostApplyResult) skip(code string) hostApplyResult {
	r.Status, r.Code = applySkipped, code
	return r
}

func (r hostApplyResult) fail(code, msg string) hostApplyResult {
	r.Status, r.Code, r.Error = applyFailed, code, msg
	return r
}

func intp(n int) *int { return &n }

// applySummary counts results by status.
type applySummary struct {
	Applied    int `json:"applied"`
	WouldApply int `json:"would_apply"`
	Unchanged  int `json:"unchanged"`
	Failed     int `json:"failed"`
	Skipped    int `json:"skipped"`
}

func summarize(results []hostApplyResult) applySummary {
	var s applySummary
	for _, r := range results {
		switch r.Status {
		case applyApplied:
			s.Applied++
		case applyWouldApply:
			s.WouldApply++
		case applyUnchanged:
			s.Unchanged++
		case applyFailed:
			s.Failed++
		case applySkipped:
			s.Skipped++
		}
	}
	return s
}

// runApply runs fn for every target on bulkApplyWorkers workers, results in
// target order. A host not started within bulkApplyDeadline is skipped with
// DEADLINE; a started host finishes on the request context. A panic in fn
// fails that host only.
func runApply(ctx context.Context, targets []domain.ApplyTarget, now time.Time,
	fn func(ctx context.Context, t domain.ApplyTarget) hostApplyResult) []hostApplyResult {
	results := make([]hostApplyResult, len(targets))
	deadline := time.Now().Add(bulkApplyDeadline)
	jobs := make(chan int)
	var wg sync.WaitGroup
	workers := min(bulkApplyWorkers, len(targets))
	for w := 0; w < workers; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := range jobs {
				if ctx.Err() != nil || !time.Now().Before(deadline) {
					results[i] = newApplyResult(targets[i], now).skip("DEADLINE")
					continue
				}
				release, ok := acquireApplySlot(ctx, deadline)
				if !ok {
					results[i] = newApplyResult(targets[i], now).skip("DEADLINE")
					continue
				}
				results[i] = runOne(ctx, targets[i], now, fn)
				release()
			}
		}()
	}
	for i := range targets {
		jobs <- i
	}
	close(jobs)
	wg.Wait()
	return results
}

func runOne(ctx context.Context, t domain.ApplyTarget, now time.Time,
	fn func(ctx context.Context, t domain.ApplyTarget) hostApplyResult) (r hostApplyResult) {
	defer func() {
		if p := recover(); p != nil {
			slog.Error("bulk_apply_host_panic", "host_id", t.HostID, "panic", fmt.Sprint(p))
			r = newApplyResult(t, now).fail("INTERNAL_ERROR", "internal error")
		}
	}()
	return fn(ctx, t)
}

// bulkApplyRun is the shared tail of the three apply routes: resolve, lock,
// fan out, summary audit, response.
type bulkApplyRun struct {
	repo      *repository.Repository
	projectID string
	op        string
	dryRun    bool
	ids       []string
	label     *domain.LabelSelector
	actor     bulkActor
	// perHost gets the apply id ("" for a dry run).
	perHost func(ctx context.Context, applyID string, t domain.ApplyTarget, now time.Time) hostApplyResult
	// sourceDigest is set for a copy from a source host (source_digest in
	// the response); "" omits it.
	sourceDigest string
}

func (b *bulkApplyRun) run(c *fiber.Ctx) error {
	ctx := c.UserContext()
	unlock, ok := tryLockApply(b.projectID)
	if !ok {
		return writeBulkError(c, errApplyInProgress)
	}
	defer unlock()
	targets, err := resolveTargets(ctx, b.repo, b.projectID, b.ids, b.label)
	if err != nil {
		return writeBulkError(c, err)
	}
	applyID := ""
	if !b.dryRun {
		applyID = uuid.NewString()
	}
	now := time.Now()
	results := runApply(ctx, targets, now, func(ctx context.Context, t domain.ApplyTarget) hostApplyResult {
		return b.perHost(ctx, applyID, t, now)
	})
	summary := summarize(results)
	var applyIDOut any
	if !b.dryRun {
		applyIDOut = applyID
		auditDetached(ctx, b.repo, repository.AuditEvent{
			ProjectID: b.projectID, ActorUserID: b.actor.userID,
			Action: repository.AuditHostBulkApply, TargetType: "project", TargetID: b.projectID,
			IP: b.actor.ip, UserAgent: b.actor.userAgent,
			MetadataJSON: map[string]any{"apply_id": applyID, "op": b.op,
				"targets": targetsAuditMeta(b.ids, b.label, len(targets)), "summary": summary},
		})
	}
	out := fiber.Map{
		"apply_id": applyIDOut, "op": b.op, "dry_run": b.dryRun,
		"results": results, "summary": summary, "total": len(results),
	}
	if b.sourceDigest != "" {
		out["source_digest"] = b.sourceDigest
	}
	return c.JSON(out)
}

// ── POST /hosts/apply/firewall ────────────────────────────────────────────

// Firewall apply operations (lists and port rules only: no geo, no mode
// settings).
const (
	opBlocklistAdd     = "blocklist.add"
	opBlocklistRemove  = "blocklist.remove"
	opAllowlistAdd     = "allowlist.add"
	opAllowlistRemove  = "allowlist.remove"
	opEgressAdd        = "egress_blocklist.add"
	opEgressRemove     = "egress_blocklist.remove"
	opPortPolicyAdd    = "port_policies.add"
	opPortPolicyRemove = "port_policies.remove"
)

type firewallApplyBody struct {
	Targets  hostTargetsReq  `json:"targets"`
	Op       string          `json:"op"`
	Entries  json.RawMessage `json:"entries"`
	Policies json.RawMessage `json:"policies"`
	DryRun   bool            `json:"dry_run"`
}

// firewallApplyOp is a validated firewall operation.
type firewallApplyOp struct {
	op       string
	entries  []hostpolicy.IPEntry       // *.add list ops
	ips      []string                   // *.remove list ops
	policies []hostpolicy.PortPolicyAPI // port ops (keys only for remove)
	scoped   bool                       // allowlist.add with ports
}

func rawPresent(raw json.RawMessage) bool {
	s := strings.TrimSpace(string(raw))
	return s != "" && s != "null"
}

// parseFirewallApplyOp validates the operation and its items once, before
// any host is touched.
func parseFirewallApplyOp(body firewallApplyBody) (*firewallApplyOp, error) {
	op := &firewallApplyOp{op: body.Op}
	switch body.Op {
	case opBlocklistAdd, opBlocklistRemove, opAllowlistAdd, opAllowlistRemove, opEgressAdd, opEgressRemove:
		if rawPresent(body.Policies) || !rawPresent(body.Entries) {
			return nil, bulkBadRequest("BAD_REQUEST", errors.New("this operation takes entries"), "")
		}
		var entries []hostpolicy.IPEntry
		if err := json.Unmarshal(body.Entries, &entries); err != nil || len(entries) == 0 {
			return nil, bulkBadRequest("BAD_REQUEST", errors.New("entries must be a non-empty list of {ip}"), "")
		}
		if len(entries) > maxApplyIPEntries {
			return nil, bulkBadRequest("BAD_REQUEST", fmt.Errorf("an apply takes at most %d entries", maxApplyIPEntries), "")
		}
		return op, op.checkEntries(entries)
	case opPortPolicyAdd, opPortPolicyRemove:
		if rawPresent(body.Entries) || !rawPresent(body.Policies) {
			return nil, bulkBadRequest("BAD_REQUEST", errors.New("this operation takes policies"), "")
		}
		var policies []hostpolicy.PortPolicyAPI
		if err := json.Unmarshal(body.Policies, &policies); err != nil || len(policies) == 0 {
			return nil, bulkBadRequest("BAD_REQUEST", errors.New("policies must be a non-empty list of port rules"), "")
		}
		if len(policies) > maxApplyPortRules {
			return nil, bulkBadRequest("BAD_REQUEST", fmt.Errorf("an apply takes at most %d port rules", maxApplyPortRules), "")
		}
		for i, p := range policies {
			if body.Op == opPortPolicyRemove {
				if p.Port == 0 {
					return nil, bulkBadRequest("PORT_POLICY_INVALID", errors.New("a port rule to remove names its port"), "")
				}
				policies[i] = hostpolicy.PortPolicyAPI{Port: p.Port, Proto: p.Proto, Direction: p.Direction}
				continue
			}
			if err := hostpolicy.ValidatePortPolicyRule(p); err != nil {
				code, ok := hostpolicy.FirewallErrorCode(err)
				if !ok {
					code = "PORT_POLICY_INVALID"
				}
				return nil, bulkBadRequest(code, err, "The port rule is invalid.")
			}
			policies[i] = hostpolicy.CanonicalPortPolicy(p)
		}
		op.policies = policies
		return op, nil
	default:
		return nil, bulkBadRequest("INVALID_OP", errors.New("op must be one of blocklist.add, blocklist.remove, allowlist.add, "+
			"allowlist.remove, egress_blocklist.add, egress_blocklist.remove, port_policies.add, port_policies.remove"), "")
	}
}

// checkEntries validates the IP items of a list operation.
func (op *firewallApplyOp) checkEntries(entries []hostpolicy.IPEntry) error {
	switch op.op {
	case opAllowlistAdd:
		checked, scoped, perr := checkAllowlistEntries(entries)
		if perr != nil {
			return bulkBadRequest(perr.code, perr.err, "The request contains an invalid value.")
		}
		op.entries, op.scoped = checked, scoped
	case opBlocklistAdd, opEgressAdd:
		// The last spelling of a repeated ip wins (a single-host add would
		// store both).
		seen := map[string]int{}
		for _, e := range entries {
			if err := validateIPEntry(e.IP); err != nil {
				return bulkBadRequest("INVALID_IP", err, "The request contains an invalid value.")
			}
			e.IP = strings.TrimSpace(e.IP)
			e.Ports = nil
			if i, ok := seen[e.IP]; ok {
				op.entries[i] = e
				continue
			}
			seen[e.IP] = len(op.entries)
			op.entries = append(op.entries, e)
		}
	default: // removes: exact ip strings, as the single-host delete
		for _, e := range entries {
			if strings.TrimSpace(e.IP) == "" {
				return bulkBadRequest("INVALID_IP", errors.New("every entry names an ip"), "")
			}
			op.ips = append(op.ips, e.IP)
		}
	}
	return nil
}

// ApplyFirewall applies one firewall list or port-rule change to many hosts.
//
//	POST /api/projects/:id/hosts/apply/firewall
func (h *HostPolicyHandler) ApplyFirewall(c *fiber.Ctx) error {
	projectID := c.Params("id")
	var body firewallApplyBody
	if err := json.Unmarshal(c.Body(), &body); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body", "code": "BAD_REQUEST"})
	}
	ids, label, err := checkTargets(body.Targets)
	if err != nil {
		return writeBulkError(c, err)
	}
	op, err := parseFirewallApplyOp(body)
	if err != nil {
		return writeBulkError(c, err)
	}
	actor := actorOf(c)
	run := &bulkApplyRun{repo: h.Repo, projectID: projectID, op: op.op, dryRun: body.DryRun, ids: ids, label: label, actor: actor,
		perHost: func(ctx context.Context, applyID string, t domain.ApplyTarget, now time.Time) hostApplyResult {
			return h.applyFirewallToHost(ctx, projectID, t, op, body.DryRun, applyID, actor, now)
		}}
	return run.run(c)
}

// firewallMutation is the outcome of one operation on one desired state.
type firewallMutation struct {
	changed  bool
	count    int
	action   string
	meta     map[string]any
	warnings []hostpolicy.FirewallWarning
}

// mutate applies op to s with the shared single-host mutators. count is the
// number of entries the op wrote (adds: every item of the request, new or
// refreshed) or removed (removes: stored entries dropped, 0 when nothing
// matched).
func (op *firewallApplyOp) mutate(s *ebpfDesiredState, t domain.ApplyTarget, now time.Time) (firewallMutation, error) {
	m := firewallMutation{changed: true}
	switch op.op {
	case opBlocklistAdd:
		if err := addBlocklist(s, op.entries, now); err != nil {
			return m, err
		}
		m.count, m.action = len(op.entries), repository.AuditFirewallBlocklistAdded
		m.meta = map[string]any{"ips": ipEntryIPs(op.entries)}
	case opBlocklistRemove:
		m.count, m.action = removeBlocklist(s, op.ips), repository.AuditFirewallBlocklistRemoved
		m.meta = map[string]any{"ips": op.ips}
	case opAllowlistAdd:
		audit, err := addAllowlist(s, op.entries, now)
		if err != nil {
			return m, err
		}
		m.count, m.action = len(op.entries), repository.AuditFirewallAllowlistAdded
		m.meta = map[string]any{"ips": ipEntryIPs(op.entries), "entries": audit}
	case opAllowlistRemove:
		m.count, m.action = removeAllowlist(s, op.ips), repository.AuditFirewallAllowlistRemoved
		m.meta = map[string]any{"ips": op.ips}
		if geoAllowActive(s) {
			m.warnings = append(m.warnings, geoAllowAllowlistRemovedWarning)
		}
	case opEgressAdd:
		added, err := addEgressBlocklist(s, op.entries, now, func() bool { return t.EgressIPv6Supported })
		if err != nil {
			return m, err
		}
		m.count, m.action = added, repository.AuditFirewallEgressAdded
		m.meta = map[string]any{"count": added}
	case opEgressRemove:
		m.count, m.action = removeEgressBlocklist(s, op.ips), repository.AuditFirewallEgressRemoved
		m.meta = map[string]any{"count": m.count}
	case opPortPolicyAdd:
		addPortPolicies(s, op.policies)
		m.count, m.action = len(op.policies), repository.AuditFirewallPortPolicyAdded
		m.meta = map[string]any{"policies": portPolicyKeys(op.policies)}
	case opPortPolicyRemove:
		m.count, m.action = removePortPolicies(s, op.policies), repository.AuditFirewallPortPolicyRemoved
		m.meta = map[string]any{"policies": portPolicyKeys(op.policies)}
	}
	switch op.op {
	case opBlocklistRemove, opAllowlistRemove, opEgressRemove, opPortPolicyRemove:
		m.changed = m.count > 0
	}
	return m, nil
}

func ipEntryIPs(entries []hostpolicy.IPEntry) []string {
	out := make([]string, 0, len(entries))
	for _, e := range entries {
		out = append(out, e.IP)
	}
	return out
}

func portPolicyKeys(policies []hostpolicy.PortPolicyAPI) []any {
	out := make([]any, 0, len(policies))
	for _, p := range policies {
		out = append(out, map[string]any{"port": p.Port, "proto": p.Proto, "direction": p.Direction})
	}
	return out
}

// mutationFailure maps a mutator error to the single-host endpoint's code.
func mutationFailure(r hostApplyResult, err error) hostApplyResult {
	switch {
	case errors.Is(err, errEgressIPv6Unsupported):
		return r.fail("EGRESS_IPV6_UNSUPPORTED", err.Error())
	case errors.Is(err, hostpolicy.ErrIPListCapacity):
		return r.fail("IP_LIST_FULL", clientText(err, "The list is full; remove entries or merge addresses into prefixes."))
	default:
		return r.fail("INVALID_IP", clientText(err, "The request contains an invalid value."))
	}
}

// applyFirewallToHost is one host of a firewall apply: the single-host
// sequence (read, mutate, feature gate, capacity, lockout guard with this
// host's sshd ports and features, CAS store, push, audit).
func (h *HostPolicyHandler) applyFirewallToHost(ctx context.Context, projectID string, t domain.ApplyTarget, op *firewallApplyOp,
	dryRun bool, applyID string, actor bulkActor, now time.Time) hostApplyResult {
	r := newApplyResult(t, now)
	switch {
	case t.Revoked:
		return r.skip("HOST_REVOKED")
	case t.AgentID == "":
		return r.skip("NO_HOST_AGENT")
	case op.scoped && !containsString(t.FirewallFeatures, hostpolicy.AllowlistFeaturePorts):
		return r.fail("ALLOWLIST_PORTS_UNSUPPORTED", "The host agent has not reported support for port-scoped allowlist entries. "+
			"Update the host agent together with its eBPF objects, or add the entry for every port.")
	}
	for attempt := 0; ; attempt++ {
		s, err := h.readState(ctx, t.AgentID)
		if err != nil {
			return r.fail("STATE_UNAVAILABLE", "desired state unavailable")
		}
		m, err := op.mutate(s, t, now.UTC())
		if err != nil {
			return mutationFailure(r, err)
		}
		count := m.count
		r.Count = &count
		if !m.changed {
			r.Status = applyUnchanged
			return r
		}
		warnings, err := h.validateStateFor(s, t.SSHPorts, t.FirewallFeatures)
		if err != nil {
			if code, ok := hostpolicy.FirewallErrorCode(err); ok {
				return r.fail(code, clientText(err, "The firewall change would lock the host out."))
			}
			return r.fail("INVALID_IP", clientText(err, "The request contains an invalid value."))
		}
		r.Warnings = append(r.Warnings, warnings...)
		r.Warnings = append(r.Warnings, m.warnings...)
		if dryRun {
			r.Status = applyWouldApply
			return r
		}
		if bulkBeforeStore != nil {
			bulkBeforeStore(t.AgentID)
		}
		if err := h.storeState(ctx, t.AgentID, projectID, s); err != nil {
			if errors.Is(err, repository.ErrDesiredStateConflict) {
				if attempt == 0 {
					r.Warnings = []hostpolicy.FirewallWarning{}
					continue
				}
				return r.fail("STATE_CONFLICT", "desired state changed; reload and retry")
			}
			slog.Error("bulk_apply_store_failed", "agent_id", t.AgentID, "err", err)
			return r.fail("INTERNAL_ERROR", "internal error")
		}
		meta := maps.Clone(m.meta)
		meta["apply_id"] = applyID
		auditDetached(ctx, h.Repo, repository.AuditEvent{
			ProjectID: projectID, ActorUserID: actor.userID,
			Action: m.action, TargetType: "agent", TargetID: t.AgentID,
			IP: actor.ip, UserAgent: actor.userAgent, MetadataJSON: meta,
		})
		r.Status = applyApplied
		return r
	}
}

// ── POST /hosts/apply/trace-policies ──────────────────────────────────────

type tracePolicyApplyBody struct {
	Targets hostTargetsReq `json:"targets"`
	Source  *struct {
		HostID    string `json:"host_id"`
		PolicyIDs []int  `json:"policy_ids"`
	} `json:"source"`
	Policies     []hostpolicy.EnforcementPolicy `json:"policies"`
	OnConflict   string                         `json:"on_conflict"`
	DryRun       bool                           `json:"dry_run"`
	SourceDigest string                         `json:"source_digest"`
}

// parseOnConflict reads on_conflict: skip (default) or replace.
func parseOnConflict(v string) (replace bool, err error) {
	switch v {
	case "", "skip":
		return false, nil
	case "replace":
		return true, nil
	}
	return false, bulkBadRequest("BAD_REQUEST", errors.New("on_conflict must be skip or replace"), "")
}

// checkCopyNames: every copied item has a name, and no name repeats (names
// are the identity on the target).
func checkCopyNames(names []string) error {
	seen := make(map[string]bool, len(names))
	for _, n := range names {
		if strings.TrimSpace(n) == "" {
			return bulkBadRequest("BAD_REQUEST", errors.New("every item needs a name"), "")
		}
		if seen[n] {
			return bulkBadRequest("BAD_REQUEST", fmt.Errorf("the name %q appears twice", clipLabel(n)), "Two items share a name.")
		}
		seen[n] = true
	}
	return nil
}

// tracePoliciesToCopy resolves the policies of a trace-policy apply: the
// named policies of the source host's agent, or inline bodies. The source
// host id is returned ("" for inline).
func (h *HostPolicyHandler) tracePoliciesToCopy(ctx context.Context, projectID string, body tracePolicyApplyBody) ([]hostpolicy.EnforcementPolicy, string, error) {
	if (body.Source == nil) == (body.Policies == nil) {
		return nil, "", bulkBadRequest("BAD_REQUEST", errors.New("name exactly one of source or policies"), "")
	}
	var out []hostpolicy.EnforcementPolicy
	sourceHost := ""
	if body.Source != nil {
		src := body.Source
		if len(src.PolicyIDs) == 0 || len(src.PolicyIDs) > maxApplyPolicyItems {
			return nil, "", bulkBadRequest("BAD_REQUEST", fmt.Errorf("policy_ids must name 1 to %d policies", maxApplyPolicyItems), "")
		}
		if _, err := uuid.Parse(src.HostID); err != nil {
			return nil, "", errApplyHostNotFound
		}
		if host, err := h.Repo.Host.GetByID(ctx, projectID, src.HostID); err != nil || host == nil {
			return nil, "", errApplyHostNotFound
		}
		agents, err := h.Repo.EBPF.ListNonWAFAgentsByHostInProject(ctx, src.HostID, projectID)
		if err != nil {
			return nil, "", err
		}
		if len(agents) == 0 {
			return nil, "", &bulkReqError{status: fiber.StatusBadRequest, code: "NO_HOST_AGENT", msg: "The source host has no host agent."}
		}
		rows, err := h.Repo.EBPF.ListTracePoliciesByAgent(ctx, agents[0].ID)
		if err != nil {
			return nil, "", err
		}
		byID := make(map[int]*repository.TracePolicyRow, len(rows))
		for i := range rows {
			if rows[i].PolicyID != nil {
				byID[*rows[i].PolicyID] = &rows[i]
			}
		}
		seen := map[int]bool{}
		for _, id := range src.PolicyIDs {
			row, ok := byID[id]
			if !ok {
				return nil, "", &bulkReqError{status: fiber.StatusNotFound, code: "POLICY_NOT_FOUND", msg: "Policy not found on the source host."}
			}
			if seen[id] {
				continue
			}
			seen[id] = true
			p := *rowToPolicy(row)
			// A copy keeps the operator's intent and drops what belongs to
			// the source agent (its id, counters, enforcement result).
			p.ID, p.HitCount, p.AutoDowngraded, p.EnforcementMode, p.CreatedAt, p.UpdatedAt = 0, 0, false, "", "", ""
			p.KernelEnforce = p.KernelEnforceRequested
			out = append(out, p)
		}
		sourceHost = src.HostID
	} else {
		if len(body.Policies) == 0 || len(body.Policies) > maxApplyPolicyItems {
			return nil, "", bulkBadRequest("BAD_REQUEST", fmt.Errorf("policies must hold 1 to %d policies", maxApplyPolicyItems), "")
		}
		for _, p := range body.Policies {
			if p.KernelEnforce {
				p.KernelEnforceRequested = true
			}
			hostpolicy.DefaultCommMatchMode(&p, "")
			p.ID, p.HitCount, p.AutoDowngraded, p.EnforcementMode, p.CreatedAt, p.UpdatedAt = 0, 0, false, "", "", ""
			out = append(out, p)
		}
	}
	names := make([]string, 0, len(out))
	for _, p := range out {
		names = append(names, p.Name)
	}
	if err := checkCopyNames(names); err != nil {
		return nil, "", err
	}
	for _, p := range out {
		if err := hostpolicy.ValidateEnforcementPolicy(p); err != nil {
			return nil, "", bulkBadRequest("BAD_REQUEST", err, "The request contains an invalid value.")
		}
		if err := checkBlockPolicy(p); err != nil {
			return nil, "", bulkBadRequest("BAD_REQUEST", err, "The request contains an invalid value.")
		}
	}
	return out, sourceHost, nil
}

// ApplyTracePolicies copies trace (enforcement) policies to many hosts, from
// a source host or inline bodies; identity on the target is the exact name.
//
//	POST /api/projects/:id/hosts/apply/trace-policies
func (h *HostPolicyHandler) ApplyTracePolicies(c *fiber.Ctx) error {
	projectID := c.Params("id")
	var body tracePolicyApplyBody
	if err := json.Unmarshal(c.Body(), &body); err != nil {
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{"error": "invalid body", "code": "BAD_REQUEST"})
	}
	ids, label, err := checkTargets(body.Targets)
	if err != nil {
		return writeBulkError(c, err)
	}
	replace, err := parseOnConflict(body.OnConflict)
	if err != nil {
		return writeBulkError(c, err)
	}
	policies, sourceHost, err := h.tracePoliciesToCopy(c.UserContext(), projectID, body)
	if err != nil {
		return writeBulkError(c, err)
	}
	digest, err := checkSourceDigest(sourceHost, policies, body.SourceDigest)
	if err != nil {
		return writeBulkError(c, err)
	}
	actor := actorOf(c)
	run := &bulkApplyRun{repo: h.Repo, projectID: projectID, op: "trace_policies.copy", dryRun: body.DryRun, ids: ids, label: label, actor: actor,
		sourceDigest: digest,
		perHost: func(ctx context.Context, applyID string, t domain.ApplyTarget, now time.Time) hostApplyResult {
			return h.applyTracePoliciesToHost(ctx, projectID, t, sourceHost, policies, replace, body.DryRun, applyID, actor, now)
		}}
	return run.run(c)
}

// applyTracePoliciesToHost writes the policies to one host agent: new names
// get the next policy id, an existing name is skipped or replaced (keeping
// its policy_id and hit_count); one push per host after its rows.
func (h *HostPolicyHandler) applyTracePoliciesToHost(ctx context.Context, projectID string, t domain.ApplyTarget, sourceHost string,
	policies []hostpolicy.EnforcementPolicy, replace, dryRun bool, applyID string, actor bulkActor, now time.Time) hostApplyResult {
	r := newApplyResult(t, now)
	switch {
	case t.Revoked:
		return r.skip("HOST_REVOKED")
	case sourceHost != "" && t.HostID == sourceHost:
		return r.skip("SOURCE_HOST")
	case t.AgentID == "":
		return r.skip("NO_HOST_AGENT")
	}
	rows, err := h.Repo.EBPF.ListTracePoliciesByAgent(ctx, t.AgentID)
	if err != nil {
		return r.fail("INTERNAL_ERROR", "internal error")
	}
	byName := make(map[string]*repository.TracePolicyRow, len(rows))
	for i := range rows {
		if _, dup := byName[rows[i].Name]; !dup {
			byName[rows[i].Name] = &rows[i]
		}
	}
	created, replaced, existing, written := 0, 0, 0, 0
	stamp := now.UTC().Format(time.RFC3339)
	defer func() {
		if written > 0 && h.GRPCSrv != nil {
			// Its own goroutine, as every caller does: pushes are
			// serialised process-wide and must not hold a worker.
			go h.GRPCSrv.PushTracePoliciesViaGRPC(t.AgentID, projectID)
		}
	}()
	audit := func(action string, pol *hostpolicy.EnforcementPolicy, meta map[string]any) {
		meta["policy_id"], meta["policy_name"], meta["enabled"], meta["apply_id"] = pol.ID, pol.Name, pol.Enabled, applyID
		auditDetached(ctx, h.Repo, repository.AuditEvent{
			ProjectID: projectID, ActorUserID: actor.userID,
			Action: action, TargetType: "trace_policy", TargetID: t.AgentID, TargetName: pol.Name,
			IP: actor.ip, UserAgent: actor.userAgent, MetadataJSON: meta,
		})
	}
	finish := func() hostApplyResult {
		r.Created, r.Replaced, r.Existing = intp(created), intp(replaced), intp(existing)
		return r
	}
	for _, p := range policies {
		pol := p
		if ex, ok := byName[pol.Name]; ok {
			// A row the agent never numbered cannot be addressed for an
			// update; it is left as it is.
			if !replace || ex.PolicyID == nil {
				existing++
				continue
			}
			replaced++
			if dryRun {
				continue
			}
			pol.ID = clampUint32(*ex.PolicyID)
			pol.UpdatedAt = stamp
			if _, err := h.Repo.EBPF.UpsertTracePolicy(ctx, policyToRow(t.AgentID, &pol)); err != nil {
				replaced--
				slog.Error("bulk_trace_policy_replace_failed", "agent_id", t.AgentID, "err", err)
				return finish().fail("INTERNAL_ERROR", "internal error")
			}
			written++
			audit(repository.AuditTracePolicyUpdated, &pol, map[string]any{})
			continue
		}
		created++
		if dryRun {
			continue
		}
		pol.CreatedAt, pol.UpdatedAt = stamp, stamp
		// The id is allocated and the row inserted atomically; a create
		// never updates an existing row (migration 000101).
		_, next, insertErr := h.Repo.EBPF.CreateTracePolicy(ctx, policyToRow(t.AgentID, &pol))
		if insertErr == nil {
			pol.ID = clampUint32(next)
		}
		if insertErr != nil {
			created--
			slog.Error("bulk_trace_policy_create_failed", "agent_id", t.AgentID, "err", insertErr)
			return finish().fail("INTERNAL_ERROR", "internal error")
		}
		written++
		audit(repository.AuditTracePolicyCreated, &pol, map[string]any{"kernel_enforce": pol.KernelEnforce})
	}
	switch {
	case created+replaced == 0:
		r.Status = applyUnchanged
	case dryRun:
		r.Status = applyWouldApply
	default:
		r.Status = applyApplied
	}
	return finish()
}

// sourceDigest is the lower-case hex SHA-256 of the canonical JSON of the
// items a copy would write (after the normalisation the copy uses; Go's
// encoder fixes field order and sorts map keys).
func sourceDigest(items any) (string, error) {
	raw, err := json.Marshal(items)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:]), nil
}

// errSourceChanged: the source host's items differ from the previewed ones.
var errSourceChanged = &bulkReqError{status: fiber.StatusConflict, code: "SOURCE_CHANGED",
	msg: "The source host's items changed since the preview; review the new preview and confirm again."}

// checkSourceDigest returns the digest of a copy from a source host ("" for
// inline items) and refuses a request whose source_digest (the preview's)
// differs, before any host is touched. source_digest with inline items is a
// 400.
func checkSourceDigest(sourceHost string, items any, want string) (string, error) {
	if sourceHost == "" {
		if want != "" {
			return "", bulkBadRequest("BAD_REQUEST", errors.New("source_digest applies only to a copy from a source host"), "")
		}
		return "", nil
	}
	digest, err := sourceDigest(items)
	if err != nil {
		return "", err
	}
	if want != "" && want != digest {
		return "", errSourceChanged
	}
	return digest, nil
}
