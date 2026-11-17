// Temporal Event Correlation Engine.
//
// The per-event detection rules are stateless — a real intrusion unfolds as a
// CHAIN of individually-low-severity events (drop payload → make executable →
// execute from web root → call out). This engine correlates trace events per
// entity (process tree or cgroup) inside sliding time windows and reports a
// completed chain so ingest can escalate the triggering event to CRITICAL.
package application

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Entity scopes for correlation rules.
const (
	CorrelateByProcess = "process" // PID + process start time (reuse-safe)
	CorrelateByCgroup  = "cgroup"  // container/pod scoped
)

type chainProgress struct {
	stage  int // -1 = completed, cooling down until coolUntil
	lastAt time.Time
	// coolUntil: after a completion the entity cannot start the chain again
	// before this time, so one compromise escalates one event per MaxSpan
	// instead of every later read+connect pair of the same process.
	coolUntil time.Time
}

// CorrelationEngine evaluates events against multi-stage rules. Safe for
// concurrent use; state is bounded (maxEntities per rule, oldest-expired
// sweep) so a spoofed-process flood cannot exhaust memory.
type CorrelationEngine struct {
	mu          sync.Mutex
	rules       []*CorrelationRule
	chain       map[string]map[string]*chainProgress // ruleID → entityKey → progress
	maxEntities int
	lastSweep   time.Time
}

// stateTTL: progress older than this (and outside any stage window) is swept.
const (
	correlationStateTTL  = 10 * time.Minute
	correlationSweepTick = time.Minute
)

func NewCorrelationEngine(rules ...*CorrelationRule) *CorrelationEngine {
	e := &CorrelationEngine{
		rules:       rules,
		chain:       make(map[string]map[string]*chainProgress),
		maxEntities: 100_000,
		lastSweep:   time.Now(),
	}
	for _, r := range rules {
		e.chain[r.ID] = make(map[string]*chainProgress)
	}
	return e
}

// Evaluate feeds one event; returns rule IDs whose chain COMPLETED on this
// event. After a completion the entity cools down for the rule's MaxSpan
// (the chain cannot restart), then recurring chains re-fire.
func (e *CorrelationEngine) Evaluate(ev CorrelationEvent) []string {
	rules := e.EvaluateRules(ev)
	if len(rules) == 0 {
		return nil
	}
	ids := make([]string, len(rules))
	for i, r := range rules {
		ids[i] = r.ID
	}
	return ids
}

// EvaluateRules is Evaluate returning the completed rules themselves.
func (e *CorrelationEngine) EvaluateRules(ev CorrelationEvent) []*CorrelationRule {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := ev.Timestamp
	if now.IsZero() {
		now = time.Now()
	}
	if now.Sub(e.lastSweep) >= correlationSweepTick {
		e.sweepLocked(now)
	}

	var completed []*CorrelationRule
	for _, rule := range e.rules {
		entity := entityKey(rule, ev)
		progress := e.chain[rule.ID][entity] // nil = no open chain

		if progress != nil && progress.stage < 0 {
			if now.Before(progress.coolUntil) {
				continue // completed recently: no restart, no re-escalation
			}
			delete(e.chain[rule.ID], entity)
			progress = nil
		}

		// Stale chains cannot continue.
		if progress != nil && now.Sub(progress.lastAt) > correlationStateTTL+rule.MaxSpan {
			delete(e.chain[rule.ID], entity)
			progress = nil
		}

		// Try to continue an open chain with the NEXT stage first.
		if progress != nil {
			next := progress.stage + 1
			if next < len(rule.Stages) && stageMatches(rule, next, ev, progress.lastAt, now) {
				progress.stage = next
				progress.lastAt = now
				if next == len(rule.Stages)-1 {
					completed = append(completed, rule)
					progress.stage = -1
					progress.coolUntil = now.Add(rule.MaxSpan)
				}
				continue
			}
		}

		// Stage 0 always (re)starts the chain.
		if matchConditions(ev, rule.Stages[0].Conditions) {
			m := e.chain[rule.ID]
			if _, exists := m[entity]; !exists {
				// Bounded state: evict an arbitrary open chain when at cap
				// (spoofed-entity flood cannot exhaust memory).
				for len(m) >= e.maxEntities {
					for other := range m {
						delete(m, other)
						break
					}
				}
			}
			m[entity] = &chainProgress{stage: 0, lastAt: now}
		}
	}
	return completed
}

// stageMatches checks stage idx conditions plus the gap constraint against
// the previous stage timestamp (gap limit: stage.Within, else rule.MaxSpan).
func stageMatches(rule *CorrelationRule, idx int, ev CorrelationEvent, prevAt, now time.Time) bool {
	limit := rule.Stages[idx].Within
	if limit <= 0 {
		limit = rule.MaxSpan
	}
	if now.Sub(prevAt) > limit {
		return false
	}
	return matchConditions(ev, rule.Stages[idx].Conditions)
}

// entityKey identifies the correlation scope for an event.
func entityKey(rule *CorrelationRule, ev CorrelationEvent) string {
	if rule.Entity == CorrelateByCgroup {
		return fmt.Sprintf("cg:%d", ev.CgroupID)
	}
	return fmt.Sprintf("p:%d:%d", ev.PID, ev.ProcessStartNS)
}

// sweepLocked drops chains whose last progress is outside any plausible
// window, and caps total state per rule.
func (e *CorrelationEngine) sweepLocked(now time.Time) {
	for _, rule := range e.rules {
		m := e.chain[rule.ID]
		for entity, p := range m {
			if now.Sub(p.lastAt) > correlationStateTTL+rule.MaxSpan {
				delete(m, entity)
			}
		}
		for len(m) > e.maxEntities {
			for entity := range m { // arbitrary eviction (map order)
				delete(m, entity)
				break
			}
		}
	}
	e.lastSweep = now
}

var destScopes = map[string]bool{
	DestScopePublic: true, DestScopePrivate: true, DestScopeLoopback: true,
	DestScopeLocal: true, DestScopeNone: true,
}

// BuiltinCorrelationRules returns the default multi-stage detection chains.
func BuiltinCorrelationRules() []*CorrelationRule {
	return []*CorrelationRule{
		{
			ID:      "webshell-exec-chain",
			Name:    "Web_Shell_Execution_Chain",
			Entity:  CorrelateByProcess,
			MaxSpan: 5 * time.Minute,
			Stages: []CorrelationStage{
				{Conditions: []CorrelationCondition{
					{Field: "event_name", Op: "eq", Value: "openat"},
					{Field: "filename", Op: "starts_with_any", Value: []string{"/dev/shm/", "/tmp/", "/var/tmp/", "/var/www/"}},
				}},
				{Within: time.Minute, Conditions: []CorrelationCondition{
					{Field: "event_name", Op: "in", Value: []string{"fchmodat", "chmod"}},
				}},
				{Within: time.Minute, Conditions: []CorrelationCondition{
					{Field: "event_name", Op: "eq", Value: "execve"},
					{Field: "parent_comm", Op: "in", Value: []string{"nginx", "apache2", "httpd", "php-fpm"}},
				}},
			},
		},
		{
			// Stage 0 is a read of a root-only secret by a process that is
			// not part of the authentication stack; stage 1 is egress to a
			// routable address. /etc/passwd is world-readable and read by
			// nearly every process through NSS, and local DNS (127.0.0.53),
			// syslog (AF_UNIX) or LAN peers are normal follow-ups, so none
			// of them counts (2026-10-16). Process names are set by the
			// process itself: a dumper running under one of the excluded
			// names is missed by this chain (the per-event rules still see
			// its shadow read).
			ID:        "cred-dump-exfil-chain",
			Name:      "Credential_Dump_Exfiltration_Chain",
			Entity:    CorrelateByProcess,
			MaxSpan:   5 * time.Minute,
			Technique: "T1041",
			Tactic:    "Exfiltration",
			Stages: []CorrelationStage{
				{Conditions: []CorrelationCondition{
					{Field: "event_name", Op: "eq", Value: "openat"},
					{Field: "filename", Op: "in", Value: credentialSecretFiles},
					{Field: "exe_verified", Op: "neq", Value: true},
					{Field: "comm", Op: "not_in", Value: authStackComms},
				}},
				{Within: time.Minute, Conditions: []CorrelationCondition{
					{Field: "event_name", Op: "in", Value: []string{"connect", "sendto"}},
					{Field: "dest_scope", Op: "eq", Value: DestScopePublic},
				}},
			},
		},
	}
}

// credentialSecretFiles are the root-only password hash stores (and their
// shadow-utils backups) a credential dump reads.
var credentialSecretFiles = []string{
	"/etc/shadow", "/etc/shadow-", "/etc/gshadow", "/etc/gshadow-", "/etc/security/opasswd",
}

// authStackComms read the shadow files as part of normal authentication,
// account checks or account management (PAM pam_unix, shadow-utils, login
// managers). Names as the kernel reports them (comm, ≤ 15 bytes).
var authStackComms = []string{
	// remote and console login
	"sshd", "sshd-session", "sshd-auth", "login", "agetty", "gdm-session-wor", "lightdm", "sddm-helper",
	// privilege change
	"su", "sudo", "sudoedit", "doas", "pkexec", "polkitd", "polkit-agent-he", "unix_chkpwd", "unix_update",
	// schedulers (pam_unix account checks)
	"cron", "crond", "anacron", "atd",
	// system services
	"systemd", "systemd-logind", "systemd-userdbd", "systemd-homed", "accounts-daemon", "nscd", "sssd", "sssd_be",
	// account management (shadow-utils / passwd)
	"passwd", "chpasswd", "chage", "chsh", "chfn", "useradd", "usermod", "userdel", "groupadd", "groupmod",
	"groupdel", "gpasswd", "newusers", "pwck", "grpck", "vipw", "vigr", "pwconv", "grpconv", "pwunconv", "grpunconv",
}

// canonicalBuiltins indexes the built-in chains by name for
// CanonicalBuiltinCorrelationRule.
var canonicalBuiltins = func() map[string]*CorrelationRule {
	m := map[string]*CorrelationRule{}
	for _, r := range BuiltinCorrelationRules() {
		m[r.Name] = r
	}
	return m
}()

// CanonicalBuiltinCorrelationRule returns the current definition of a
// built-in chain by name (nil if unknown). Built-in rows are seeded per
// project and their stages are not editable, so the stored copy goes stale
// whenever a built-in changes; readers take entity, span, stages and MITRE
// attribution from here instead of from the seeded row.
func CanonicalBuiltinCorrelationRule(name string) *CorrelationRule {
	r, ok := canonicalBuiltins[name]
	if !ok {
		return nil
	}
	cp := *r
	cp.Stages = append([]CorrelationStage(nil), r.Stages...)
	return &cp
}

// ── Validation ───────────────────────────────────────────────────────────────

var correlationConditionFields = map[string]bool{
	"event_name": true, "category": true, "comm": true, "parent_comm": true,
	"filename": true, "severity": true, "addr": true, "dest_scope": true,
	"exe_verified": true,
}

var correlationConditionOps = map[string]bool{
	"eq": true, "neq": true, "in": true, "not_in": true, "starts_with": true,
	"starts_with_any": true, "contains": true,
}

// ValidateCorrelationRule enforces the contract the engine can evaluate.
func ValidateCorrelationRule(r *CorrelationRule) error {
	if strings.TrimSpace(r.ID) == "" {
		return fmt.Errorf("id is required")
	}
	if strings.TrimSpace(r.Name) == "" {
		return fmt.Errorf("name is required")
	}
	if r.Entity != CorrelateByProcess && r.Entity != CorrelateByCgroup {
		return fmt.Errorf("entity must be %q or %q", CorrelateByProcess, CorrelateByCgroup)
	}
	if r.MaxSpan <= 0 || r.MaxSpan > 30*time.Minute {
		return fmt.Errorf("max_span must be between 1ms and 30m")
	}
	if len(r.Stages) < 2 || len(r.Stages) > 8 {
		return fmt.Errorf("stages must be 2..8 (a one-stage chain is a plain detection rule)")
	}
	for si, st := range r.Stages {
		if len(st.Conditions) == 0 {
			return fmt.Errorf("stage %d: at least one condition required", si)
		}
		if si > 0 && (st.Within <= 0 || st.Within > r.MaxSpan) {
			return fmt.Errorf("stage %d: within must be 1ms..max_span", si)
		}
		for ci, cond := range st.Conditions {
			if !correlationConditionFields[cond.Field] {
				return fmt.Errorf("stage %d condition %d: unsupported field %q", si, ci, cond.Field)
			}
			if !correlationConditionOps[cond.Op] {
				return fmt.Errorf("stage %d condition %d: unsupported op %q", si, ci, cond.Op)
			}
			if cond.Value == nil {
				return fmt.Errorf("stage %d condition %d: value is required", si, ci)
			}
			if cond.Field == "severity" {
				if cond.Op != "eq" && cond.Op != "neq" {
					return fmt.Errorf("stage %d condition %d: severity supports eq (at least) and neq (below) only", si, ci)
				}
				if _, ok := severityValue(cond.Value); !ok {
					return fmt.Errorf("stage %d condition %d: severity must be a whole number 0..4", si, ci)
				}
			}
			if cond.Field == "exe_verified" {
				if cond.Op != "eq" && cond.Op != "neq" {
					return fmt.Errorf("stage %d condition %d: exe_verified supports eq and neq only", si, ci)
				}
				if _, ok := boolValue(cond.Value); !ok {
					return fmt.Errorf("stage %d condition %d: exe_verified must be true or false", si, ci)
				}
			}
			if cond.Op == "in" || cond.Op == "not_in" || cond.Op == "starts_with_any" {
				if asSlice(cond.Value) == nil {
					return fmt.Errorf("stage %d condition %d: op %q requires a list value", si, ci, cond.Op)
				}
			}
			if cond.Field == "dest_scope" {
				vals := asSlice(cond.Value)
				if vals == nil {
					vals = []string{asString(cond.Value)}
				}
				for _, v := range vals {
					if !destScopes[v] {
						return fmt.Errorf("stage %d condition %d: dest_scope must be one of public, private, loopback, local, none", si, ci)
					}
				}
			}
		}
	}
	return nil
}

// ── Per-project registry ─────────────────────────────────────────────────────

// CorrelationRegistry holds one engine per project. Ingest evaluates through
// it; CRUD handlers swap rule sets, which resets in-flight chain state for
// that project only. Projects without configured rules fall back to the
// built-in chains.
type CorrelationRegistry struct {
	mu      sync.Mutex
	engines map[string]*CorrelationEngine
	// onChange: SetChangeHook.
	onChange atomic.Pointer[func(projectID string)]
}

// SetChangeHook installs fn, called after a project's engine was replaced
// (SetRules) or dropped (Reset), outside the registry lock. The control
// plane sends trace forwarding filters through it. fn must
// not block; nil removes the hook.
func (r *CorrelationRegistry) SetChangeHook(fn func(projectID string)) {
	if fn == nil {
		r.onChange.Store(nil)
		return
	}
	r.onChange.Store(&fn)
}

func (r *CorrelationRegistry) changed(projectID string) {
	if fn := r.onChange.Load(); fn != nil {
		(*fn)(projectID)
	}
}

var correlationRegistry = &CorrelationRegistry{engines: map[string]*CorrelationEngine{}}

// Correlations returns the process-wide registry.
func Correlations() *CorrelationRegistry { return correlationRegistry }

// SetRules atomically replaces the engine for a project.
func (r *CorrelationRegistry) SetRules(projectID string, rules []*CorrelationRule) {
	enabled := make([]*CorrelationRule, 0, len(rules))
	for _, rule := range rules {
		if rule != nil {
			enabled = append(enabled, rule)
		}
	}
	r.mu.Lock()
	r.engines[projectID] = NewCorrelationEngine(enabled...)
	r.mu.Unlock()
	r.changed(projectID)
}

// CorrelationRuleSource is the port the registry loads stored rule sets
// through at startup. The map holds every project that has stored correlation
// rows, each with its enabled rules (an empty slice when every rule is
// disabled); projects absent from the map keep the built-in chains.
type CorrelationRuleSource interface {
	EnabledCorrelationRulesByProject(ctx context.Context) (map[string][]*CorrelationRule, error)
}

// LoadAll installs every stored project rule set from src, so a restart
// keeps disabled built-ins off and custom chains on before any rule is
// edited. Returns the number of projects loaded.
func (r *CorrelationRegistry) LoadAll(ctx context.Context, src CorrelationRuleSource) (int, error) {
	byProject, err := src.EnabledCorrelationRulesByProject(ctx)
	if err != nil {
		return 0, err
	}
	for projectID, rules := range byProject {
		r.SetRules(projectID, rules)
	}
	return len(byProject), nil
}

// Reset drops a project back to the built-in chains.
func (r *CorrelationRegistry) Reset(projectID string) {
	r.mu.Lock()
	delete(r.engines, projectID)
	r.mu.Unlock()
	r.changed(projectID)
}

// Evaluate runs the event through the project's engine (built-ins when unset).
func (r *CorrelationRegistry) Evaluate(projectID string, ev CorrelationEvent) []string {
	return r.engine(projectID).Evaluate(ev)
}

// EvaluateRules is Evaluate returning the completed rules themselves.
func (r *CorrelationRegistry) EvaluateRules(projectID string, ev CorrelationEvent) []*CorrelationRule {
	return r.engine(projectID).EvaluateRules(ev)
}

func (r *CorrelationRegistry) engine(projectID string) *CorrelationEngine {
	r.mu.Lock()
	defer r.mu.Unlock()
	engine, ok := r.engines[projectID]
	if !ok {
		engine = NewCorrelationEngine(BuiltinCorrelationRules()...)
		r.engines[projectID] = engine
	}
	return engine
}
