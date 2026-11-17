package application

// Trace forwarding filter: the host agent stops sending the
// trace events whose only fate at the control plane is to be discarded.
//
// Before ingestWithBody decides whether to store a trace event it does
// three things with it: ClassifyTraceEvent (canonical paths, lineage
// context, the process × file matrix, then the host's detection rules,
// where the first matching rule counts a hit and suppress drops the event),
// the project's correlation chains (stateful, Correlations), and the noise
// filter storeTraceEvent. Every other reader — the live trace view, the
// feature tables, incidents, the sampled database write — sees stored rows
// only. So an event is dead at the control plane, with no effect but the
// hit count of the rule that matched it, when it is not a kill outcome
// update and, after ClassifyTraceEvent,
//
//   - a suppress rule matched it, or
//   - it matches the conditions of no stage of any correlation chain of its
//     project, and storeTraceEvent does not keep it.
//
// An event that matches no stage leaves every chain as it was: the engine
// changes state only on a stage match, and the expired entries it removes
// on the way would be removed by the next event of that entity anyway
// (TestTraceForwardUnmatchedEventsLeaveCorrelationState).
//
// The control plane builds the filter from exactly what ingest evaluates
// for the agent — ListRules of its host and its project's correlation
// engine — and sends it (domain.TraceForwardFilterCommandID) when a batch
// reports another digest. The agent runs shared/tracefilter's Decide, the same code
// ingest runs, on each event as encoded for sending, drops what is dead,
// counts the hits the dropped events carried per rule and reports them in
// the next batch (TraceForwardReport), which ingest adds to the rule's hit
// count. Without a filter, with an unparsable one, one built for other
// ingest semantics (TraceForwardRevision), or a too-large marker (a filter
// over TraceForwardFilterMaxBytes is never sent), the agent sends
// everything.
//
// A rule or chain write reaches connected agents at once, not with their
// next batch: the detection rule store and the correlation registry call
// RefreshTraceForwardFilters after every write (wired in cmd/wafio).

import (
	"context"
	"fmt"
	"log/slog"
	"slices"
	"sync"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/domain"
	"github.com/wafio/wafio-cp-backend/internal/lru"
	"golang.org/x/sync/singleflight"
)

const (
	// traceForwardHitMax caps one rule's count in one batch report (an
	// agent drains at most 500 trace events per batch).
	traceForwardHitMax = 1 << 16
	// traceForwardRepush: a control plane sends the same filter again to an
	// agent that still reports another digest after this long.
	traceForwardRepush = 10 * time.Second
	// traceForwardCacheMax bounds each cache of traceForwardSync (LRU: past
	// it the least recently used entry goes; the next batch of its host or
	// agent rebuilds it).
	traceForwardCacheMax = 16384
	// traceForwardRefreshMax bounds the projects with rule changes waiting
	// to be sent; past it a change goes out with the agents' next batches
	// instead.
	traceForwardRefreshMax = 4096
	// traceForwardRefreshHostsMax: a project with more hosts waiting is
	// refreshed whole (every connected agent once).
	traceForwardRefreshHostsMax = 1024
	// traceForwardRefreshTimeout bounds the reads of one refresh slice.
	traceForwardRefreshTimeout = 10 * time.Second
)

// forwardedRuleHits returns the counts of a batch report that ingest
// accepts: rules the evaluator holds (the agent compiles the same rule set
// with the same validation), each count 1..traceForwardHitMax. A report
// from a stale filter can name rules since deleted; those are ignored.
func forwardedRuleHits(report *TraceForwardReport, rules *TraceRuleEvaluator) map[string]int {
	if report == nil || len(report.RuleHits) == 0 || rules == nil {
		return nil
	}
	ids := rules.RuleIDs()
	known := make(map[string]bool, len(ids))
	for _, id := range ids {
		known[id] = true
	}
	var hits map[string]int
	for id, n := range report.RuleHits {
		if n <= 0 || id == "" || !known[id] {
			continue
		}
		if hits == nil {
			hits = make(map[string]int, len(report.RuleHits))
		}
		hits[id] = min(n, traceForwardHitMax)
	}
	return hits
}

// traceForwardSync is the control plane's side of filter delivery: the
// digest of the filter each host's agent should hold, the last filter sent
// to each agent, and the rule changes waiting to be sent. Both caches are
// bounded LRUs; a filter is built outside every shared lock, once per host
// and rule set at a time (builds).
type traceForwardSync struct {
	init    sync.Once
	digests *lru.Cache[traceForwardDigestEntry] // projectID\x00hostID
	pushed  *lru.Cache[traceForwardPush]        // projectID\x00agentID
	builds  singleflight.Group

	// hosts: the host ingest last resolved for each agent
	// (projectID\x00agentID), for an agent whose stream Hello bound to no
	// host but that was linked to one since.
	hosts *lru.Cache[string]

	refreshMu       sync.Mutex
	refreshJobs     map[string]*traceForwardJob // waiting, by project
	refreshNew      []*traceForwardJob          // owner not yet looked up
	refreshOwners   map[string]*traceForwardOwnerQueue
	refreshRotation []string // owners with jobs waiting, round-robin
	refreshRunning  bool
	refreshDropped  bool // a change was not queued since the queue last drained
	slice           int  // hosts per turn; 0 = traceForwardRefreshSlice
}

// traceForwardDigestEntry caches the digest of one rule set: ListRules
// returns the same cached slice until a rule write or its TTL replaces it,
// and the correlation registry replaces a project's engine on every change.
// tooLarge: the filter is over TraceForwardFilterMaxBytes, so the agent
// gets the marker.
type traceForwardDigestEntry struct {
	rules    []domain.DetectionRule
	engine   *CorrelationEngine
	digest   string
	tooLarge bool
}

type traceForwardPush struct {
	digest string
	at     time.Time
}

func (fs *traceForwardSync) caches() {
	fs.init.Do(func() {
		fs.digests = lru.New[traceForwardDigestEntry](traceForwardCacheMax)
		fs.pushed = lru.New[traceForwardPush](traceForwardCacheMax)
		fs.hosts = lru.New[string](traceForwardCacheMax)
	})
}

// noteAgentHost records the host ingest resolved for agentID's batch.
func (fs *traceForwardSync) noteAgentHost(projectID, agentID, hostID string) {
	fs.caches()
	fs.hosts.Update(projectID+"\x00"+agentID, func(v *string, _ bool) { *v = hostID })
}

// agentHost is the host a refresh builds agentID's filter for: its stream's
// (streamHost), or, for a stream bound to no host, the host ingest last
// resolved for the agent's batches (a link made after Hello).
func (fs *traceForwardSync) agentHost(projectID, agentID, streamHost string) string {
	if streamHost != "" {
		return streamHost
	}
	fs.caches()
	var host string
	fs.hosts.Get(projectID+"\x00"+agentID, func(v *string) { host = *v })
	return host
}

func sameRuleSlice(a, b []domain.DetectionRule) bool {
	return len(a) == len(b) && (len(a) == 0 || &a[0] == &b[0])
}

// traceForwardNow is the clock of filter re-sends (tests replace it).
var traceForwardNow = time.Now

// traceForwardRefreshSlice is the most hosts one refresh turn reads rules
// for before the worker serves the next account (traceForwardSync.slice
// overrides it in tests).
const traceForwardRefreshSlice = 64

// filterFor returns the digest entry of what ingest evaluates for the host
// (rules from ListRules, engine of the project) and, when this call built
// it, the message. ok is false when the filter cannot be encoded. A build
// runs outside every shared lock; concurrent callers with the same host,
// rule slice and engine share one build.
func (fs *traceForwardSync) filterFor(projectID, hostID string, rules []domain.DetectionRule, engine *CorrelationEngine) (entry traceForwardDigestEntry, msg []byte, ok bool) {
	fs.caches()
	key := projectID + "\x00" + hostID
	var cached traceForwardDigestEntry
	found := fs.digests.Get(key, func(v *traceForwardDigestEntry) { cached = *v })
	if found && cached.engine == engine && sameRuleSlice(cached.rules, rules) {
		return cached, nil, true
	}
	var first *domain.DetectionRule
	if len(rules) > 0 {
		first = &rules[0]
	}
	type built struct {
		entry traceForwardDigestEntry
		msg   []byte
	}
	v, _, _ := fs.builds.Do(fmt.Sprintf("%s\x00%p\x00%d\x00%p", key, first, len(rules), engine), func() (any, error) {
		msg, digest, size := buildTraceForwardFilter(rules, engine.rules)
		if msg == nil {
			return built{}, nil
		}
		e := traceForwardDigestEntry{rules: rules, engine: engine, digest: digest, tooLarge: size > TraceForwardFilterMaxBytes}
		fs.digests.Update(key, func(v *traceForwardDigestEntry, _ bool) { *v = e })
		if e.tooLarge && (!found || !cached.tooLarge || cached.digest != digest) {
			// Once per rule set: a rebuild of the same set (rule cache
			// TTL) does not log again.
			slog.Warn("trace_forward_filter_too_large", "project_id", projectID, "host_id", hostID,
				"bytes", size, "max_bytes", TraceForwardFilterMaxBytes, "rules", len(rules))
		}
		return built{entry: e, msg: msg}, nil
	})
	b := v.(built)
	return b.entry, b.msg, b.msg != nil
}

// syncTraceForwardFilter sends the agent the filter for what ingest
// evaluates for it (projectID/hostID as ingest resolves them, rules from
// ListRules) when its batch reported another digest: at once when the
// filter changed since the last send, else at most every
// traceForwardRepush. streamProjectID is the project of the agent's stream.
func (s *HostTelemetryIngest) syncTraceForwardFilter(streamProjectID, agentID, projectID, hostID string, rules []domain.DetectionRule, reported string) {
	if s.ForwardFilters == nil || projectID == "" || agentID == "" {
		return
	}
	if streamProjectID == projectID {
		s.forward.noteAgentHost(projectID, agentID, hostID)
	}
	engine := Correlations().engine(projectID)
	entry, msg, ok := s.forward.filterFor(projectID, hostID, rules, engine)
	if !ok || reported == entry.digest {
		return
	}
	s.pushTraceForward(streamProjectID, agentID, entry, msg, false)
}

// pushTraceForward sends entry's filter to the agent unless it was the last
// one sent there: within traceForwardRepush (a batch still reporting
// another digest), or at all (refresh: a rule change that left this agent's
// filter as it was). msg is entry's message when the caller has it.
func (s *HostTelemetryIngest) pushTraceForward(streamProjectID, agentID string, entry traceForwardDigestEntry, msg []byte, refresh bool) {
	fs := &s.forward
	fs.caches()
	now := traceForwardNow()
	send := true
	fs.pushed.Update(streamProjectID+"\x00"+agentID, func(v *traceForwardPush, created bool) {
		if !created && v.digest == entry.digest && (refresh || now.Sub(v.at) < traceForwardRepush) {
			send = false
			return
		}
		*v = traceForwardPush{digest: entry.digest, at: now}
	})
	if !send {
		return
	}
	if msg == nil {
		var digest string
		msg, digest, _ = buildTraceForwardFilter(entry.rules, entry.engine.rules)
		if msg == nil || digest != entry.digest {
			return
		}
	}
	s.ForwardFilters.PushTraceForwardFilter(streamProjectID, agentID, msg)
}

// RefreshTraceForwardFilters sends, without waiting for the agents' next
// batches, the filter of what ingest now evaluates to every connected agent
// of projectID's host hostID ("" = every agent of the project, host-less
// ones included) whose last filter it changes. The detection rule store
// (after each rule write, built-in seeding included; a bulk apply once per
// host) and the correlation registry (after each chain change) call it; it
// returns at once and reads nothing.
//
// One worker per service sends the refreshes. Changes waiting for the same
// project merge into one job (its hosts, or the whole project); the worker
// takes jobs round-robin per owning account, then in queue order inside an
// account, and runs at most traceForwardRefreshSlice hosts of a job before
// it moves on, requeueing the rest behind the other accounts' jobs. So a
// rule edit waits for at most one slice per other active account, however
// much one account queues. Agents are listed from the live stream table
// (no database read per agent); each host's rules are read once per slice.
// Past traceForwardRefreshMax waiting projects a change is dropped, and the
// agents' next batches carry it instead (they report the old digest).
func (s *HostTelemetryIngest) RefreshTraceForwardFilters(projectID, hostID string) {
	if s == nil || s.ForwardFilters == nil || projectID == "" {
		return
	}
	fs := &s.forward
	fs.refreshMu.Lock()
	if job := fs.refreshJobs[projectID]; job != nil {
		job.add(hostID)
		fs.refreshMu.Unlock()
		return
	}
	if len(fs.refreshJobs) >= traceForwardRefreshMax {
		logged := fs.refreshDropped
		fs.refreshDropped = true
		fs.refreshMu.Unlock()
		if !logged {
			slog.Warn("trace_forward_refresh_queue_full", "max", traceForwardRefreshMax)
		}
		return
	}
	if fs.refreshJobs == nil {
		fs.refreshJobs = make(map[string]*traceForwardJob)
	}
	job := &traceForwardJob{projectID: projectID}
	job.add(hostID)
	fs.refreshJobs[projectID] = job
	fs.refreshNew = append(fs.refreshNew, job)
	start := !fs.refreshRunning
	fs.refreshRunning = true
	fs.refreshMu.Unlock()
	if start {
		go s.runTraceForwardRefreshes()
	}
}

// traceForwardJob is the waiting refresh work of one project: every agent
// (all), or the agents of the listed hosts ("" = agents bound to no host).
type traceForwardJob struct {
	projectID, owner string
	all              bool
	hosts            map[string]struct{}
	order            []string // hosts in queueing order
	queued           int      // hosts queued by add (the cap), not by merge
}

func (j *traceForwardJob) add(hostID string) {
	if j.all {
		return
	}
	if hostID == "" {
		j.all, j.hosts, j.order = true, nil, nil
		return
	}
	if _, ok := j.hosts[hostID]; ok {
		return
	}
	// The cap counts hosts queued by changes, not the merged rest of a
	// slice: a waiting rest of more than traceForwardRefreshHostsMax hosts
	// must not turn into "all" (and restart) on the next single-host edit.
	if j.queued >= traceForwardRefreshHostsMax {
		j.all, j.hosts, j.order = true, nil, nil
		return
	}
	j.queued++
	j.addHost(hostID)
}

// addHost adds hostID without the traceForwardRefreshHostsMax cap. Only
// for hosts that have a connected agent (the rest of a slice): their number
// is bounded by the project's connected hosts, and turning that rest back
// into "all" would restart the job at its first slice forever.
func (j *traceForwardJob) addHost(hostID string) {
	if j.all {
		return
	}
	if _, ok := j.hosts[hostID]; ok {
		return
	}
	if j.hosts == nil {
		j.hosts = make(map[string]struct{})
	}
	j.hosts[hostID] = struct{}{}
	j.order = append(j.order, hostID)
}

// merge adds the hosts of rest (work left of a job of the same project).
func (j *traceForwardJob) merge(rest *traceForwardJob) {
	if rest.all {
		j.all, j.hosts, j.order = true, nil, nil
		return
	}
	for _, h := range rest.order {
		if h == "" { // host-less agents: only a project-wide job has them
			if !j.all {
				if _, ok := j.hosts[""]; !ok {
					if j.hosts == nil {
						j.hosts = make(map[string]struct{})
					}
					j.hosts[""] = struct{}{}
					j.order = append(j.order, "")
				}
			}
			continue
		}
		j.addHost(h)
	}
}

// traceForwardOwnerQueue is one account's waiting jobs, in queue order.
type traceForwardOwnerQueue struct {
	jobs []*traceForwardJob
}

func (s *HostTelemetryIngest) runTraceForwardRefreshes() {
	fs := &s.forward
	var rest *traceForwardJob // work left of the last slice
	for {
		fs.refreshMu.Lock()
		fresh := fs.refreshNew
		fs.refreshNew = nil
		fs.refreshMu.Unlock()
		// Owners are looked up outside the lock (a cache hit, else one
		// query per project).
		owners := make([]string, len(fresh))
		for i, job := range fresh {
			owners[i] = s.traceForwardOwner(job.projectID)
		}
		fs.refreshMu.Lock()
		for i, job := range fresh {
			job.owner = owners[i]
			fs.enqueueOwnerLocked(job)
		}
		// The rest of the last slice queues behind the changes that
		// arrived during it.
		if rest != nil {
			if waiting := fs.refreshJobs[rest.projectID]; waiting != nil {
				waiting.merge(rest)
			} else {
				fs.refreshJobs[rest.projectID] = rest
				fs.enqueueOwnerLocked(rest)
			}
			rest = nil
		}
		if len(fs.refreshRotation) == 0 {
			if len(fs.refreshNew) > 0 {
				fs.refreshMu.Unlock()
				continue
			}
			fs.refreshRunning, fs.refreshDropped = false, false
			fs.refreshRotation, fs.refreshOwners = nil, nil
			fs.refreshMu.Unlock()
			return
		}
		owner := fs.refreshRotation[0]
		fs.refreshRotation = fs.refreshRotation[1:]
		q := fs.refreshOwners[owner]
		job := q.jobs[0]
		q.jobs = q.jobs[1:]
		if len(q.jobs) > 0 {
			fs.refreshRotation = append(fs.refreshRotation, owner)
		} else {
			delete(fs.refreshOwners, owner)
		}
		// From now on a change of the project starts a new job.
		delete(fs.refreshJobs, job.projectID)
		fs.refreshMu.Unlock()

		rest = s.refreshTraceForward(job)
	}
}

// enqueueOwnerLocked appends job to its owner's queue, and the owner to the
// rotation when it had nothing waiting. Caller holds refreshMu.
func (fs *traceForwardSync) enqueueOwnerLocked(job *traceForwardJob) {
	if fs.refreshJobs[job.projectID] != job {
		return // merged away
	}
	if fs.refreshOwners == nil {
		fs.refreshOwners = make(map[string]*traceForwardOwnerQueue)
	}
	q := fs.refreshOwners[job.owner]
	if q == nil {
		q = &traceForwardOwnerQueue{}
		fs.refreshOwners[job.owner] = q
		fs.refreshRotation = append(fs.refreshRotation, job.owner)
	}
	q.jobs = append(q.jobs, job)
}

// traceForwardOwner is the account the worker shares its time by.
func (s *HostTelemetryIngest) traceForwardOwner(projectID string) (owner string) {
	defer func() {
		if r := recover(); r != nil {
			owner = projectID
		}
	}()
	if owner = s.ForwardFilters.TraceForwardOwner(projectID); owner == "" {
		owner = projectID
	}
	return owner
}

// refreshTraceForward runs one slice of job: for each connected agent of at
// most traceForwardRefreshSlice of its hosts, the filter ingest's next batch
// of it would compute. It returns the work left (nil: none).
func (s *HostTelemetryIngest) refreshTraceForward(job *traceForwardJob) (rest *traceForwardJob) {
	defer func() {
		if r := recover(); r != nil {
			slog.Error("trace_forward_refresh_panic", "project_id", job.projectID, "panic", fmt.Sprint(r))
			rest = nil
		}
	}()
	targets := s.ForwardFilters.TraceForwardAgents(job.projectID)
	byHost := make(map[string][]string)
	for _, t := range targets {
		if t.AgentID == "" {
			continue
		}
		host := s.forward.agentHost(job.projectID, t.AgentID, t.HostID)
		byHost[host] = append(byHost[host], t.AgentID)
	}
	// Only hosts with a connected agent cost a turn.
	var hosts []string
	if job.all {
		hosts = make([]string, 0, len(byHost))
		for h := range byHost {
			hosts = append(hosts, h)
		}
		slices.Sort(hosts)
	} else {
		for _, h := range job.order {
			if len(byHost[h]) > 0 {
				hosts = append(hosts, h)
			}
		}
	}
	slice := traceForwardRefreshSlice
	if s.forward.slice > 0 {
		slice = s.forward.slice
	}
	if len(hosts) > slice {
		rest = &traceForwardJob{projectID: job.projectID, owner: job.owner}
		for _, h := range hosts[slice:] {
			rest.merge(&traceForwardJob{order: []string{h}})
		}
		hosts = hosts[:slice]
	}
	ctx, cancel := context.WithTimeout(context.Background(), traceForwardRefreshTimeout)
	defer cancel()
	engine := Correlations().engine(job.projectID)
	for _, hostID := range hosts {
		agents := byHost[hostID]
		if len(agents) == 0 {
			continue
		}
		// As ingestWithBody resolves them (loadTraceRules): a host-less
		// agent has no detection rules.
		var rules []domain.DetectionRule
		if hostID != "" {
			var err error
			if rules, err = s.Rules.ListRules(ctx, job.projectID, hostID); err != nil {
				continue // the next batch retries
			}
		}
		entry, msg, ok := s.forward.filterFor(job.projectID, hostID, rules, engine)
		if !ok {
			continue
		}
		for _, agentID := range agents {
			s.pushTraceForward(job.projectID, agentID, entry, msg, true)
		}
	}
	return rest
}
