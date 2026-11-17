package agentserver

import (
	"errors"
	"strings"
	"sync"
	"time"

	agentv1 "github.com/wafio/wafio-cp-backend/shared/agentpb"
)

const (
	replayBufSize = 100 // events kept per project for late-joining SSE clients

	// A project's replay buffer is dropped once nothing was published to it
	// for replayIdleTTL and no live subscriber is attached: buffers of
	// deleted projects used to stay for the life of the process. The sweep
	// runs at most every replaySweepEvery, from Publish and Subscribe.
	replayIdleTTL    = 24 * time.Hour
	replaySweepEvery = 10 * time.Minute

	// Each subscriber is a live HTTP connection holding a goroutine and a
	// buffered channel, and every published decision is offered to every one of
	// them while the broker lock is held. Without a ceiling, a member of a
	// project can open connections until the control plane runs out of memory
	// or fan-out cost swamps the gRPC receive loop. Authentication does not
	// make that acceptable; it only names who did it.
	//
	// A dashboard needs one connection per open tab. These allow for many tabs
	// across many operators and still bound the damage.
	maxSubscribersPerProject = 64
	maxSubscribersTotal      = 512

	// Per-user ceilings. Without them one account with access to a
	// handful of projects could fill maxSubscribersTotal alone and lock every
	// other tenant out of live decisions. Eight tabs per project and 32 in
	// all is well past what one operator uses.
	MaxSubscribersPerUserProject = 8
	MaxSubscribersPerUser        = 32

	// MaxSubscribersPerOwner caps the subscribers of every project one
	// account owns, whoever opened them: the per-user ceilings
	// alone let one person mint accounts, invite them to their own
	// projects and fill maxSubscribersTotal. A quarter of the process.
	MaxSubscribersPerOwner = maxSubscribersTotal / 4
)

// Refusal reasons from SubscribeUser.
var (
	// ErrStreamLimitProject: the project or the process is at its ceiling.
	ErrStreamLimitProject = errors.New("decision stream limit reached for the project")
	// ErrStreamLimitUser: the user is at a per-user ceiling.
	ErrStreamLimitUser = errors.New("decision stream limit reached for the user")
	// ErrStreamLimitOwner: the projects of the project's owner are at
	// MaxSubscribersPerOwner.
	ErrStreamLimitOwner = errors.New("decision stream limit reached for the projects of the project's owner")
)

// DecisionBroker is a tiny pub/sub of WAF decisions keyed by project_id.
// Subscribers (HTTP SSE handlers) get a buffered channel; if the channel
// fills the broker drops the oldest event for that subscriber rather than
// blocking the gRPC receive loop.
// A per-project ring buffer stores the last replayBufSize events so that
// SSE clients reconnecting after a page refresh immediately receive history.
//
// Stored-decision subscriptions (SubscribeStored) receive no decisions: only
// a signal that decisions of one app have been written to waf_decisions
// (NotifyStored). They count toward the same ceilings.
type DecisionBroker struct {
	mu     sync.RWMutex
	subs   map[string]map[*Subscriber]struct{}    // project_id -> set
	stored map[string]map[*Subscriber]struct{}    // project_id -> stored-decision subscribers
	replay map[string][]*agentv1.WAFDecisionEvent // project_id -> ring buffer (oldest first)
	// replayAt is when each replay buffer last received an event; lastSweep
	// is when idle buffers were last dropped; now replaces time.Now (tests).
	replayAt  map[string]time.Time
	lastSweep time.Time
	now       func() time.Time
	// Per-user subscriber counts; only subscriptions made through
	// SubscribeUser are counted.
	userTotal   map[string]int         // user_id -> subscribers
	userProject map[userProjectKey]int // (user_id, project_id) -> subscribers
	// ownerTotal counts subscribers per owning account; only
	// subscriptions made with an owner are counted.
	ownerTotal map[string]int
}

type userProjectKey struct{ user, project string }

type Subscriber struct {
	ProjectID string
	// UserID is set for subscriptions made through SubscribeUser and
	// SubscribeStored.
	UserID string
	// OwnerID is the project's owning account, set for subscriptions made
	// through SubscribeUserOwned and SubscribeStoredOwned.
	OwnerID string
	// Ch receives the project's decisions; nil for a stored-decision
	// subscription.
	Ch chan *agentv1.WAFDecisionEvent
	// AppID (lower case) and Stored are set for a stored-decision
	// subscription: Stored holds at most one pending signal that decisions
	// of AppID have been written since the subscriber last read it.
	AppID  string
	Stored chan struct{}
}

func NewDecisionBroker() *DecisionBroker {
	return &DecisionBroker{
		subs:        make(map[string]map[*Subscriber]struct{}),
		stored:      make(map[string]map[*Subscriber]struct{}),
		replay:      make(map[string][]*agentv1.WAFDecisionEvent),
		replayAt:    make(map[string]time.Time),
		userTotal:   make(map[string]int),
		userProject: make(map[userProjectKey]int),
		ownerTotal:  make(map[string]int),
	}
}

// SubscribeUser is Subscribe for a named user: on top of the project and
// process ceilings it holds the user to MaxSubscribersPerUserProject streams
// per project and MaxSubscribersPerUser in all. It returns
// ErrStreamLimitUser or ErrStreamLimitProject when refused.
func (b *DecisionBroker) SubscribeUser(projectID, userID string, capacity int) (*Subscriber, error) {
	return b.SubscribeUserOwned(projectID, "", userID, capacity)
}

// SubscribeUserOwned is SubscribeUser that also holds ownerID, the account
// owning the project, to MaxSubscribersPerOwner across all its projects
// (ErrStreamLimitOwner). An empty ownerID skips that ceiling.
func (b *DecisionBroker) SubscribeUserOwned(projectID, ownerID, userID string, capacity int) (*Subscriber, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.admitUserLocked(projectID, ownerID, userID); err != nil {
		return nil, err
	}
	sub := b.subscribeLocked(projectID, capacity)
	if sub == nil {
		return nil, ErrStreamLimitProject
	}
	b.trackUserLocked(sub, ownerID, userID)
	return sub, nil
}

// SubscribeStored registers a stored-decision subscription for one app of a
// project: its Stored channel is signalled by NotifyStored, and it receives
// no decisions. It is held to the same project, process and per-user
// ceilings as SubscribeUser and returns the same errors.
func (b *DecisionBroker) SubscribeStored(projectID, appID, userID string) (*Subscriber, error) {
	return b.SubscribeStoredOwned(projectID, "", appID, userID)
}

// SubscribeStoredOwned is SubscribeStored with the per-owner ceiling of
// SubscribeUserOwned.
func (b *DecisionBroker) SubscribeStoredOwned(projectID, ownerID, appID, userID string) (*Subscriber, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	if err := b.admitUserLocked(projectID, ownerID, userID); err != nil {
		return nil, err
	}
	if b.projectCountLocked(projectID) >= maxSubscribersPerProject || b.countLocked() >= maxSubscribersTotal {
		return nil, ErrStreamLimitProject
	}
	sub := &Subscriber{
		ProjectID: projectID,
		AppID:     strings.ToLower(appID),
		Stored:    make(chan struct{}, 1),
	}
	set, ok := b.stored[projectID]
	if !ok {
		set = make(map[*Subscriber]struct{})
		b.stored[projectID] = set
	}
	set[sub] = struct{}{}
	b.trackUserLocked(sub, ownerID, userID)
	return sub, nil
}

// NotifyStored signals the stored-decision subscribers of projectID whose app
// is in appIDs (lower case) that decisions of that app are now in
// waf_decisions. A subscriber holds at most one pending signal, so a burst of
// writes costs it one wake-up. Never blocks.
func (b *DecisionBroker) NotifyStored(projectID string, appIDs map[string]struct{}) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	// Unsubscribe closes Stored under the write lock, so no send here can
	// meet a closed channel.
	for s := range b.stored[projectID] {
		if _, ok := appIDs[s.AppID]; !ok {
			continue
		}
		select {
		case s.Stored <- struct{}{}:
		default: // a signal is already pending
		}
	}
}

// HasStoredSubscribers reports whether any stored-decision subscription is
// open, so the writer can skip collecting app IDs when nobody listens.
func (b *DecisionBroker) HasStoredSubscribers() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.stored) > 0
}

// admitUserLocked applies the per-user ceilings and the per-owner
// one. The caller holds b.mu.
func (b *DecisionBroker) admitUserLocked(projectID, ownerID, userID string) error {
	if ownerID != "" && b.ownerTotal[ownerID] >= MaxSubscribersPerOwner {
		return ErrStreamLimitOwner
	}
	if userID != "" {
		if b.userTotal[userID] >= MaxSubscribersPerUser ||
			b.userProject[userProjectKey{userID, projectID}] >= MaxSubscribersPerUserProject {
			return ErrStreamLimitUser
		}
	}
	return nil
}

// trackUserLocked counts sub against ownerID and userID. The caller holds
// b.mu.
func (b *DecisionBroker) trackUserLocked(sub *Subscriber, ownerID, userID string) {
	if ownerID != "" {
		sub.OwnerID = ownerID
		b.ownerTotal[ownerID]++
	}
	if userID == "" {
		return
	}
	sub.UserID = userID
	b.userTotal[userID]++
	b.userProject[userProjectKey{userID, sub.ProjectID}]++
}

// UserSubscriberCount reports the subscribers a user holds in all projects.
func (b *DecisionBroker) UserSubscriberCount(userID string) int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.userTotal[userID]
}

// Subscribe returns a Subscriber whose channel receives decisions for the
// given project. Capacity is fixed; on overflow the broker drops the
// oldest. Recent events from the replay buffer are immediately queued so
// SSE clients that reconnect after a refresh see the last replayBufSize
// decisions right away.
// Subscribe returns nil when the project or the process is already at its
// subscriber ceiling. Callers must handle that -- see maxSubscribersPerProject.
func (b *DecisionBroker) Subscribe(projectID string, capacity int) *Subscriber {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.subscribeLocked(projectID, capacity)
}

// subscribeLocked registers a subscriber under the project and process
// ceilings. The caller holds b.mu.
func (b *DecisionBroker) subscribeLocked(projectID string, capacity int) *Subscriber {
	if capacity <= 0 {
		capacity = 64
	}
	if b.projectCountLocked(projectID) >= maxSubscribersPerProject || b.countLocked() >= maxSubscribersTotal {
		return nil
	}
	b.sweepReplayLocked()

	sub := &Subscriber{
		ProjectID: projectID,
		Ch:        make(chan *agentv1.WAFDecisionEvent, capacity),
	}
	set, ok := b.subs[projectID]
	if !ok {
		set = make(map[*Subscriber]struct{})
		b.subs[projectID] = set
	}
	set[sub] = struct{}{}
	// Replay buffered events (non-blocking; skip if channel would fill).
	for _, ev := range b.replay[projectID] {
		select {
		case sub.Ch <- ev:
		default:
		}
	}
	return sub
}

// countLocked returns the number of subscribers across all projects. The caller
// holds b.mu.
func (b *DecisionBroker) countLocked() int {
	n := 0
	for _, set := range b.subs {
		n += len(set)
	}
	for _, set := range b.stored {
		n += len(set)
	}
	return n
}

// projectCountLocked returns the subscribers of one project, stored-decision
// subscriptions included. The caller holds b.mu.
func (b *DecisionBroker) projectCountLocked(projectID string) int {
	return len(b.subs[projectID]) + len(b.stored[projectID])
}

// ProjectSubscriberCount reports subscribers for a single project.
func (b *DecisionBroker) ProjectSubscriberCount(projectID string) int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.projectCountLocked(projectID)
}

// Unsubscribe removes a subscriber and closes its channel. It takes the write
// lock that Publish holds while sending, which is what makes the close safe.
func (b *DecisionBroker) Unsubscribe(sub *Subscriber) {
	if sub == nil {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if sub.Stored != nil {
		if set, ok := b.stored[sub.ProjectID]; ok {
			if _, present := set[sub]; present {
				delete(set, sub)
				close(sub.Stored)
				b.releaseUserLocked(sub)
			}
			if len(set) == 0 {
				delete(b.stored, sub.ProjectID)
			}
		}
		return
	}
	if set, ok := b.subs[sub.ProjectID]; ok {
		if _, present := set[sub]; present {
			delete(set, sub)
			close(sub.Ch)
			b.releaseUserLocked(sub)
		}
		if len(set) == 0 {
			delete(b.subs, sub.ProjectID)
		}
	}
}

// releaseUserLocked drops sub from the per-user and per-owner counts. The
// caller holds b.mu.
func (b *DecisionBroker) releaseUserLocked(sub *Subscriber) {
	if sub.OwnerID != "" {
		if n := b.ownerTotal[sub.OwnerID] - 1; n > 0 {
			b.ownerTotal[sub.OwnerID] = n
		} else {
			delete(b.ownerTotal, sub.OwnerID)
		}
	}
	if sub.UserID == "" {
		return
	}
	if n := b.userTotal[sub.UserID] - 1; n > 0 {
		b.userTotal[sub.UserID] = n
	} else {
		delete(b.userTotal, sub.UserID)
	}
	k := userProjectKey{sub.UserID, sub.ProjectID}
	if n := b.userProject[k] - 1; n > 0 {
		b.userProject[k] = n
	} else {
		delete(b.userProject, k)
	}
}

// Publish fans out a decision to all subscribers of the project.
// Non-blocking: if a subscriber's buffer is full the oldest event is dropped.
// The event is also appended to the per-project replay ring buffer.
//
// The sends happen while b.mu is held. Unsubscribe closes a channel under the
// same lock, so a send can never meet a closed channel (sending on a
// snapshot after unlocking panicked when a tab disconnected mid-publish).
// Every send is non-blocking, so holding the lock costs at most one channel
// operation per subscriber, bounded by maxSubscribersPerProject.
func (b *DecisionBroker) Publish(projectID string, ev *agentv1.WAFDecisionEvent) {
	b.mu.Lock()
	defer b.mu.Unlock()

	buf := b.replay[projectID]
	buf = append(buf, ev)
	if len(buf) > replayBufSize {
		buf = buf[len(buf)-replayBufSize:]
	}
	b.replay[projectID] = buf
	if b.replayAt == nil {
		b.replayAt = make(map[string]time.Time)
	}
	b.replayAt[projectID] = b.nowLocked()
	b.sweepReplayLocked()

	for s := range b.subs[projectID] {
		select {
		case s.Ch <- ev:
		default:
			// drop oldest, then push
			select {
			case <-s.Ch:
			default:
			}
			select {
			case s.Ch <- ev:
			default:
			}
		}
	}
}

func (b *DecisionBroker) nowLocked() time.Time {
	if b.now != nil {
		return b.now()
	}
	return time.Now()
}

// sweepReplayLocked drops the replay buffers that received nothing for
// replayIdleTTL and have no live subscriber -- deleted projects, mostly.
// Runs at most every replaySweepEvery. The caller holds b.mu for writing.
func (b *DecisionBroker) sweepReplayLocked() {
	now := b.nowLocked()
	if now.Sub(b.lastSweep) < replaySweepEvery {
		return
	}
	b.lastSweep = now
	for projectID := range b.replay {
		if len(b.subs[projectID]) > 0 || now.Sub(b.replayAt[projectID]) < replayIdleTTL {
			continue
		}
		delete(b.replay, projectID)
		delete(b.replayAt, projectID)
	}
}

// ReplayBuffers is the number of projects with a replay buffer (tests,
// diagnostics).
func (b *DecisionBroker) ReplayBuffers() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.replay)
}

// SubscriberCount returns total subscribers (for diagnostics).
func (b *DecisionBroker) SubscriberCount() int {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.countLocked()
}
