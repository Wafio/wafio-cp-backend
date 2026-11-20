package agentserver

import (
	"context"
	"errors"
	"log"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	agentv1 "github.com/wafio/wafio-cp-backend/shared/agentpb"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// Credential revocation. The fingerprint is checked when a stream
// opens; after that three things end a stream whose credential is gone:
//
//  1. DisconnectCredential, called by the revoke endpoint right after the
//     row is deleted, closes every stream authenticated with it;
//  2. each stream re-reads its credential every credentialRecheck (default
//     5 min), which catches deletes that bypass the endpoint (project
//     delete cascade, manual SQL);
//  3. gRPC MaxConnectionAge closes every connection after a day.
//
// A stream also re-reads its credential once right after it is tracked, so
// a revoke that lands between the interceptor's lookup and the tracking is
// not missed, and once more after Hello validation, before Welcome and the
// first bundle, so a revoke that lands while Hello is being validated sends
// nothing. Project delete ends every stream of the project's credentials
// through DisconnectProject (the cascade removes the rows without going
// through the revoke endpoint), and DownloadMalwareDatabase streams are
// tracked like Stream calls, so both disconnects reach them too.

const (
	// defaultCredentialRecheck is how often an open stream re-reads its
	// credential from mtls_credentials.
	defaultCredentialRecheck = 5 * time.Minute
	// credentialLookupTimeout bounds one re-check query.
	credentialLookupTimeout = 3 * time.Second

	// grpcMaxConnectionAge / grpcMaxConnectionAgeGrace: backstop for every
	// other path. The agent reconnects (and is re-authenticated) after a
	// GOAWAY; the grace lets an in-flight bundle or telemetry batch finish.
	grpcMaxConnectionAge      = 24 * time.Hour
	grpcMaxConnectionAgeGrace = 5 * time.Minute
)

// errCredentialRevoked ends a stream whose credential no longer exists.
var errCredentialRevoked = status.Error(codes.Unauthenticated, "credential revoked")

// liveStream is one open Stream call, tracked from its first line until it
// returns, independent of whether it is the credential's push target.
type liveStream struct {
	// projectID is the project the credential belonged to at open, for
	// DisconnectProject.
	projectID string
	// hostID and agentID are the host and agent row the stream was bound to
	// by Hello, for DisconnectHost. Written and read under
	// Server.liveMu.
	hostID, agentID string
	revoked         chan struct{}
	once            sync.Once
	// hostRevoked is closed by DisconnectHost.
	hostRevoked chan struct{}
	hostOnce    sync.Once
	// stuck is closed when a push to this stream missed its send deadline; the handler then
	// returns so the blocked Send is released.
	stuck     chan struct{}
	stuckOnce sync.Once
}

func (l *liveStream) revoke() { l.once.Do(func() { close(l.revoked) }) }

// isRevoked reports whether a disconnect already signalled this stream.
func (l *liveStream) isRevoked() bool {
	select {
	case <-l.revoked:
		return true
	default:
		return false
	}
}

// ending reports whether the stream was told to end: a revoke of its credential or of its host, or a
// push that missed its send deadline. The handler returns soon after, so nothing secret should still
// be sent to it.
func (l *liveStream) ending() bool {
	select {
	case <-l.stuck:
		return true
	default:
	}
	return l.isRevoked() || l.hostRevokedNow()
}

// markStuck ends the stream because a push could not be delivered in time.
func (l *liveStream) markStuck() { l.stuckOnce.Do(func() { close(l.stuck) }) }

// trackLive records a stream for credID of projectID and returns the handle
// plus the function that forgets it.
func (s *Server) trackLive(credID, projectID string) (*liveStream, func()) {
	l := &liveStream{projectID: projectID, revoked: make(chan struct{}), hostRevoked: make(chan struct{}), stuck: make(chan struct{})}
	s.liveMu.Lock()
	if s.live == nil {
		s.live = make(map[string]map[*liveStream]struct{})
	}
	set := s.live[credID]
	if set == nil {
		set = make(map[*liveStream]struct{})
		s.live[credID] = set
	}
	set[l] = struct{}{}
	s.liveMu.Unlock()
	return l, func() {
		s.liveMu.Lock()
		defer s.liveMu.Unlock()
		if set := s.live[credID]; set != nil {
			delete(set, l)
			if len(set) == 0 {
				delete(s.live, credID)
			}
		}
	}
}

// DisconnectCredential ends every open stream authenticated with credID and
// returns how many it signalled. Each stream returns Unauthenticated and
// unregisters itself; the agent's reconnect is then refused by the auth
// interceptor because the row is gone. Safe on a nil or bare Server.
func (s *Server) DisconnectCredential(credID string) int {
	if s == nil || credID == "" {
		return 0
	}
	s.liveMu.Lock()
	set := s.live[credID]
	delete(s.live, credID)
	s.liveMu.Unlock()
	for l := range set {
		l.revoke()
	}
	if len(set) > 0 {
		log.Printf("[agentserver] credential revoked: closed %d stream(s) credential=%s", len(set), credID)
	}
	return len(set)
}

// DisconnectProject ends every open stream whose credential belonged to
// projectID and returns how many it signalled. Project delete calls it after
// the cascade removed the project's credentials, so their streams do not
// live on until the next periodic re-check. Safe on a nil or bare Server.
func (s *Server) DisconnectProject(projectID string) int {
	if s == nil || projectID == "" {
		return 0
	}
	var hit []*liveStream
	s.liveMu.Lock()
	for credID, set := range s.live {
		for l := range set {
			if l.projectID == projectID {
				hit = append(hit, l)
				delete(set, l)
			}
		}
		if len(set) == 0 {
			delete(s.live, credID)
		}
	}
	s.liveMu.Unlock()
	for _, l := range hit {
		l.revoke()
	}
	if len(hit) > 0 {
		log.Printf("[agentserver] project deleted: closed %d stream(s) project=%s", len(hit), projectID)
	}
	return len(hit)
}

// bindLive records the host and agent a stream's Hello resolved to, so a
// host revoke can find it.
func (s *Server) bindLive(l *liveStream, hostID, agentID string) {
	s.liveMu.Lock()
	defer s.liveMu.Unlock()
	l.hostID, l.agentID = hostID, agentID
}

// DisconnectHost ends every open stream of projectID bound to hostID, or to
// one of agentIDs (the host's agents, for streams whose host link was made
// after their Hello), and returns how many it signalled. The host revoke
// and delete endpoints call it: revoking a host used to only mark
// the row, while its agents stayed connected, kept receiving desired
// firewall state and kept writing telemetry. Each stream returns
// PermissionDenied ("host revoked"); the agent's reconnect is refused at
// Hello. Safe on a nil or bare Server.
func (s *Server) DisconnectHost(projectID, hostID string, agentIDs []string) int {
	if s == nil || projectID == "" || (hostID == "" && len(agentIDs) == 0) {
		return 0
	}
	agents := make(map[string]bool, len(agentIDs))
	for _, id := range agentIDs {
		if id != "" {
			agents[id] = true
		}
	}
	var hit []*liveStream
	s.liveMu.Lock()
	for _, set := range s.live {
		for l := range set {
			if l.projectID != projectID {
				continue
			}
			if (hostID != "" && l.hostID == hostID) || agents[l.agentID] {
				hit = append(hit, l)
			}
		}
	}
	s.liveMu.Unlock()
	for _, l := range hit {
		l.revokeHost()
	}
	if len(hit) > 0 {
		log.Printf("[agentserver] host revoked: closed %d stream(s) project=%s host=%s", len(hit), projectID, hostID)
	}
	return len(hit)
}

// errHostRevoked ends a stream whose host was revoked or deleted.
var errHostRevoked = status.Error(codes.PermissionDenied, "host revoked")

// revokeHost ends the stream because its host was revoked.
func (l *liveStream) revokeHost() { l.hostOnce.Do(func() { close(l.hostRevoked) }) }

// hostRevokedNow reports whether DisconnectHost already signalled this stream.
func (l *liveStream) hostRevokedNow() bool {
	select {
	case <-l.hostRevoked:
		return true
	default:
		return false
	}
}

// hostStillActive re-reads the host a stream is bound to. It is false only
// when the host is revoked or gone; a transient lookup error keeps the
// stream, like the credential re-check.
func (s *Server) hostStillActive(ctx context.Context, projectID, hostID string) bool {
	if hostID == "" {
		return true
	}
	if s.hostRevokedLookup == nil && (s.Repo == nil || s.Repo.Host == nil) {
		return true
	}
	lctx, cancel := context.WithTimeout(ctx, credentialLookupTimeout)
	defer cancel()
	var revoked bool
	var err error
	if s.hostRevokedLookup != nil {
		revoked, err = s.hostRevokedLookup(lctx, projectID, hostID)
	} else {
		revoked, err = s.Repo.Host.HostRevoked(lctx, projectID, hostID)
	}
	if err != nil {
		if ctx.Err() == nil {
			log.Printf("[agentserver] host re-check failed host=%s: %v (stream kept)", hostID, err)
		}
		return true
	}
	return !revoked
}

// agentHostID returns the host agentID is linked to ("" for none or on a
// lookup error).
func (s *Server) agentHostID(ctx context.Context, agentID string) string {
	if s.agentHostLookup != nil {
		return s.agentHostLookup(agentID)
	}
	if s.Repo == nil || s.Repo.EBPF == nil {
		return ""
	}
	lctx, cancel := context.WithTimeout(ctx, credentialLookupTimeout)
	defer cancel()
	return s.Repo.EBPF.GetAgentHostID(lctx, agentID)
}

// liveStreamCount reports the open streams for credID (tests).
func (s *Server) liveStreamCount(credID string) int {
	s.liveMu.Lock()
	defer s.liveMu.Unlock()
	return len(s.live[credID])
}

func (s *Server) lookupCredential(ctx context.Context, fp string) (*repository.MTLSCredential, error) {
	if s.credLookup != nil {
		return s.credLookup(ctx, fp)
	}
	if s.Repo == nil || s.Repo.AgentGRPC == nil {
		return nil, errors.New("credential store unavailable")
	}
	return s.Repo.AgentGRPC.LookupAgentCredentialByFingerprint(ctx, fp)
}

// credentialStillValid re-reads the credential for fp. It is false only when
// the row is gone or now names another credential or project; a transient
// lookup error keeps the stream (a database blip must not disconnect the
// fleet) and is retried on the next tick. MaxConnectionAge bounds how long
// that can last.
func (s *Server) credentialStillValid(ctx context.Context, fp, credID, projectID string) bool {
	if fp == "" {
		return false
	}
	lctx, cancel := context.WithTimeout(ctx, credentialLookupTimeout)
	defer cancel()
	cred, err := s.lookupCredential(lctx, fp)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return false
	case err != nil:
		if ctx.Err() == nil {
			log.Printf("[agentserver] credential re-check failed credential=%s: %v (stream kept)", credID, err)
		}
		return true
	}
	return cred.ID == credID && cred.ProjectID == projectID
}

func (s *Server) recheckInterval() time.Duration {
	if s.credentialRecheck > 0 {
		return s.credentialRecheck
	}
	return defaultCredentialRecheck
}

type recvResult struct {
	msg *agentv1.AgentMessage
	err error
}

// streamReceiver reads a stream on its own goroutine so the handler can
// stop waiting when the credential is revoked: stream.Recv cannot be
// interrupted from outside, but returning from the handler ends the stream,
// which unblocks Recv and lets the goroutine exit.
type streamReceiver struct {
	s         *Server
	ctx       context.Context
	msgs      chan recvResult
	done      chan struct{}
	live      *liveStream
	ticker    *time.Ticker
	fp        string
	credID    string
	projectID string
	// hostID is the host Hello bound the stream to ("" for none); it is
	// re-checked with the credential. agentID is the stream's agent
	// row: while hostID is empty the re-check looks the agent's host up
	// again, since a WAF agent is linked to its host by hostname in the
	// background after Hello. Both are set and read on the handler
	// goroutine only.
	hostID, agentID string
	// handle is the stream's registered handle (nil before Hello's end);
	// a host link the re-check finds is copied to it.
	handle *streamHandle
	// owner is the account charged for every message received (recvBudget).
	owner string
	// onStall marks the agent as seen (touchStreamLiveness); set after
	// Hello. lastAlive is when it last was: the stream's start, its last
	// heartbeat, or the last onStall. Both are used on the handler goroutine
	// only.
	onStall   func()
	lastAlive time.Time
	// want asks the receive goroutine for the next message: it calls
	// stream.Recv only then, so no decoded message waits ahead of the
	// handler. asked: a request is outstanding; first: the next message is
	// the stream's first (Hello).
	want         chan struct{}
	asked, first bool
}

const (
	// maxFirstMessageBytes caps the first message (the Hello).
	maxFirstMessageBytes = 64 << 10
	// recvBudgetPoll caps one wait for the receive budget: a waiting stream
	// asks again at least this often, which keeps its account counted as
	// active for the fair share and applies a changed share.
	recvBudgetPoll = recvSharePeriod
	// stallLivenessEvery: while a stream waits for the receive budget, the
	// agent is marked as seen this often after its last heartbeat (agents
	// send one every 30 s; a host is offline after 90 s), so a throttled
	// agent does not look offline.
	stallLivenessEvery = 30 * time.Second
)

func (s *Server) newStreamReceiver(stream agentv1.AgentControl_StreamServer, live *liveStream, fp, credID, projectID string) *streamReceiver {
	r := &streamReceiver{
		s:         s,
		ctx:       stream.Context(),
		msgs:      make(chan recvResult),
		done:      make(chan struct{}),
		live:      live,
		ticker:    time.NewTicker(s.recheckInterval()),
		fp:        fp,
		credID:    credID,
		projectID: projectID,
		owner:     s.projectOwner(projectID),
		want:      make(chan struct{}, 1),
		first:     true,
		lastAlive: time.Now(),
	}
	go func() {
		defer recoverPanic("stream-recv")
		for {
			select {
			case <-r.want:
			case <-r.done:
				return
			}
			msg, err := stream.Recv()
			select {
			case r.msgs <- recvResult{msg: msg, err: err}:
			case <-r.done:
				return
			}
			if err != nil {
				return
			}
		}
	}()
	return r
}

// admit charges n bytes to the stream's owner once its receive budget is
// out of debt (recvBudget), waiting until then;
// admit(0) only waits. The wait ends early on revocation, a stuck push or
// the stream's end, and keeps the periodic credential and host re-check;
// while it lasts the agent is still marked as seen (keepAlive).
func (r *streamReceiver) admit(n int) error {
	if r.s == nil {
		return nil // a receiver built without a server (tests)
	}
	b := &r.s.recvBudget
	var waitStart time.Time
	for {
		now := time.Now()
		wait, contended := b.admit(r.owner, n, now)
		if wait <= 0 {
			if !waitStart.IsZero() {
				b.waited(now.Sub(waitStart))
			}
			return nil
		}
		if waitStart.IsZero() {
			waitStart = now
			b.noteWait(contended)
		}
		r.keepAlive(now)
		if err := r.pause(min(wait, recvBudgetPoll)); err != nil {
			b.waited(time.Since(waitStart))
			return err
		}
	}
}

// keepAlive marks the agent as seen once its stream has waited for the
// receive budget stallLivenessEvery past its last heartbeat: the stream is
// open, re-checked and kept alive by HTTP/2 pings, and only the control plane
// is holding its heartbeats back.
func (r *streamReceiver) keepAlive(now time.Time) {
	if r.onStall == nil || now.Sub(r.lastAlive) < stallLivenessEvery {
		return
	}
	r.lastAlive = now
	r.onStall()
	r.s.recvBudget.liveTouches.Add(1)
}

// pause waits d, or less on revocation, a stuck push, the stream's end or a
// failed periodic re-check (returned as the error).
func (r *streamReceiver) pause(d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-r.live.revoked:
		return errCredentialRevoked
	case <-r.live.hostRevoked:
		return errHostRevoked
	case <-r.live.stuck:
		return errStreamStuck
	case <-r.ctx.Done():
		return r.ctx.Err()
	case <-r.ticker.C:
		return r.recheck()
	}
}

// close releases the receive goroutine and the ticker. Call when the
// handler returns.
func (r *streamReceiver) close() {
	r.ticker.Stop()
	close(r.done)
}

// recv returns the next agent message, or errCredentialRevoked once the
// credential is revoked or fails a periodic re-check. While the owner's
// receive budget is in debt it reads nothing (no decoded message is held);
// each message read is charged at its size (recvBudget).
// The first message (the Hello) may be at most
// maxFirstMessageBytes. A heartbeat read marks the agent as alive for
// keepAlive.
func (r *streamReceiver) recv() (*agentv1.AgentMessage, error) {
	if !r.asked {
		if err := r.admit(0); err != nil {
			return nil, err
		}
		select {
		case r.want <- struct{}{}: // buffered, one request outstanding at most
		default: // nil (a receiver built without the goroutine)
		}
		r.asked = true
	}
	for {
		select {
		case res := <-r.msgs:
			r.asked = false
			if res.err != nil {
				return nil, res.err
			}
			n := proto.Size(res.msg)
			if r.first {
				r.first = false
				if n > maxFirstMessageBytes {
					return nil, status.Error(codes.InvalidArgument, "first message too large")
				}
			}
			now := time.Now()
			if r.s != nil {
				r.s.recvBudget.charge(r.owner, n, now)
			}
			if res.msg.GetHeartbeat() != nil {
				r.lastAlive = now
			}
			return res.msg, nil
		case <-r.live.revoked:
			return nil, errCredentialRevoked
		case <-r.live.hostRevoked:
			return nil, errHostRevoked
		case <-r.live.stuck:
			return nil, errStreamStuck
		case <-r.ticker.C:
			if err := r.recheck(); err != nil {
				return nil, err
			}
		}
	}
}

// recheck re-reads the credential and the host (every recheckInterval).
func (r *streamReceiver) recheck() error {
	if !r.s.credentialStillValid(r.ctx, r.fp, r.credID, r.projectID) {
		log.Printf("[agentserver] credential no longer valid, closing stream project=%s credential=%s", r.projectID, r.credID)
		return errCredentialRevoked
	}
	// Catches a revoke or delete that bypassed the endpoint, and a host link
	// made after Hello.
	if r.hostID == "" && r.agentID != "" {
		if hostID := r.s.agentHostID(r.ctx, r.agentID); hostID != "" {
			r.hostID = hostID
			r.s.bindLive(r.live, hostID, r.agentID)
			if r.handle != nil {
				r.handle.linkedHost.Store(&hostID)
			}
		}
	}
	if !r.s.hostStillActive(r.ctx, r.projectID, r.hostID) {
		log.Printf("[agentserver] host revoked, closing stream project=%s host=%s", r.projectID, r.hostID)
		return errHostRevoked
	}
	return nil
}
