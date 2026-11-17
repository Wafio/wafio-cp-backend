package agentserver

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/google/uuid"
	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
	agentv1 "github.com/wafio/wafio-cp-backend/shared/agentpb"
	"time"
)

var ErrUnblockOffline = errors.New("agent offline; block entry retained")
var ErrUnblockNotFound = errors.New("block entry not found")
var ErrUnblockUnsupported = errors.New("entry does not support remote unblocking")
var ErrUnblockBusy = errors.New("unblock queue full; retry later")

const unblockTimeout = 10 * time.Second
const unblockRetention = 5 * time.Minute

// unblockCapacity bounds the operations held process-wide. The table is
// shared fairly by project: when it is full the project holding the
// most operations gives one up (evictUnblockLocked), so one project's burst
// of unblocks cannot make every other project's unblock answer 503.
const unblockCapacity = 1024

type UnblockOperation struct {
	CommandID                   string    `json:"command_id"`
	Status                      string    `json:"status"`
	Error                       string    `json:"error,omitempty"`
	ExpiresAt                   time.Time `json:"expires_at"`
	projectID, agentID, entryID string
	entry                       BlockEntry
	waiting                     map[*streamHandle]bool
}

// RequestUnblock tracks only this process's evidence. It never deletes an entry on send.
func (s *Server) RequestUnblock(projectID, agentID, entryID string) (*UnblockOperation, error) {
	entry := s.BlockWindow.Get(projectID, agentID, entryID)
	if entry == nil {
		return nil, ErrUnblockNotFound
	}
	if entry.UnblockType == "" || (entry.UnblockKey == "" && entry.UnblockType != "login_scope") {
		return nil, ErrUnblockUnsupported
	}
	s.mu.RLock()
	targets := []*streamHandle{}
	for _, h := range s.streams {
		if h.projectID == projectID && h.agentID == agentID && h.agentKind == "waf" {
			targets = append(targets, h)
		}
	}
	s.mu.RUnlock()
	if len(targets) == 0 {
		return nil, ErrUnblockOffline
	}
	owner := s.projectOwner(projectID)
	s.unblockMu.Lock()
	if s.unblocks == nil {
		s.unblocks = map[string]*UnblockOperation{}
	}
	now := time.Now()
	for id, op := range s.unblocks {
		if now.After(op.ExpiresAt.Add(unblockRetention)) {
			s.deleteUnblockLocked(id)
			continue
		}
		if op.projectID == projectID && op.agentID == agentID && op.entryID == entryID && op.Status == "pending" {
			cp := *op
			s.unblockMu.Unlock()
			return &cp, nil
		}
	}
	if len(s.unblocks) >= s.unblockCap() && !s.evictUnblockLocked(owner, projectID) {
		s.unblockMu.Unlock()
		return nil, ErrUnblockBusy
	}
	op := &UnblockOperation{CommandID: "unblock-" + uuid.NewString(), Status: "pending", ExpiresAt: now.Add(unblockTimeout), projectID: projectID, agentID: agentID, entryID: entryID, entry: *entry, waiting: map[*streamHandle]bool{}}
	for _, h := range targets {
		op.waiting[h] = true
	}
	s.unblocks[op.CommandID] = op
	s.unblockLedger.Add(owner, projectID, 1)
	cp := *op
	s.unblockMu.Unlock()
	raw, _ := json.Marshal(struct {
		ManagementOnly bool           `json:"management_only"`
		UnblockEntries []UnblockEntry `json:"unblock_entries"`
	}{true, []UnblockEntry{{Type: entry.UnblockType, Scope: entry.UnblockScope, Key: entry.UnblockKey}}})
	msg := &agentv1.ServerMessage{Kind: &agentv1.ServerMessage_Bundle{Bundle: &agentv1.BundleUpdate{CommandId: op.CommandID, BundleJson: raw}}}
	// Stream writes are outside global locks. At most capacity operations are retained.
	for _, h := range targets {
		go func(h *streamHandle) {
			defer recoverPanic("unblock-send")
			if err := s.sendBounded(h, func() error { return h.send(msg) }); err != nil {
				s.recordUnblockAck(h, &agentv1.CommandAck{CommandId: cp.CommandID, Ok: false, Error: "command send failed; delivery unknown"})
			}
		}(h)
	}
	time.AfterFunc(unblockTimeout, func() { s.expireUnblock(cp.CommandID) })
	return &cp, nil
}

func (s *Server) unblockCap() int {
	if s.unblockCapacity > 0 {
		return s.unblockCapacity
	}
	return unblockCapacity
}

// deleteUnblockLocked forgets operation id. The caller holds unblockMu.
func (s *Server) deleteUnblockLocked(id string) {
	if op := s.unblocks[id]; op != nil {
		delete(s.unblocks, id)
		s.unblockLedger.Add(op.projectID, op.projectID, -1) // charged to the owner recorded at insert
	}
}

// evictUnblockLocked makes room for one operation of projectID (owned by
// owner) in a full table. The account holding the most operations
// and, inside it, its project holding the most gives one up --
// its oldest finished one (kept only so its status can be read), else, when
// that project is not the requester, its oldest pending one (its outcome is
// then audited as "evicted"). A project that is itself the largest holder
// never loses a pending operation to its own request; it is refused
// instead. Reports whether room was made. The caller holds unblockMu.
func (s *Server) evictUnblockLocked(owner, projectID string) bool {
	_, victim := s.unblockLedger.Victim(owner, projectID)
	var finished, pending *UnblockOperation
	for _, op := range s.unblocks {
		if op.projectID != victim {
			continue
		}
		if op.Status == "pending" {
			if pending == nil || op.ExpiresAt.Before(pending.ExpiresAt) {
				pending = op
			}
		} else if finished == nil || op.ExpiresAt.Before(finished.ExpiresAt) {
			finished = op
		}
	}
	switch {
	case finished != nil:
		s.deleteUnblockLocked(finished.CommandID)
		return true
	case pending != nil && victim != projectID:
		s.deleteUnblockLocked(pending.CommandID)
		pending.Status = "evicted"
		pending.Error = "dropped from the unblock table to make room for another project; agent state unknown"
		pending.waiting = nil
		go s.auditUnblockOutcome(*pending)
		return true
	}
	return false
}
func (s *Server) expireUnblock(id string) {
	defer recoverPanic("unblock-expire") // time.AfterFunc goroutine
	s.unblockMu.Lock()
	defer s.unblockMu.Unlock()
	if op := s.unblocks[id]; op != nil && op.Status == "pending" {
		op.Status = "timeout"
		op.Error = "acknowledgement timed out; agent state unknown"
		op.waiting = nil
		go s.auditUnblockOutcome(*op)
	}
}
func (s *Server) recordUnblockAck(h *streamHandle, ack *agentv1.CommandAck) {
	s.unblockMu.Lock()
	defer s.unblockMu.Unlock()
	op := s.unblocks[ack.GetCommandId()]
	wasPending := op != nil && op.Status == "pending"
	defer func() {
		if wasPending && op.Status != "pending" {
			op.waiting = nil
			go s.auditUnblockOutcome(*op)
		}
	}()
	if op == nil || op.Status != "pending" || op.projectID != h.projectID || op.agentID != h.agentID || !op.waiting[h] {
		return
	}
	if time.Now().After(op.ExpiresAt) {
		op.Status = "timeout"
		op.Error = "acknowledgement timed out; agent state unknown"
		op.waiting = nil
		return
	}
	if !ack.GetOk() {
		op.Status = "failed"
		op.Error = "agent rejected command or send failed; entry retained"
		op.waiting = nil
		return
	}
	delete(op.waiting, h)
	if len(op.waiting) > 0 {
		return
	}
	if s.BlockWindow.DeleteUnchanged(op.entry) {
		op.Status = "applied"
	} else {
		op.Status = "superseded"
		op.Error = "newer block evidence exists; entry retained"
	}
}
func (s *Server) UnblockStatus(projectID, agentID, entryID string) *UnblockOperation {
	s.unblockMu.Lock()
	defer s.unblockMu.Unlock()
	var newest *UnblockOperation
	for id, op := range s.unblocks {
		if time.Now().After(op.ExpiresAt.Add(unblockRetention)) {
			s.deleteUnblockLocked(id)
			continue
		}
		if op.projectID == projectID && op.agentID == agentID && op.entryID == entryID && (newest == nil || op.ExpiresAt.After(newest.ExpiresAt)) {
			newest = op
		}
	}
	if newest == nil {
		return nil
	}
	cp := *newest
	cp.waiting = nil
	return &cp
}

func (s *Server) auditUnblockOutcome(op UnblockOperation) {
	defer recoverPanic("unblock-audit")
	if s.Repo == nil {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = s.Repo.Audit.Log(ctx, repository.AuditEvent{ProjectID: op.projectID, Action: "waf.unblock_outcome", TargetType: "agent", TargetID: op.agentID, MetadataJSON: map[string]any{"command_id": op.CommandID, "entry_id": op.entryID, "status": op.Status}})
}
