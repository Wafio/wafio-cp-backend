package agentserver

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"sync/atomic"
	"time"
)

// maxBlockEntriesPerAgent bounds one agent's active block entries.
// Every entry is created by inbound traffic at a rate an attacker sets, so
// the store is capped per agent; past the cap the oldest entry is evicted.
const maxBlockEntriesPerAgent = 5000

// newBlockEntryID returns a random 128-bit hex ID. IDs used to be UnixNano
// in one map shared by every project, so two blocks recorded in the same
// nanosecond overwrote each other across tenants.
func newBlockEntryID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// crypto/rand does not fail on supported platforms; fall back to a
		// clock value rather than panic on the ingest path.
		return time.Now().Format("20060102150405.000000000")
	}
	return hex.EncodeToString(b[:])
}

// BlockEntry is a record of a block event recorded by the control plane when
// it observes a block action from a WAF agent for LoginProtection or BlockPolicy.
type BlockEntry struct {
	ID        string    `json:"id"`
	ProjectID string    `json:"project_id"`
	AgentID   string    `json:"agent_id"`
	Key       string    `json:"key"`      // blocked identifier (usually IP)
	KeyType   string    `json:"key_type"` // "ip", "field", "ua"
	Reason    string    `json:"reason"`   // "LoginProtection" | "BlockPolicy"
	Path      string    `json:"path"`     // URI where the block occurred
	ExpiresAt time.Time `json:"expires_at"`
	BlockedAt time.Time `json:"blocked_at"`

	// Fields used to reconstruct the unblock command; not exposed to the API.
	UnblockType  string `json:"-"` // "ratelimit" | "blockpolicy"
	UnblockScope string `json:"-"` // scope string for rate-limit unblock
	UnblockKey   string `json:"-"` // key value for unblock
}

// BlockWindowStore tracks active block entries per (projectID, agentID).
// All methods are safe for concurrent use.
type BlockWindowStore struct {
	mu      sync.Mutex
	entries map[string]*BlockEntry // key: entry.ID
	byAgent map[string][]string    // key: projectID+"|"+agentID → []entry IDs
	// perAgentCap overrides maxBlockEntriesPerAgent (tests only); 0 = default.
	perAgentCap int
	evicted     atomic.Uint64
}

// Evicted is how many entries were dropped because an agent hit the cap.
func (s *BlockWindowStore) Evicted() uint64 { return s.evicted.Load() }

// NewBlockWindowStore returns a ready-to-use BlockWindowStore.
func NewBlockWindowStore() *BlockWindowStore {
	return &BlockWindowStore{
		entries: make(map[string]*BlockEntry),
		byAgent: make(map[string][]string),
	}
}

// Record adds a new block entry. Duplicate keys from the same agent/path/reason
// within the same expiry window are deduplicated: an existing unexpired entry
// for the same (agentID, key, reason, path) is refreshed rather than added again.
func (s *BlockWindowStore) Record(entry BlockEntry) {
	s.mu.Lock()
	defer s.mu.Unlock()

	agentKey := entry.ProjectID + "|" + entry.AgentID
	now := time.Now()

	// Deduplicate: update expiry if an unexpired entry with the same
	// fingerprint exists. Expired entries are dropped on the way past.
	//
	// Reclaiming here matters because the only other place that frees them is
	// ListActive, which runs when a human opens the page. Every entry is
	// created by inbound traffic, so a project nobody is watching would
	// otherwise accumulate one per block for as long as the process lives, at
	// a rate an attacker sets. Pruning during the scan this loop already
	// performs bounds the store by concurrently-active blocks instead of
	// cumulative ones, and costs nothing extra.
	ids := s.byAgent[agentKey]
	fresh := ids[:0]
	var dup *BlockEntry
	for _, id := range ids {
		existing, ok := s.entries[id]
		if !ok {
			continue
		}
		if now.After(existing.ExpiresAt) {
			delete(s.entries, id)
			continue
		}
		fresh = append(fresh, id)
		if dup == nil && existing.Key == entry.Key && existing.Reason == entry.Reason && existing.Path == entry.Path {
			dup = existing
		}
	}
	if len(fresh) != len(ids) {
		s.byAgent[agentKey] = fresh
	}
	if dup != nil {
		dup.ExpiresAt = entry.ExpiresAt
		dup.BlockedAt = entry.BlockedAt
		return
	}

	if entry.ID == "" {
		entry.ID = newBlockEntryID()
	}
	if _, taken := s.entries[entry.ID]; taken {
		// Never overwrite another entry (possibly another project's).
		entry.ID = newBlockEntryID()
	}
	limit := s.perAgentCap
	if limit <= 0 {
		limit = maxBlockEntriesPerAgent
	}
	list := s.byAgent[agentKey]
	for len(list) >= limit {
		delete(s.entries, list[0])
		list = list[1:]
		s.evicted.Add(1)
	}
	s.entries[entry.ID] = &entry
	s.byAgent[agentKey] = append(list, entry.ID)
}

// ListActive returns all non-expired block entries for the given agent.
func (s *BlockWindowStore) ListActive(projectID, agentID string) []BlockEntry {
	s.mu.Lock()
	defer s.mu.Unlock()

	agentKey := projectID + "|" + agentID
	ids := s.byAgent[agentKey]
	now := time.Now()
	active := make([]BlockEntry, 0, len(ids))
	// Compact stale IDs while iterating.
	fresh := ids[:0]
	for _, id := range ids {
		e, ok := s.entries[id]
		if !ok {
			continue
		}
		// The index is keyed by project and agent, but the entry itself is
		// the authority: never return another tenant's entry.
		if e.ProjectID != projectID || e.AgentID != agentID {
			continue
		}
		if now.After(e.ExpiresAt) {
			delete(s.entries, id)
			continue
		}
		active = append(active, *e)
		fresh = append(fresh, id)
	}
	if len(fresh) != len(ids) {
		s.byAgent[agentKey] = fresh
	}
	return active
}

// Delete removes the block entry with the given ID. Returns the deleted entry
// (with unblock fields populated) so the caller can send an unblock command
// to the agent. Returns nil if the entry was not found or already expired.
func (s *BlockWindowStore) Delete(projectID, agentID, entryID string) *BlockEntry {
	s.mu.Lock()
	defer s.mu.Unlock()

	e, ok := s.entries[entryID]
	if !ok {
		return nil
	}
	if e.ProjectID != projectID || e.AgentID != agentID {
		return nil
	}
	cp := *e
	delete(s.entries, entryID)
	agentKey := projectID + "|" + agentID
	ids := s.byAgent[agentKey]
	for i, id := range ids {
		if id == entryID {
			s.byAgent[agentKey] = append(ids[:i], ids[i+1:]...)
			break
		}
	}
	return &cp
}

// Get returns a copy without changing active block evidence.
func (s *BlockWindowStore) Get(projectID, agentID, entryID string) *BlockEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.entries[entryID]
	if e == nil || e.ProjectID != projectID || e.AgentID != agentID || time.Now().After(e.ExpiresAt) {
		return nil
	}
	cp := *e
	return &cp
}

// DeleteUnchanged cannot erase a refreshed block using an older command ACK.
func (s *BlockWindowStore) DeleteUnchanged(expected BlockEntry) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	e := s.entries[expected.ID]
	if e == nil || e.ProjectID != expected.ProjectID || e.AgentID != expected.AgentID || !e.BlockedAt.Equal(expected.BlockedAt) || !e.ExpiresAt.Equal(expected.ExpiresAt) {
		return false
	}
	delete(s.entries, expected.ID)
	return true // ListActive compacts the per-agent ID index.
}
