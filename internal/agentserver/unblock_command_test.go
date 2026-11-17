package agentserver

import (
	"errors"
	agentv1 "github.com/wafio/wafio-cp-backend/shared/agentpb"
	"strconv"
	"testing"
	"time"
)

func unblockFixture() (*Server, *streamHandle) {
	s := &Server{BlockWindow: NewBlockWindowStore(), streams: map[string]*streamHandle{}}
	s.BlockWindow.Record(BlockEntry{ID: "entry", ProjectID: "p", AgentID: "a", Key: "ip", UnblockType: "blockpolicy", UnblockKey: "ip", BlockedAt: time.Now(), ExpiresAt: time.Now().Add(time.Minute)})
	h := &streamHandle{projectID: "p", agentID: "a", agentKind: "waf", send: func(*agentv1.ServerMessage) error { return nil }}
	return s, h
}
func TestUnblockOfflineAndSendFailureRetainEntry(t *testing.T) {
	s, h := unblockFixture()
	if _, err := s.RequestUnblock("p", "a", "entry"); !errors.Is(err, ErrUnblockOffline) {
		t.Fatal(err)
	}
	s.streams["h"] = h
	h.send = func(*agentv1.ServerMessage) error { return errors.New("send failed") }
	op, err := s.RequestUnblock("p", "a", "entry")
	if err != nil {
		t.Fatal(err)
	}
	for deadline := time.Now().Add(time.Second); time.Now().Before(deadline); {
		if s.UnblockStatus("p", "a", "entry").Status == "failed" {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if s.UnblockStatus("p", "a", "entry").Status != "failed" || op.CommandID == "" || len(s.BlockWindow.ListActive("p", "a")) != 1 {
		t.Fatal("send failure lost entry")
	}
}
func TestUnblockAllStreamsAckTenantAndStaleSafety(t *testing.T) {
	s, h := unblockFixture()
	s.streams["h"] = h
	h2 := &streamHandle{projectID: "p", agentID: "a", agentKind: "waf", send: h.send}
	s.streams["h2"] = h2
	op, err := s.RequestUnblock("p", "a", "entry")
	if err != nil {
		t.Fatal(err)
	}
	ack := &agentv1.CommandAck{CommandId: op.CommandID, Ok: true}
	s.recordUnblockAck(&streamHandle{projectID: "other", agentID: "a"}, ack)
	s.recordUnblockAck(h, ack)
	if len(s.BlockWindow.ListActive("p", "a")) != 1 {
		t.Fatal("removed before every stream ACK")
	}
	s.recordUnblockAck(h2, ack)
	if len(s.BlockWindow.ListActive("p", "a")) != 0 {
		t.Fatal("positive ACK did not remove")
	}
	if s.UnblockStatus("other", "a", "entry") != nil {
		t.Fatal("cross tenant operation leaked")
	}
	s, h = unblockFixture()
	s.streams["h"] = h
	op, _ = s.RequestUnblock("p", "a", "entry")
	s.BlockWindow.Record(BlockEntry{ID: "new", ProjectID: "p", AgentID: "a", Key: "ip", BlockedAt: time.Now().Add(time.Second), ExpiresAt: time.Now().Add(2 * time.Minute)})
	s.recordUnblockAck(h, &agentv1.CommandAck{CommandId: op.CommandID, Ok: true})
	if len(s.BlockWindow.ListActive("p", "a")) != 1 || s.UnblockStatus("p", "a", "entry").Status != "superseded" {
		t.Fatal("stale ACK removed refreshed entry")
	}
}
func TestUnblockNegativeAckAndTimeoutRetainEntry(t *testing.T) {
	for _, timeout := range []bool{false, true} {
		s, h := unblockFixture()
		s.streams["h"] = h
		op, _ := s.RequestUnblock("p", "a", "entry")
		if timeout {
			s.expireUnblock(op.CommandID)
		} else {
			s.recordUnblockAck(h, &agentv1.CommandAck{CommandId: op.CommandID, Ok: false, Error: "rejected"})
		}
		s.recordUnblockAck(h, &agentv1.CommandAck{CommandId: op.CommandID, Ok: true})
		if len(s.BlockWindow.ListActive("p", "a")) != 1 {
			t.Fatal("failed/timed out command removed entry")
		}
	}
}

// One project filling the process-wide unblock table used to make
// every other project's unblock answer ErrUnblockBusy (503) for five
// minutes. Now the largest holder gives up an operation: project B always
// gets its unblock, and project A, once it is the largest, is refused for
// its own extra requests rather than displacing anyone.
func TestUnblockFloodStaysInFloodingProject(t *testing.T) {
	s := &Server{BlockWindow: NewBlockWindowStore(), streams: map[string]*streamHandle{}, unblockCapacity: 16}
	send := func(*agentv1.ServerMessage) error { return nil }
	s.streams["A"] = &streamHandle{projectID: "A", agentID: "a", agentKind: "waf", send: send}
	s.streams["B"] = &streamHandle{projectID: "B", agentID: "b", agentKind: "waf", send: send}
	record := func(project, agent, id string) {
		s.BlockWindow.Record(BlockEntry{ID: id, ProjectID: project, AgentID: agent, Key: id, UnblockType: "blockpolicy", UnblockKey: id, BlockedAt: time.Now(), ExpiresAt: time.Now().Add(time.Hour)})
	}
	var aOK, aBusy int
	for i := range 40 {
		id := "a-" + strconv.Itoa(i)
		record("A", "a", id)
		switch _, err := s.RequestUnblock("A", "a", id); {
		case err == nil:
			aOK++
		case errors.Is(err, ErrUnblockBusy):
			aBusy++
		default:
			t.Fatal(err)
		}
	}
	if aOK != 16 || aBusy != 24 {
		t.Fatalf("A: %d accepted, %d busy; want 16 / 24 (pending operations of the largest project are never displaced by its own requests)", aOK, aBusy)
	}
	for i := range 4 {
		id := "b-" + strconv.Itoa(i)
		record("B", "b", id)
		if _, err := s.RequestUnblock("B", "b", id); err != nil {
			t.Fatalf("project B refused after A filled the table: %v", err)
		}
	}
	s.unblockMu.Lock()
	a, b, total := s.unblockLedger.Count("A"), s.unblockLedger.Count("B"), len(s.unblocks)
	s.unblockMu.Unlock()
	if a != 12 || b != 4 || total != 16 {
		t.Fatalf("A %d B %d total %d, want 12 / 4 / 16", a, b, total)
	}
}
