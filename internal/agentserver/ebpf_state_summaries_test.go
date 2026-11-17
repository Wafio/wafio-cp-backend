package agentserver

import "testing"

// The fleet view reads only the asking project's host agents.
func TestEBPFStateSummariesProjectScoped(t *testing.T) {
	s := &Server{streams: map[string]*streamHandle{
		"c1": {projectID: "p1", agentKind: "host", ebpfAgentID: "h1",
			bundleStates: map[string]HostBundleApplyStatus{"ebpf_state": {Status: "refused", Code: "SSH_ALLOW_REQUIRED"}}},
		"c2": {projectID: "p2", agentKind: "host", ebpfAgentID: "h2",
			bundleStates: map[string]HostBundleApplyStatus{"ebpf_state": {Status: "failed"}}},
		"c3": {projectID: "p1", agentKind: "waf", agentID: "w1",
			bundleStates: map[string]HostBundleApplyStatus{"waf": {Status: "failed"}}},
		"c4": {projectID: "p1", agentKind: "host", ebpfAgentID: "h4"},
	}}
	got := s.EBPFStateSummaries("p1")
	if len(got) != 1 || got["h1"].Status != "refused" || got["h1"].Code != "SSH_ALLOW_REQUIRED" {
		t.Fatalf("p1 summaries = %+v", got)
	}
	if got := s.EBPFStateSummaries("p3"); len(got) != 0 {
		t.Fatalf("unknown project = %+v", got)
	}
	var nilServer *Server
	if got := nilServer.EBPFStateSummaries("p1"); len(got) != 0 {
		t.Fatalf("nil server = %+v", got)
	}
}
