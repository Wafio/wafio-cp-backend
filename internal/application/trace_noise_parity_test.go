package application

import (
	"encoding/json"
	"testing"

	"github.com/wafio/wafio-cp-backend/internal/domain"
	"github.com/wafio/wafio-cp-backend/shared/hostpolicy"
	"github.com/wafio/wafio-cp-backend/shared/tracefilter"
)

// The host agent's send queue drops noise, then watched
// events, before significant ones. Significant must be exactly what ingest
// always stores (storeTraceEvent), read through the wire format the agent
// sends; noise and watched are what ingest stores only after a raise.
func TestAgentNoiseClassMatchesIngestStoreFilter(t *testing.T) {
	categories := []string{"", "file", "network", "file,network", "process", "security", "file,security", "process,file", "x"}
	actions := []uint32{hostpolicy.ActionMonitor, hostpolicy.ActionAlert, hostpolicy.ActionKill, hostpolicy.ActionSimulate, hostpolicy.ActionBlock}
	for _, cat := range categories {
		for sev := uint32(0); sev <= 4; sev++ {
			for _, action := range actions {
				for _, outcome := range []bool{false, true} {
					evt := hostpolicy.TraceEvent{Category: cat, Severity: sev, Action: action, OutcomeUpdate: outcome, EventName: "openat"}
					raw, err := json.Marshal(evt)
					if err != nil {
						t.Fatal(err)
					}
					var p TraceEventPayload
					if err := json.Unmarshal(raw, &p); err != nil {
						t.Fatal(err)
					}
					noise := hostpolicy.ClassifyTraceEvent(&evt) != hostpolicy.TraceClassSignificant
					always := storeTraceEvent(&p, p.Severity)
					// An outcome update is never classified at ingest (it
					// updates an event already stored); the agent keeps it.
					if outcome {
						if noise {
							t.Errorf("%q sev %d action %d: outcome update classified as noise", cat, sev, action)
						}
						continue
					}
					if noise == always {
						t.Errorf("%q sev %d action %d: agent noise=%v, ingest always stores=%v", cat, sev, action, noise, always)
					}
				}
			}
		}
	}
}

// The agent's loss and shed report names are the ones storage keeps
// unsampled (domain.IsTraceAgentReport) and ingest maps to T1562.006.
func TestAgentReportNamesMatchControlPlane(t *testing.T) {
	for _, name := range hostpolicy.TraceAgentReportNames() {
		if !domain.IsTraceAgentReport(name) {
			t.Errorf("%s: not a domain agent report, storage would sample it", name)
		}
		if technique, _ := mitreForEvent(name); technique != "T1562.006" {
			t.Errorf("%s: technique %q, want T1562.006", name, technique)
		}
	}
}

// Ingest lowers reads of the public identity files to INFO and drops
// them, so the kernel must not exempt those reads from shedding (a read loop
// of /etc/passwd by any user would fill the ring and lose execs); their
// writes, and reads of credential files, stay exempt.
func TestPublicIdentityReadsAreNotShedExempt(t *testing.T) {
	for _, path := range []string{"/etc/passwd", "/etc/group", "/etc/nsswitch.conf", "/etc/login.defs", "/root/.ssh/authorized_keys", "/home/u/.ssh/authorized_keys"} {
		p := TraceEventPayload{EventName: "openat", Filename: path}
		if !tracefilter.IsPublicIdentityRead(&p) {
			t.Fatalf("%s: no longer a public identity read at ingest; revisit traceKeepBuiltin", path)
		}
		if hostpolicy.KeepsBuiltinRead(path) {
			t.Errorf("%s: a read is shed-exempt although ingest drops it", path)
		}
	}
	for _, path := range []string{"/etc/shadow", "/etc/sudoers", "/etc/pam.d/common-auth", "/etc/security/limits.conf", "/root/.ssh/id_ed25519"} {
		if !hostpolicy.KeepsBuiltinRead(path) {
			t.Errorf("%s: a read must stay shed-exempt", path)
		}
	}
}
