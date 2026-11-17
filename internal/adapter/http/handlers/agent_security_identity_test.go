package handlers

import (
	"github.com/wafio/wafio-cp-backend/internal/agentserver"
	"testing"
)

func TestAgentSecurityDataUsesTenantIdentityNotName(t *testing.T) {
	reports := []agentserver.AgentComponentReport{
		{AgentName: "same-name", AgentID: "other-agent", ProjectID: "other-project", CredentialID: "other-secret"},
		{AgentName: "same-name", AgentID: "target-agent", ProjectID: "target-project", CredentialID: "target-credential"},
	}
	report, ok := findAgentComponentReport(reports, "target-project", "target-agent")
	if !ok || report.CredentialID != "target-credential" {
		t.Fatal("selected report by name instead of identity")
	}
	if _, ok := findAgentComponentReport(reports, "other-project", "target-agent"); ok {
		t.Fatal("cross-project report exposed")
	}
	if _, ok := findAgentComponentReport(reports, "target-project", "missing-agent"); ok {
		t.Fatal("unmatched agent reported online")
	}
}
