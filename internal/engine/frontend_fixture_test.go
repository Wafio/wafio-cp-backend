package engine

import (
	"encoding/json"
	"testing"

	"github.com/wafio/wafio-cp-backend/internal/domain"
	"github.com/wafio/wafio-cp-backend/internal/testutil/jsonfixture"
)

// The dashboard's policy editor starts from these defaults; its tests read the copy of this file.
func TestFrontendDefaultsFixture(t *testing.T) {
	jsonfixture.Check(t, "../../test/frontend-fixtures/defaults.json", struct {
		DefaultRules json.RawMessage `json:"default_rules"`
	}{DefaultRulesJSON()})
}

// The dashboard's maintenance tab checks its form against these limits and previews the standard page.
func TestFrontendMaintenanceFixture(t *testing.T) {
	type limits struct {
		MessageChars   int `json:"message_chars"`
		CustomHTMLSize int `json:"custom_html_bytes"`
		AllowIPs       int `json:"allow_ips"`
		AllowPaths     int `json:"allow_paths"`
		PathBytes      int `json:"path_bytes"`
		EndTimeMaxDays int `json:"end_time_max_days"`
		// AgentBundleBytes is the largest bundle an agent accepts; the custom pages of all applications
		// of one agent count toward it.
		AgentBundleBytes int `json:"agent_bundle_bytes"`
	}
	jsonfixture.Check(t, "../../test/frontend-fixtures/maintenance.json", struct {
		DefaultMessage string `json:"default_message"`
		StockHTML      string `json:"stock_html"`
		Limits         limits `json:"limits"`
	}{DefaultMaintenanceMessage, StockMaintenanceHTML, limits{
		domain.MaintenanceMessageChars, domain.MaintenanceCustomHTMLSize, domain.MaintenanceMaxIPs,
		domain.MaintenanceMaxPaths, domain.MaintenancePathBytes, domain.MaintenanceEndMaxDays, MaxAgentBundleBytes,
	}})
}
