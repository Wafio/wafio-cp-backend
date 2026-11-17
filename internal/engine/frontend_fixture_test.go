package engine

import (
	"encoding/json"
	"testing"

	"github.com/wafio/wafio-cp-backend/internal/testutil/jsonfixture"
)

// The dashboard's policy editor starts from these defaults; its tests read the copy of this file.
func TestFrontendDefaultsFixture(t *testing.T) {
	jsonfixture.Check(t, "../../test/frontend-fixtures/defaults.json", struct {
		DefaultRules json.RawMessage `json:"default_rules"`
	}{DefaultRulesJSON()})
}
