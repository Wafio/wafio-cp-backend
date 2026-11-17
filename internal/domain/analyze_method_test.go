package domain

import (
	"slices"
	"testing"
)

// An older agent's rule_based and hybrid (and the SIEM spelling rule-based)
// read as semantic; every other method is left alone.
func TestCanonicalAnalyzeMethod(t *testing.T) {
	for in, want := range map[string]string{
		"rule_based": "semantic", "rule-based": "semantic", "hybrid": "semantic", "semantic": "semantic",
		"policy": "policy", "geo": "geo", "bot": "bot", "body_limit": "body_limit", "custom_rule": "custom_rule",
		"content_scan": "content_scan", "error": "error", "": "", "Rule_Based": "Rule_Based",
	} {
		if got := CanonicalAnalyzeMethod(in); got != want {
			t.Errorf("CanonicalAnalyzeMethod(%q) = %q, want %q", in, got, want)
		}
	}
}

// The coverage text of a decision splits into gap flags and engine marks, for
// the rows of an agent that wrote the marks among the gap flags too.
func TestSplitCoverage(t *testing.T) {
	for _, tc := range []struct {
		in, gaps string
		off      []string
		logOnly  []string
	}{
		{"", "", []string{}, []string{}},
		{"field_cap,body_binary", "field_cap,body_binary", []string{}, []string{}},
		{"engine_disabled:xss", "", []string{"xss"}, []string{}},
		{"truncated,engine_disabled:xss,header_len,engine_disabled:jwt", "truncated,header_len", []string{"xss", "jwt"}, []string{}},
		{"engine_disabled:xss,engine_disabled:xss", "", []string{"xss"}, []string{}},
		{"engine_weakened:sql,engine_disabled:sql", "engine_weakened:sql", []string{"sql"}, []string{}},
		{" field_cap , engine_disabled:cmd ,", "field_cap", []string{"cmd"}, []string{}},
		{"engine_disabled:", "", []string{}, []string{}},
		{"engine_log_only:sql", "", []string{}, []string{"sql"}},
		{"field_cap,engine_disabled:xss,engine_log_only:sql,engine_log_only:sql,engine_log_only:jwt", "field_cap", []string{"xss"}, []string{"sql", "jwt"}},
		{"engine_log_only:", "", []string{}, []string{}},
	} {
		gaps, off, logOnly := SplitCoverage(tc.in)
		if gaps != tc.gaps || !slices.Equal(off, tc.off) || off == nil || !slices.Equal(logOnly, tc.logOnly) || logOnly == nil {
			t.Errorf("SplitCoverage(%q) = %q %v %v, want %q %v %v", tc.in, gaps, off, logOnly, tc.gaps, tc.off, tc.logOnly)
		}
	}
}

// The strength of a decision follows its action, its categories and the engines that held a block back.
func TestDecisionStrength(t *testing.T) {
	cats := []string{"SQLi"}
	for _, tc := range []struct {
		name, action string
		categories   []string
		logOnly      []string
		want         string // "" = null
	}{
		{"block", "block", cats, nil, "block"},
		{"block without a category", "block", nil, nil, "block"},
		{"monitor", "monitor", cats, nil, "block"},
		{"log that held a block back", "log", cats, []string{"sql"}, "block"},
		{"allow that names a held engine", "allow", nil, []string{"sql"}, "block"},
		{"log with a category", "log", cats, nil, "weak"},
		{"log without a category", "log", nil, nil, ""},
		{"log with an empty category list", "log", []string{}, []string{}, ""},
		{"allow", "allow", nil, nil, ""},
		{"allow with a category", "allow", cats, nil, ""},
		{"challenge", "challenge", nil, nil, ""},
		{"upstream_error", "upstream_error", nil, nil, ""},
		{"unknown action", "", nil, nil, ""},
	} {
		got := DecisionStrength(tc.action, tc.categories, tc.logOnly)
		switch {
		case tc.want == "" && got != nil:
			t.Errorf("%s: strength %q, want null", tc.name, *got)
		case tc.want != "" && (got == nil || *got != tc.want):
			t.Errorf("%s: strength %v, want %q", tc.name, got, tc.want)
		}
	}
}
