package main

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/application"
)

type fakeCorrelationSource struct {
	rules map[string][]*application.CorrelationRule
	err   error
}

func (f fakeCorrelationSource) EnabledCorrelationRulesByProject(context.Context) (map[string][]*application.CorrelationRule, error) {
	return f.rules, f.err
}

// The boot load must install a project's stored set (here: every chain
// disabled), so the built-in webshell chain no longer fires for it.
func TestLoadCorrelationRulesAtBoot(t *testing.T) {
	reg := application.Correlations()
	const project = "boot-load-test-project"
	t.Cleanup(func() { reg.Reset(project) })

	loadCorrelationRulesInto(context.Background(), reg, fakeCorrelationSource{
		rules: map[string][]*application.CorrelationRule{project: {}},
	})
	base := time.Now()
	_ = reg.Evaluate(project, application.CorrelationEvent{EventName: "openat", Filename: "/tmp/x", PID: 1, ProcessStartNS: 1, Timestamp: base})
	_ = reg.Evaluate(project, application.CorrelationEvent{EventName: "chmod", PID: 1, ProcessStartNS: 1, Timestamp: base.Add(time.Second)})
	if got := reg.Evaluate(project, application.CorrelationEvent{EventName: "execve", ParentComm: "php-fpm", PID: 1, ProcessStartNS: 1, Timestamp: base.Add(2 * time.Second)}); len(got) != 0 {
		t.Fatalf("built-in chain fired for a project whose stored rules are all disabled: %v", got)
	}

	// A failing source leaves the registry untouched (no panic).
	loadCorrelationRulesInto(context.Background(), reg, fakeCorrelationSource{err: errors.New("db down")})
}
