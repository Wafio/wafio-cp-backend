package main

import (
	"context"
	"log"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/application"
)

// correlationLoadTimeout bounds the startup load of stored correlation rules.
const correlationLoadTimeout = 30 * time.Second

// loadCorrelationRules installs every project's stored correlation rules into
// the process-wide registry. A failure is logged and every project keeps the
// built-in chains until its next rule edit (the pre-load behaviour).
func loadCorrelationRules(ctx context.Context, src application.CorrelationRuleSource) {
	loadCorrelationRulesInto(ctx, application.Correlations(), src)
}

func loadCorrelationRulesInto(ctx context.Context, reg *application.CorrelationRegistry, src application.CorrelationRuleSource) {
	loadCtx, cancel := context.WithTimeout(ctx, correlationLoadTimeout)
	defer cancel()
	n, err := reg.LoadAll(loadCtx, src)
	if err != nil {
		log.Printf("[startup] correlation rules not loaded, built-in chains apply until a rule edit: %v", err) //nolint:gosec // G706: repository error, no request data
		return
	}
	log.Printf("[startup] loaded stored correlation rules for %d project(s)", n)
}
