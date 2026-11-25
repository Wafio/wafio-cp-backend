package application

import (
	"testing"

	"github.com/wafio/wafio-cp-backend/internal/testutil/jsonfixture"
	"github.com/wafio/wafio-cp-backend/shared/hostpolicy"
)

// The WAF agent's static file walk refuses a name the kernel keeps in the trace
// ring, so a file with such a name is never opened. It holds a copy of this
// table, and its tests compare that copy with this file. Rewrite it with
//
//	WAFIO_UPDATE_FRONTEND_FIXTURES=1 go test ./internal/application -run TestTraceKeepNamesFixture
func TestTraceKeepNamesFixture(t *testing.T) {
	jsonfixture.Check(t, "../../test/frontend-fixtures/trace-keep-names.json", hostpolicy.TraceKeepBuiltin)
}
