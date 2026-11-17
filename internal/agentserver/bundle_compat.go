package agentserver

import (
	"log"

	"github.com/wafio/wafio-cp-backend/internal/engine"
)

// bundleForAgent returns the bundle sent on this connection: the stored one, with the legacy keys of v1
// documents rewritten by engine.NormalizeBundle. Every agent gets the same bundle; the rewrite is never
// stored.
func (h *streamHandle) bundleForAgent(bundle []byte) []byte {
	out, legacy := engine.NormalizeBundle(bundle)
	h.noteChanges(legacy)
	return out
}

// noteChanges logs the legacy rewrites a bundle sent on this connection had:
// once per connection, scope and rewrite.
func (h *streamHandle) noteChanges(legacy []string) {
	for _, line := range legacy {
		if _, seen := h.legacyLogged.LoadOrStore(line, struct{}{}); !seen {
			log.Printf("[agentserver] agent=%q: %s", h.agentName, line)
		}
	}
}
