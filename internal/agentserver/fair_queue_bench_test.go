package agentserver

import (
	"testing"

	"github.com/wafio/wafio-cp-backend/internal/adapter/repository"
)

// BenchmarkDecisionEnqueue is the WAF decision ingest hot path (Enqueue on
// the agent receive loop) plus the writer's pop, against the old shared
// channel.
func BenchmarkDecisionEnqueue(b *testing.B) {
	projects := []string{"p1", "p2", "p3", "p4"}
	b.Run("fair_queue", func(b *testing.B) {
		q := newFairQueue[repository.WAFDecision](defaultDecisionQueue)
		row := repository.WAFDecision{}
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			row.ProjectID = projects[i&3]
			q.push(row.ProjectID, row)
			q.pop()
		}
	})
	b.Run("fair_queue_full", func(b *testing.B) {
		q := newFairQueue[repository.WAFDecision](defaultDecisionQueue)
		row := repository.WAFDecision{}
		for i := 0; i < defaultDecisionQueue; i++ {
			row.ProjectID = projects[i&3]
			q.push(row.ProjectID, row)
		}
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			row.ProjectID = projects[i&3]
			q.push(row.ProjectID, row) // longest-queue drop on every push
		}
	})
	b.Run("channel", func(b *testing.B) {
		ch := make(chan repository.WAFDecision, defaultDecisionQueue)
		row := repository.WAFDecision{}
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			row.ProjectID = projects[i&3]
			ch <- row
			<-ch
		}
	})
}
