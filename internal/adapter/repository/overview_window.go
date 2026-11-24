package repository

import (
	"context"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/domain"
)

// WithWAFWindowEnd fixes the WAF time-window boundaries across widget queries.
// It does not turn their independent SQL statements into one MVCC snapshot.
// The context key lives in domain so the application layer can set it.
func WithWAFWindowEnd(ctx context.Context, end time.Time) context.Context {
	return domain.WithWAFWindowEnd(ctx, end)
}

// windowEnd is the end the context carries, or the database clock. A window that ends behind the rollup
// marks counts its distinct addresses from the decisions, which a slow control plane clock would cause.
func (r *WAFRepo) windowEnd(ctx context.Context) (time.Time, error) {
	if end, ok := domain.WAFWindowEnd(ctx); ok {
		return end, nil
	}
	return r.DBNow(ctx)
}
