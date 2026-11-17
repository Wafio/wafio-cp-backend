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
func wafWindowEnd(ctx context.Context) time.Time {
	return domain.WAFWindowEnd(ctx)
}
