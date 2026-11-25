package application

import (
	"context"
	"log/slog"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/domain"
)

// The WAF rollup job fills three tables from waf_decisions: counters per minute, the last time each
// client address was seen, and the largest values of each hour. A pass runs every minute under an
// advisory lock: minute rows of at most one hour, hour rows of at most one hour, then older hours
// newest first until rollupBackfillBudget is used, down to what retention keeps. Each unit is one
// transaction that moves its mark with its rows, so a failed unit leaves its range unfilled and is
// tried again.

const (
	rollupInterval       = time.Minute
	rollupBackfillBudget = 20 * time.Second
)

// WAFRollup is the rollup job. Both fields are required.
type WAFRollup struct {
	Store domain.WAFRollupStore
	// Keep says how long the decisions are kept and, on a hypertable, when its oldest chunk starts
	// (Storage.WAFKeep).
	Keep func(ctx context.Context) (days int, oldestChunk *time.Time, err error)
}

// Run passes until ctx ends, the first one a minute after the start.
func (j *WAFRollup) Run(ctx context.Context) {
	tick := time.NewTicker(rollupInterval)
	defer tick.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-tick.C:
			j.Pass(ctx)
		}
	}
}

// Pass is one pass. It does nothing while another process holds the lock.
func (j *WAFRollup) Pass(ctx context.Context) {
	started := time.Now()
	release, ok, err := j.Store.TryRollupLock(ctx)
	if err != nil {
		slog.Warn("waf rollup: pass skipped", "err", err)
		return
	}
	if !ok {
		return
	}
	defer release()

	settled, err := j.Store.RollupSettled(ctx)
	if err != nil {
		slog.Warn("waf rollup: pass skipped", "err", err)
		return
	}
	if err := j.Store.FillRollupMinutes(ctx, settled); err != nil {
		slog.Warn("waf rollup: minute fill failed", "err", err)
	}
	if err := j.Store.FillRollupHour(ctx); err != nil {
		slog.Warn("waf rollup: hour fill failed", "err", err)
	}

	// Without a readable retention there is no floor to fill down to.
	floor, err := j.floor(ctx)
	if err != nil {
		slog.Warn("waf rollup: backfill skipped", "err", err)
		return
	}
	for time.Since(started) < rollupBackfillBudget && ctx.Err() == nil {
		more, err := j.Store.BackfillRollupHour(ctx, settled, floor)
		if err != nil {
			slog.Warn("waf rollup: backfill failed", "err", err)
			return
		}
		if !more {
			return
		}
	}
}

func (j *WAFRollup) floor(ctx context.Context) (time.Time, error) {
	days, oldest, err := j.Keep(ctx)
	if err != nil {
		return time.Time{}, err
	}
	return j.Store.RollupFloor(ctx, days, oldest)
}

// Cleanup is the part of the retention pass that trims the rollups: rows older than the oldest
// decision retention keeps leave, and the rollups stop claiming to cover that range. Raw rows
// between the cutoff and the next whole hour stay, and a reader counts them from the decisions. A
// reader leaves out the decisions below the cutoff, which a chunk not yet dropped can still hold.
// It deletes until a batch is short, with no cap per pass: TimescaleDB drops the raw chunks at
// once, and the addresses, URIs and user agents in the rollups must leave with them. Each batch is
// its own short transaction.
func (j *WAFRollup) Cleanup(ctx context.Context, keepDays int, oldestChunk *time.Time) error {
	floor, err := j.Store.RollupFloor(ctx, keepDays, oldestChunk)
	if err != nil {
		return err
	}
	if err := j.Store.RaiseRollupFloor(ctx, floor); err != nil {
		return err
	}
	for {
		n, err := j.Store.DeleteExpiredRollups(ctx, deleteBatch)
		if err != nil {
			return err
		}
		if n < deleteBatch {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(deleteBatchPause):
		}
	}
}
