package domain

import (
	"context"
	"time"
)

// WAFRollupStore is what the WAF rollup job reads and writes (repository.WAFRollupRepo). Every
// instant it returns comes from the database clock.
type WAFRollupStore interface {
	// TryRollupLock takes the lock that lets one control plane process fill the rollups at a time;
	// ok is false while another one holds it. release is never nil.
	TryRollupLock(ctx context.Context) (release func(), ok bool, err error)
	// RollupSettled creates the state row when it is missing (all marks at the start of the current
	// hour) and returns the instant before which no decision can still be committed.
	RollupSettled(ctx context.Context) (time.Time, error)
	// RollupFloor returns the first whole hour at or after the oldest decision retention keeps:
	// now minus keepDays, or the start of the oldest chunk (nil on a plain table) when that is later.
	RollupFloor(ctx context.Context, keepDays int, oldestChunk *time.Time) (time.Time, error)
	// FillRollupMinutes adds the minute and seen rows of at most one hour after the minute mark, up
	// to settled, and moves the mark, in one transaction.
	FillRollupMinutes(ctx context.Context, settled time.Time) error
	// FillRollupHour adds the hour rows of the hour after the hour mark when the minute mark has
	// passed it, and moves the mark, in one transaction.
	FillRollupHour(ctx context.Context) error
	// BackfillRollupHour adds the minute, seen and hour rows of the hour before covered_from and
	// moves it back, in one transaction. It reports false, and does nothing, when covered_from is
	// not above floor or not at or below settled.
	BackfillRollupHour(ctx context.Context, settled, floor time.Time) (bool, error)
	// RaiseRollupFloor raises covered_from, the minute mark and the hour mark to at least floor.
	RaiseRollupFloor(ctx context.Context, floor time.Time) error
	// DeleteExpiredRollups deletes up to limit rows from each rollup table that lie before
	// covered_from and returns the most rows any one table lost.
	DeleteExpiredRollups(ctx context.Context, limit int) (int64, error)
}
