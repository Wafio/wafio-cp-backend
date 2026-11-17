package repository

import (
	"context"
	"log"
	"time"
)

// KeySweeperInterval is how often the background sweeper runs. Short enough
// that grace windows expire within a bounded lag (here: ≤ 1 min past the
// configured grace period) without hammering the database.
const KeySweeperInterval = 30 * time.Second

// KeySweeperDeps is the minimal surface the key/heartbeat sweeper needs from
// the repository layer. Using an interface keeps `serve.go` decoupled from
// the concrete struct wiring and makes the sweeper trivially testable.
type KeySweeperDeps interface {
	PurgeExpiredPrevKeys(ctx context.Context) (int64, error)
	MarkOfflineStale(ctx context.Context) (int64, error)
}

// RunKeySweeper blocks until ctx is cancelled, running two idempotent
// maintenance jobs on each tick:
//
//  1. Clear expired previous Host Keys (rotation grace-period sweep).
//  2. Flip hosts whose last heartbeat is older than HostOfflineThreshold
//     from 'online' to 'offline' so operators see a truthful dashboard.
//
// Errors are logged but not fatal: a transient DB hiccup must not bring the
// control plane down. Callers typically spawn this in a goroutine from
// cmd/wafio/serve.go after repo/config wiring is complete.
func RunKeySweeper(ctx context.Context, deps KeySweeperDeps) {
	if deps == nil {
		return
	}
	t := time.NewTicker(KeySweeperInterval)
	defer t.Stop()
	runOnce := func() {
		sweepCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		if n, err := deps.PurgeExpiredPrevKeys(sweepCtx); err != nil {
			log.Printf("host_key_sweeper: purge_prev_host_keys failed: %v", err)
		} else if n > 0 {
			log.Printf("host_key_sweeper: cleared %d expired previous host keys", n)
		}
		if n, err := deps.MarkOfflineStale(sweepCtx); err != nil {
			log.Printf("host_key_sweeper: mark_offline failed: %v", err)
		} else if n > 0 {
			log.Printf("host_key_sweeper: marked %d hosts offline (no heartbeat > %s)", n, HostOfflineThreshold)
		}
	}
	runOnce()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			runOnce()
		}
	}
}
