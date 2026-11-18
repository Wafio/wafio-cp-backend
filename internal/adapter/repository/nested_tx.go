package repository

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// nestedTx bounds the transactions that read through the pool while they hold one of its
// connections: UpdateMaintenance and ReplaceAssignment run a function of the caller inside the
// transaction, and that function queries the pool. Saves of one application wait for each other
// on its row lock with a connection in hand, so without a bound a burst of them could hold the
// whole pool and leave the one that holds the lock without a connection to read through. With two
// open at a time the pool needs four connections.
var nestedTx = make(chan struct{}, 2)

// enterNestedTx waits for a place among the open transactions of that kind. leave gives it back.
func enterNestedTx(ctx context.Context) (leave func(), err error) {
	select {
	case nestedTx <- struct{}{}:
		return func() { <-nestedTx }, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

// lockAgentBundle holds the bundle of a WAF agent until the transaction ends. A change that is
// measured against the bundle size limit takes it before the caller measures through the pool, so
// two changes for one agent (two applications, or a save and a move) are measured one after the
// other and cannot each fit alone and pass the limit together. It is taken after the row of the
// application, and a transaction takes at most one, so the order of the locks is always the same.
func lockAgentBundle(ctx context.Context, tx pgx.Tx, agentID string) error {
	_, err := tx.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "waf-agent-bundle:"+agentID)
	return err
}
