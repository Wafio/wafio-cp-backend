package repository

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
)

// nestedTx bounds the transactions that wait for the lock of an application or of the bundle of its
// agent with a pool connection in hand. Some of them (UpdateMaintenance, UpdateAtomic with a check,
// ReplaceAssignment) run a function of the caller inside the transaction, and that function queries
// the pool. Saves of one application wait for each other on its row lock, so without a bound a
// burst of them could hold the whole pool and leave the one that holds the lock without a connection
// to read through. Every transaction that takes one of those locks takes a place here first (the
// TLS changes, a move, an assignment, a config save, a delivery save, a cache removal). With two open
// at a time the pool needs four connections.
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

// enabledAssignment reads the agent and the mode of the enabled assignment of an application, both
// "" when it has none. A caller that holds the application row (SELECT ... FOR UPDATE) calls it in a
// statement after the locking one, never inside it: a statement that waits for the row lock still
// sees the assignments its snapshot had when it started, so a move that committed while it waited
// would not show, and the caller would lock the bundle of the agent that the application has left.
// A move holds the same row, so once the caller has it the assignment cannot change under it.
func enabledAssignment(ctx context.Context, tx pgx.Tx, appID string) (agentID, mode string, err error) {
	err = tx.QueryRow(ctx, `SELECT agent_id::text, mode FROM waf_agent_apps WHERE app_id = $1 AND enabled = TRUE LIMIT 1`, appID).Scan(&agentID, &mode)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", nil
	}
	return agentID, mode, err
}
