package repository

import "context"

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
