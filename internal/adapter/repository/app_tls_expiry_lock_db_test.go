package repository

import (
	"context"
	"testing"
)

// One replica at a time mails the expiry warnings, and the lock is not the one of the retention pass:
// neither job waits for the other.
func TestDBTLSExpiryLock(t *testing.T) {
	f := newTLSDB(t)
	ctx := context.Background()
	release, ok, err := f.repo.TLS.TryExpiryLock(ctx)
	if err != nil || !ok {
		t.Fatalf("lock: %v %v", ok, err)
	}
	if _, again, err := f.repo.TLS.TryExpiryLock(ctx); err != nil || again {
		t.Fatalf("second lock taken: %v %v", again, err)
	}
	retention, ok, err := f.repo.Storage.TryRetentionLock(ctx)
	if err != nil || !ok {
		t.Fatalf("the retention lock was not free while the expiry lock was held: %v %v", ok, err)
	}
	retention()
	release()
	release, ok, err = f.repo.TLS.TryExpiryLock(ctx)
	if err != nil || !ok {
		t.Fatalf("lock after release: %v %v", ok, err)
	}
	release()
}
