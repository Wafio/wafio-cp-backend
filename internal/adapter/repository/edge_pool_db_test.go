package repository

import (
	"context"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/domain"
	"github.com/wafio/wafio-cp-backend/internal/testutil/dbfixture"
)

// A save of the cache holds the row of the application and then reads through the pool in its check.
// A burst of removals for the same application queues up behind that row. With a pool smaller than
// the burst, the removals must not each hold a connection while they wait: they take a place among
// the open transactions first, so the save still finds a connection and the burst finishes.
func TestDBCachePurgeBurstDoesNotStarveASaveOfThePool(t *testing.T) {
	dsn := os.Getenv("TEST_DB_URL")
	if dsn == "" {
		t.Skip("TEST_DB_URL not set")
	}
	repo, err := NewWithPool(context.Background(), dsn, PoolOptions{MaxConns: 4})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(repo.Close)
	project, user := dbfixture.SeedProject(t, repo.DB)
	f := &tlsDB{t: t, repo: repo, project: project, user: user}
	_, app := f.served()
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	if _, err := repo.Edge.UpdateDelivery(ctx, project, app, DeliveryCache, cacheOn(t, nil), nil); err != nil {
		t.Fatal(err)
	}

	const burst = CachePurgeMaxPending - 1
	inAdmit := make(chan struct{})
	release := make(chan struct{})
	saved := make(chan error, 1)
	go func() {
		_, err := repo.Edge.UpdateDelivery(ctx, project, app, DeliveryCache, cacheOn(t, func(c *domain.Cache) { c.DefaultTTLS = ptr(int64(120)) }),
			func(AppDelivery, EdgeAgent, string) error {
				close(inAdmit)
				<-release
				readCtx, stop := context.WithTimeout(ctx, 8*time.Second)
				defer stop()
				var one int
				return repo.DB.QueryRow(readCtx, `SELECT 1`).Scan(&one)
			})
		saved <- err
	}()
	select {
	case <-inAdmit:
	case <-time.After(10 * time.Second):
		t.Fatal("the save did not reach its check")
	}

	var wg sync.WaitGroup
	failures := make(chan error, burst)
	for i := 0; i < burst; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := repo.Edge.CreateCachePurge(ctx, project, app, user, "app", "")
			if err != nil {
				failures <- err
			}
		}()
	}
	// Give the burst time to reach the row lock, then let the save read.
	time.Sleep(time.Second)
	close(release)

	if err := <-saved; err != nil {
		t.Fatalf("the save found no connection while a burst of removals waited for its row: %v", err)
	}
	wg.Wait()
	close(failures)
	for err := range failures {
		t.Errorf("a removal of the burst: %v", err)
	}
	if rows, err := repo.Edge.ListCachePurges(ctx, project, app, 100); err != nil || len(rows) != burst {
		t.Errorf("%d removals queued, want %d (%v)", len(rows), burst, err)
	}
}
