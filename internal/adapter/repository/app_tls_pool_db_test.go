package repository

import (
	"context"
	"fmt"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/domain"
	"github.com/wafio/wafio-cp-backend/internal/testutil/dbfixture"
)

// Many writers to one agent each wait for the lock of the bundle with a connection in hand. With
// more of them than the pool has connections they must still all finish: the ones that wait for a
// lock take a place among the open transactions first, so the writer that holds the lock, and the
// check of a save that reads through the pool, always find a connection.
func TestDBWritersToOneAgentFinishWithAPoolSmallerThanThem(t *testing.T) {
	dsn := os.Getenv("TEST_DB_URL")
	if dsn == "" {
		t.Skip("TEST_DB_URL not set")
	}
	const conns = 4
	repo, err := NewWithPool(context.Background(), dsn, PoolOptions{MaxConns: conns})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(repo.Close)
	project, user := dbfixture.SeedProject(t, repo.DB)
	f := &tlsDB{t: t, repo: repo, project: project, user: user}

	agent := f.agent(nil)
	const perKind = 6
	type app struct{ id, host string }
	port := 21000
	newApps := func(kind string, assigned bool) []app {
		out := make([]app, perKind)
		for i := range out {
			port++
			out[i] = app{id: f.app(kind, "0.0.0.0", port), host: fmt.Sprintf("%s%d.example.com", kind, i)}
			if assigned {
				f.assign(agent, out[i].id)
			}
		}
		return out
	}
	saves, edits, uploads, requests, deletes, lates := newApps("save", true), newApps("edit", true), newApps("upload", true), newApps("acme", true), newApps("delete", true), newApps("late", false)
	for _, a := range requests {
		f.mustUpdate(a.id, f.settings("proxy", "", a.host))
	}

	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	defer cancel()
	start := make(chan struct{})
	var wg sync.WaitGroup
	failures := make(chan error, 5*perKind)
	run := func(what string, i int, fn func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if err := fn(); err != nil {
				failures <- fmt.Errorf("%s %d: %w", what, i, err)
			}
		}()
	}
	for i := 0; i < perKind; i++ {
		i := i
		run("UpdateTLS", i, func() error {
			s := domain.TLSSettings{Mode: domain.TLSModeGateway, Source: domain.TLSSourceACME, Hosts: []string{saves[i].host}}
			if err := s.Normalize(); err != nil {
				return err
			}
			_, err := repo.TLS.UpdateTLS(ctx, project, saves[i].id, s, time.Now())
			return err
		})
		// The check of this save reads through the pool while it holds the row and the bundle.
		run("UpdateAtomic", i, func() error {
			return repo.App.UpdateAtomic(ctx, project, edits[i].id, AppPatch{ListenPort: ptr(22000 + i)}, func(domain.Maintenance, string, string) error {
				var one int
				return repo.DB.QueryRow(ctx, `SELECT 1`).Scan(&one)
			})
		})
		run("InsertCertificate", i, func() error {
			c := newCert(uploads[i].host)
			_, err := repo.TLS.InsertCertificate(ctx, project, uploads[i].id, c, testEncryptor)
			return err
		})
		run("RequestACME", i, func() error {
			_, err := repo.TLS.RequestACME(ctx, project, requests[i].id, time.Now())
			return err
		})
		run("DeleteCertificate", i, func() error {
			_, err := repo.TLS.DeleteCertificate(ctx, project, deletes[i].id)
			return err
		})
		run("AssignApp", i, func() error { return repo.WAF.AssignApp(ctx, agent, lates[i].id, "block") })
	}
	close(start)
	finished := make(chan struct{})
	go func() {
		wg.Wait()
		close(finished)
	}()
	select {
	case <-finished:
	case <-time.After(50 * time.Second):
		t.Fatal("the writers did not finish in 50 seconds: they starved the pool")
	}
	close(failures)
	for err := range failures {
		t.Error(err)
	}
}
