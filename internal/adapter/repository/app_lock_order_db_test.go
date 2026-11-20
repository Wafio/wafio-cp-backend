package repository

import (
	"context"
	"testing"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/domain"
)

// bundleHeld says whether some other session holds the bundle lock of the agent now. It takes the lock
// for the length of one statement when nobody does, and gives it back at once.
func (f *tlsDB) bundleHeld(agentID string) bool {
	f.t.Helper()
	var held bool
	if err := f.repo.DB.QueryRow(context.Background(), `SELECT NOT pg_try_advisory_xact_lock(hashtextextended($1, 0))`, "waf-agent-bundle:"+agentID).Scan(&held); err != nil {
		f.t.Fatal(err)
	}
	return held
}

// movedWhileWaiting runs a move of the application to y that stays inside its admit callback, holding
// the application row, until release is called; it starts start() meanwhile and gives it time to
// reach the row lock. wait returns the error of the move.
func (f *tlsDB) movedWhileWaiting(app, y string, start func()) (release func(), wait func() error) {
	f.t.Helper()
	entered, free := make(chan struct{}), make(chan struct{})
	moved := make(chan error, 1)
	go func() {
		moved <- f.repo.WAF.ReplaceAssignment(context.Background(), f.project, app, y, "block", func(domain.Maintenance) error {
			close(entered)
			<-free
			return nil
		})
	}()
	<-entered
	start()
	time.Sleep(500 * time.Millisecond)
	return func() { close(free) }, func() error { return <-moved }
}

// A maintenance save that waits for the row of the application while a move commits must lock the
// bundle of the agent that serves the application after the move, not the one it left: its answer
// about the size of the bundle is only good while it holds the right one.
func TestDBUpdateMaintenanceLocksTheBundleOfTheAgentThatServesTheApplication(t *testing.T) {
	f := newTLSDB(t)
	ctx := context.Background()
	x, y := f.agent(nil), f.agent(nil)
	app := f.app("shop", "", 0)
	f.assign(x, app)

	type held struct{ x, y bool }
	seen := make(chan held, 1)
	saved := make(chan error, 1)
	release, wait := f.movedWhileWaiting(app, y, func() {
		go func() {
			_, _, err := f.repo.App.UpdateMaintenance(ctx, f.project, app, func(stored domain.Maintenance) (domain.Maintenance, error) {
				// Called with the row and the bundle of the agent held.
				seen <- held{x: f.bundleHeld(x), y: f.bundleHeld(y)}
				return stored, nil
			})
			saved <- err
		}()
	})
	select {
	case <-seen:
		t.Fatal("the save went through while the move held the application")
	default:
	}
	release()
	if err := wait(); err != nil {
		t.Fatal(err)
	}
	if err := <-saved; err != nil {
		t.Fatal(err)
	}
	if got := <-seen; got.x || !got.y {
		t.Errorf("the save held the bundle of the old agent: %v, of the new agent: %v", got.x, got.y)
	}
}

// The same for a route or application change that checks the maintenance mode of its agent.
func TestDBUpdateAtomicAdmitsAgainstTheAgentThatServesTheApplication(t *testing.T) {
	f := newTLSDB(t)
	ctx := context.Background()
	x, y := f.agent(nil), f.agent(nil)
	app := f.app("shop", "", 0)
	f.assign(x, app)

	type seenAgent struct {
		agent string
		x, y  bool
	}
	seen := make(chan seenAgent, 1)
	done := make(chan error, 1)
	release, wait := f.movedWhileWaiting(app, y, func() {
		go func() {
			done <- f.repo.App.UpdateAtomic(ctx, f.project, app, AppPatch{}, func(_ domain.Maintenance, agentID, _ string) error {
				seen <- seenAgent{agent: agentID, x: f.bundleHeld(x), y: f.bundleHeld(y)}
				return nil
			})
		}()
	})
	release()
	if err := wait(); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if got := <-seen; got.agent != y || got.x || !got.y {
		t.Errorf("admit saw agent %s (want %s), held the old bundle: %v, the new one: %v", got.agent, y, got.x, got.y)
	}
}
