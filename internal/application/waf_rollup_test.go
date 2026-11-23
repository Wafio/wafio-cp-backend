package application

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/domain"
)

// fakeRollupStore records the calls of the rollup job and reports a fixed number of backfilled hours.
type fakeRollupStore struct {
	mu        sync.Mutex
	busy      bool
	calls     []string
	backfills int
	floor     time.Time
	keepDays  int
	oldest    *time.Time
}

func (f *fakeRollupStore) note(call string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, call)
}

func (f *fakeRollupStore) TryRollupLock(context.Context) (func(), bool, error) {
	f.note("lock")
	return func() { f.note("release") }, !f.busy, nil
}

func (f *fakeRollupStore) RollupSettled(context.Context) (time.Time, error) {
	f.note("settled")
	return time.Time{}, nil
}

func (f *fakeRollupStore) RollupFloor(_ context.Context, days int, oldest *time.Time) (time.Time, error) {
	f.note("floor")
	f.keepDays, f.oldest = days, oldest
	return f.floor, nil
}

func (f *fakeRollupStore) FillRollupMinutes(context.Context, time.Time) error {
	f.note("minutes")
	return nil
}

func (f *fakeRollupStore) FillRollupHour(context.Context) error {
	f.note("hour")
	return nil
}

func (f *fakeRollupStore) BackfillRollupHour(context.Context, time.Time, time.Time) (bool, error) {
	f.note("backfill")
	if f.backfills == 0 {
		return false, nil
	}
	f.backfills--
	return true, nil
}

func (f *fakeRollupStore) RaiseRollupFloor(context.Context, time.Time) error {
	f.note("raise")
	return nil
}

func (f *fakeRollupStore) DeleteExpiredRollups(context.Context, int) (int64, error) {
	f.note("delete")
	return 0, nil
}

func keepOf(days int, oldest *time.Time, err error) func(context.Context) (int, *time.Time, error) {
	return func(context.Context) (int, *time.Time, error) { return days, oldest, err }
}

func TestWAFRollupPassFillsThenBackfillsUntilNothingIsLeft(t *testing.T) {
	store := &fakeRollupStore{backfills: 2}
	(&WAFRollup{Store: store, Keep: keepOf(30, nil, nil)}).Pass(context.Background())
	want := []string{"lock", "settled", "minutes", "hour", "floor", "backfill", "backfill", "backfill", "release"}
	if !reflect.DeepEqual(store.calls, want) {
		t.Fatalf("calls %v, want %v", store.calls, want)
	}
}

func TestWAFRollupPassWithoutRetentionStillFills(t *testing.T) {
	store := &fakeRollupStore{backfills: 5}
	(&WAFRollup{Store: store, Keep: keepOf(0, nil, errors.New("settings down"))}).Pass(context.Background())
	want := []string{"lock", "settled", "minutes", "hour", "release"}
	if !reflect.DeepEqual(store.calls, want) {
		t.Fatalf("calls %v, want %v", store.calls, want)
	}
}

func TestWAFRollupPassWhileAnotherHoldsTheLockDoesNothing(t *testing.T) {
	store := &fakeRollupStore{busy: true}
	(&WAFRollup{Store: store, Keep: keepOf(30, nil, nil)}).Pass(context.Background())
	if !reflect.DeepEqual(store.calls, []string{"lock"}) {
		t.Fatalf("calls %v, want only the lock", store.calls)
	}
}

// The retention pass trims the rollups with the retention of waf_decisions, also where TimescaleDB
// drops the chunks itself, and not when that retention cannot be read.
func TestRetentionPassTrimsRollups(t *testing.T) {
	ctx := context.Background()
	oldest := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	for _, c := range []struct {
		name         string
		settingsDown bool
		wantCalls    []string
	}{
		{"policy mode, saved retention", false, []string{"floor", "raise", "delete"}},
		{"retention unreadable", true, nil},
	} {
		store, set := newPolicyStore()
		st := store.stats["waf_decisions"]
		st.Chunks = []domain.StorageChunk{{Start: oldest, End: oldest.Add(24 * time.Hour)}}
		store.stats["waf_decisions"] = st
		if err := set.SetJSON(ctx, dataRetentionKey, retentionRecord{Tables: map[string]int{"waf_decisions": 14}}); err != nil {
			t.Fatal(err)
		}
		set.fail = c.settingsDown
		rollups := &fakeRollupStore{}
		s := &Storage{Store: store, Settings: set, Rollup: &WAFRollup{Store: rollups, Keep: keepOf(14, nil, nil)}}
		s.retentionPass(ctx)
		if !reflect.DeepEqual(rollups.calls, c.wantCalls) {
			t.Fatalf("%s: calls %v, want %v", c.name, rollups.calls, c.wantCalls)
		}
		if c.wantCalls != nil && (rollups.keepDays != 14 || rollups.oldest == nil || !rollups.oldest.Equal(oldest)) {
			t.Fatalf("%s: floor asked for %d days and oldest %v, want 14 and %v", c.name, rollups.keepDays, rollups.oldest, oldest)
		}
	}
}
