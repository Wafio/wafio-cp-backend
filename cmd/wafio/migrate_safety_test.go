package main

import (
	"errors"
	"testing"
)

type stepRecorder struct {
	steps int
	err   error
}

func (r *stepRecorder) Steps(steps int) error { r.steps = steps; return r.err }

func TestRollbackUsesOnlyRequestedSteps(t *testing.T) {
	for _, steps := range []int{1, 3} {
		r := &stepRecorder{}
		if err := rollbackSteps(r, steps); err != nil || r.steps != -steps {
			t.Fatalf("rollback %d: invoked %d, error %v", steps, r.steps, err)
		}
	}
	for _, steps := range []int{0, -1} {
		r := &stepRecorder{}
		if err := rollbackSteps(r, steps); err == nil || r.steps != 0 {
			t.Fatalf("invalid step count %d reached database", steps)
		}
	}
	want := errors.New("migration failed")
	if err := rollbackSteps(&stepRecorder{err: want}, 1); !errors.Is(err, want) {
		t.Fatalf("rollback error lost: %v", err)
	}
}
