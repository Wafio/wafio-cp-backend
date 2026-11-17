package handlers

import (
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// The unknown-email login path compares against a hash of the same cost as
// stored passwords, so both paths take the same time.
func TestDummyPasswordHashCost(t *testing.T) {
	cost, err := bcrypt.Cost(dummyPasswordHash())
	if err != nil || cost != bcrypt.DefaultCost {
		t.Fatalf("dummy hash cost = %d (%v), want %d", cost, err, bcrypt.DefaultCost)
	}
	if bcrypt.CompareHashAndPassword(dummyPasswordHash(), []byte("anything")) == nil {
		t.Fatal("dummy hash must not match a password")
	}
}
