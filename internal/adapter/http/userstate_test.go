package httpadapter

import (
	"context"
	"sync"

	"github.com/wafio/wafio-cp-backend/internal/adapter/http/auth"
)

// testUserStore stands in for the users table behind RequireJWT in tests
// that run without a database. A listed id returns its row; any other id is
// an existing plain user at token version 0, which is what a token signed
// with auth.SignJWT(..., "user", ...) for a fresh account looks like.
type testUserStore struct {
	mu   sync.Mutex
	rows map[string]auth.UserState
	err  error
}

func newTestUserStore() *testUserStore {
	return &testUserStore{rows: map[string]auth.UserState{}}
}

func (s *testUserStore) put(id string, st auth.UserState) {
	s.mu.Lock()
	s.rows[id] = st
	s.mu.Unlock()
}

func (s *testUserStore) load(_ context.Context, id string) (auth.UserState, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.err != nil {
		return auth.UserState{}, s.err
	}
	if st, ok := s.rows[id]; ok {
		return st, nil
	}
	return auth.UserState{Exists: true, Role: "user"}, nil
}

// states returns a fresh RequireJWT cache over the store.
func (s *testUserStore) states() *auth.UserStates {
	return auth.NewUserStates(s.load, auth.UserStateTTL)
}

// testUsers backs newTestFiberApp and newJWTApp. adminToken registers its
// admins here.
var testUsers = newTestUserStore()
