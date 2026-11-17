package handlers

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// The listen-address index maps to LISTEN_HOST_TAKEN, any other unique
// violation on an application write (the name) to CONFLICT.
func TestAppUniqueConflict(t *testing.T) {
	wrap := func(e *pgconn.PgError) error { return fmt.Errorf("update route: %w", e) }
	cases := []struct {
		name string
		err  error
		ok   bool
		code string
	}{
		{"listen address", wrap(&pgconn.PgError{Code: "23505", ConstraintName: listenAddrUniqueIndex}), true, "LISTEN_HOST_TAKEN"},
		{"name", wrap(&pgconn.PgError{Code: "23505", ConstraintName: "apps_project_id_name_key"}), true, "CONFLICT"},
		{"unnamed unique", &pgconn.PgError{Code: "23505"}, true, "CONFLICT"},
		{"other constraint class", &pgconn.PgError{Code: "23503", ConstraintName: listenAddrUniqueIndex}, false, ""},
		{"plain error", errors.New("boom"), false, ""},
	}
	for _, tc := range cases {
		body, ok := appUniqueConflict(tc.err)
		if ok != tc.ok || (ok && body["code"] != tc.code) {
			t.Errorf("%s: ok=%v body=%v, want ok=%v code=%q", tc.name, ok, body, tc.ok, tc.code)
		}
		if got := isListenAddrTaken(tc.err); got != (tc.code == "LISTEN_HOST_TAKEN") {
			t.Errorf("%s: isListenAddrTaken=%v", tc.name, got)
		}
	}
}
