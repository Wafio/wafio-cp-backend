// Package dbfixture seeds the rows DB-backed tests depend on, so every such
// test runs against a database freshly migrated from zero instead of assuming
// a developer database that already holds a project.
//
// Only test code imports this package.
package dbfixture

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgconn"
)

// DB is the subset of pgxpool.Pool (and pgx.Tx) the fixtures need.
type DB interface {
	Exec(ctx context.Context, sql string, args ...any) (pgconn.CommandTag, error)
}

// SeedProject inserts a user and a project owned by that user and returns
// both IDs. The user is deleted when the test ends; the foreign keys cascade
// the delete to the project and to agents and other rows hanging off it.
// Tests that close the pool before the end must delete the user themselves
// (DeleteUser) first.
func SeedProject(t testing.TB, db DB) (projectID, userID string) {
	t.Helper()
	ctx := context.Background()
	userID, projectID = uuid.NewString(), uuid.NewString()
	if _, err := db.Exec(ctx,
		`INSERT INTO users (id, email, password_hash, name) VALUES ($1, $2, 'x', 'fixture')`,
		userID, "fixture-"+userID+"@wafio.test"); err != nil {
		t.Fatalf("seed user: %v", err)
	}
	t.Cleanup(func() { _ = DeleteUser(db, userID) })
	if _, err := db.Exec(ctx,
		`INSERT INTO projects (id, user_id, name, code) VALUES ($1, $2, 'fixture', $3)`,
		projectID, userID, "fx-"+projectID[:8]); err != nil {
		t.Fatalf("seed project: %v", err)
	}
	return projectID, userID
}

// DeleteUser removes a seeded user and, through the cascades, its projects.
func DeleteUser(db DB, userID string) error {
	ctx := context.Background()
	// Agents are soft-deleted in production code, so their rows reference the
	// project until removed here; clear them before the project goes.
	if _, err := db.Exec(ctx, `DELETE FROM agents WHERE project_id IN (SELECT id FROM projects WHERE user_id = $1)`, userID); err != nil {
		return err
	}
	_, err := db.Exec(ctx, `DELETE FROM users WHERE id = $1`, userID)
	return err
}
