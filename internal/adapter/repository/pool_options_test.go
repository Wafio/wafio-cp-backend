package repository

import (
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

func TestApplyStatementTimeout(t *testing.T) {
	cfg, err := pgxpool.ParseConfig("postgres://u:p@localhost:5432/db")
	if err != nil {
		t.Fatal(err)
	}
	applyStatementTimeout(cfg, 15*time.Second)
	if got := cfg.ConnConfig.RuntimeParams["statement_timeout"]; got != "15000" {
		t.Fatalf("statement_timeout = %q, want 15000", got)
	}

	off, _ := pgxpool.ParseConfig("postgres://u:p@localhost:5432/db")
	applyStatementTimeout(off, 0)
	if _, set := off.ConnConfig.RuntimeParams["statement_timeout"]; set {
		t.Fatal("0 must leave the server setting alone")
	}

	dsn, _ := pgxpool.ParseConfig("postgres://u:p@localhost:5432/db?statement_timeout=5000")
	applyStatementTimeout(dsn, 15*time.Second)
	if got := dsn.ConnConfig.RuntimeParams["statement_timeout"]; got != "5000" {
		t.Fatalf("DSN value overridden: %q", got)
	}
}
