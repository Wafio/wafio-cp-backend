package repository

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// keyStatement judges one SQL string of the program. delivery is true for the one statement that may
// select the sealed key of a certificate; problem is "" when the string is allowed.
//
// The key lives in app_certificate_keys. Allowed: the delivery query (CertificateForDelivery, in the
// TLS repository), the insert of a key and the deletes of key rows, without RETURNING. Never
// allowed: the table or the column anywhere else, and a query that reads every column of either
// table.
func keyStatement(sql, fn string, inTLSRepo bool) (delivery bool, problem string) {
	lower := strings.ToLower(sql)
	for _, table := range []string{"app_certificates", "app_certificate_keys"} {
		if strings.Contains(lower, table) && (strings.Contains(lower, "select *") || strings.Contains(lower, "returning *") || strings.Contains(lower, ".*")) {
			return false, "reads every column of " + table
		}
	}
	if !strings.Contains(lower, "app_certificate_keys") && !strings.Contains(lower, "key_ciphertext") {
		return false, ""
	}
	trimmed := strings.TrimSpace(lower)
	switch {
	case !inTLSRepo:
		return false, "names the key table or column outside the TLS repository"
	case fn == "CertificateForDelivery":
		return true, ""
	case (strings.HasPrefix(trimmed, "insert into app_certificate_keys") || strings.HasPrefix(trimmed, "delete from app_certificate_keys")) && !strings.Contains(lower, "returning"):
		return false, ""
	}
	return false, "names the key table or column in " + fn + ", which is neither the delivery query nor a plain write"
}

// keyMigration judges a migration file. Only the migration that creates the key table (and its down
// file, which drops it) may name the table or the column, and only to create or drop the table: a
// later view, trigger, function or backfill that read the key would be a second way to it.
func keyMigration(file, content string) []string {
	var lines []string
	for _, l := range strings.Split(content, "\n") {
		if !strings.HasPrefix(strings.TrimSpace(l), "--") {
			lines = append(lines, l)
		}
	}
	var problems []string
	for _, stmt := range strings.Split(strings.ToLower(strings.Join(lines, "\n")), ";") {
		if !strings.Contains(stmt, "app_certificate_keys") && !strings.Contains(stmt, "key_ciphertext") {
			continue
		}
		trimmed := strings.TrimSpace(stmt)
		creates := strings.HasPrefix(trimmed, "create table if not exists app_certificate_keys") || strings.HasPrefix(trimmed, "drop table if exists app_certificate_keys")
		if !strings.HasPrefix(filepath.Base(file), "000124_") || !creates {
			problems = append(problems, file+": a statement names app_certificate_keys or key_ciphertext: "+firstLine(trimmed))
		}
	}
	return problems
}

func firstLine(s string) string {
	line, _, _ := strings.Cut(s, "\n")
	return line
}

// The sealed private key of a certificate is read by one query, CertificateForDelivery, whose
// conditions decide who may have it. Any other query that selected it, or a SELECT * on the table,
// would be a second way to the key that nobody checked. This test reads every SQL string of the
// program and fails on such a query.
func TestOnlyTheDeliveryQuerySelectsTheKey(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	var delivery int
	fset := token.NewFileSet()
	for _, dir := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			file, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				return err
			}
			inTLSRepo := strings.HasSuffix(filepath.ToSlash(path), "internal/adapter/repository/app_tls.go")
			for _, decl := range file.Decls {
				fn := ""
				if f, ok := decl.(*ast.FuncDecl); ok {
					fn = f.Name.Name
				}
				ast.Inspect(decl, func(n ast.Node) bool {
					lit, ok := n.(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						return true
					}
					sql, err := strconv.Unquote(lit.Value)
					if err != nil {
						return true
					}
					isDelivery, problem := keyStatement(sql, fn, inTLSRepo)
					if problem != "" {
						t.Errorf("%s: %s", fset.Position(lit.Pos()), problem)
					}
					if isDelivery {
						delivery++
					}
					return true
				})
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if delivery != 1 {
		t.Fatalf("found %d statements of CertificateForDelivery that name the key table, want 1: the scan is blind", delivery)
	}

	files, err := filepath.Glob(filepath.Join(root, "migrations", "*.sql"))
	if err != nil || len(files) < 124 {
		t.Fatalf("migrations: %d files, %v", len(files), err)
	}
	named := 0
	for _, f := range files {
		content, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, problem := range keyMigration(f, string(content)) {
			t.Error(problem)
		}
		if strings.Contains(strings.ToLower(string(content)), "app_certificate_keys") {
			named++
		}
	}
	if named != 2 {
		t.Fatalf("%d migration files name the key table, want the up and the down file of the one that creates it", named)
	}
}

// The scan is only as good as its rules, so the rules are checked against statements that must be
// caught and statements that must pass.
func TestKeyStatementRules(t *testing.T) {
	tests := []struct {
		name      string
		sql, fn   string
		inTLSRepo bool
		delivery  bool
		bad       bool
	}{
		{"the delivery query", `SELECT k.key_ciphertext FROM app_certificate_keys k`, "CertificateForDelivery", true, true, false},
		{"the same query under another name", `SELECT k.key_ciphertext FROM app_certificate_keys k`, "GetTLS", true, false, true},
		{"the same query elsewhere", `SELECT k.key_ciphertext FROM app_certificate_keys k`, "CertificateForDelivery", false, false, true},
		{"a read of the column alone", `SELECT key_ciphertext IS NOT NULL FROM app_certificate_keys`, "UpdateTLS", true, false, true},
		{"a join that only counts", `SELECT count(*) FROM app_certificates c JOIN app_certificate_keys k ON k.certificate_id = c.id`, "GetTLS", true, false, true},
		{"the insert of a key", "\n INSERT INTO app_certificate_keys (certificate_id, project_id, key_ciphertext) VALUES ($1, $2, $3)", "InsertCertificate", true, false, false},
		{"deleting keys", `DELETE FROM app_certificate_keys WHERE project_id = $2 AND certificate_id IN (SELECT id FROM app_certificates WHERE app_id = $1`, "retireCertificates", true, false, false},
		{"deleting a key and reading it back", `DELETE FROM app_certificate_keys WHERE certificate_id = $1 RETURNING key_ciphertext`, "DeleteCertificate", true, false, true},
		{"inserting and reading it back", `INSERT INTO app_certificate_keys (key_ciphertext) VALUES ($1) RETURNING key_ciphertext`, "InsertCertificate", true, false, true},
		{"a write outside the repository", `DELETE FROM app_certificate_keys`, "Other", false, false, true},
		{"updating the key", `UPDATE app_certificate_keys SET key_ciphertext = $2 WHERE certificate_id = $1`, "InsertCertificate", true, false, true},
		{"every column", `SELECT * FROM app_certificates WHERE id = $1`, "GetTLS", true, false, true},
		{"every column of an alias", `SELECT c.* FROM app_certificates c`, "GetTLS", true, false, true},
		{"every column of the key table", `SELECT * FROM app_certificate_keys`, "GetTLS", true, false, true},
		{"returning every column", `UPDATE app_certificates SET replaced_at = NOW() RETURNING *`, "X", true, false, true},
		{"a query without the key", `SELECT c.id FROM app_certificates c`, "GetTLS", true, false, false},
		{"the retire of a certificate", `UPDATE app_certificates SET replaced_at = COALESCE(replaced_at, NOW()) WHERE app_id = $1`, "retireCertificates", true, false, false},
		{"another table", `SELECT * FROM apps`, "X", true, false, false},
	}
	for _, tt := range tests {
		delivery, problem := keyStatement(tt.sql, tt.fn, tt.inTLSRepo)
		if delivery != tt.delivery || (problem != "") != tt.bad {
			t.Errorf("%s: delivery=%v problem=%q, want delivery=%v bad=%v", tt.name, delivery, problem, tt.delivery, tt.bad)
		}
	}
}

func TestKeyMigrationRules(t *testing.T) {
	create := "-- the key table is app_certificate_keys, key_ciphertext holds the key\nCREATE TABLE IF NOT EXISTS app_certificate_keys (certificate_id UUID, key_ciphertext TEXT NOT NULL);\nCREATE INDEX IF NOT EXISTS i ON app_certificates (app_id);"
	for name, tt := range map[string]struct {
		file, content string
		bad           bool
	}{
		"the migration that creates it":      {"migrations/000124_app_tls.up.sql", create, false},
		"the migration that drops it":        {"migrations/000124_app_tls.down.sql", "DROP TABLE IF EXISTS app_certificate_keys;", false},
		"no mention":                         {"migrations/000125_other.up.sql", "ALTER TABLE apps ADD COLUMN x INT;", false},
		"only a comment":                     {"migrations/000125_other.up.sql", "-- app_certificate_keys is not touched here\nSELECT 1;", false},
		"a later migration reads it":         {"migrations/000125_other.up.sql", "CREATE VIEW v AS SELECT key_ciphertext FROM app_certificate_keys;", true},
		"a later migration drops it":         {"migrations/000125_other.up.sql", "DROP TABLE IF EXISTS app_certificate_keys;", true},
		"the creating migration adds a view": {"migrations/000124_app_tls.up.sql", create + "\nCREATE VIEW v AS SELECT key_ciphertext FROM app_certificate_keys;", true},
		"the creating migration copies keys": {"migrations/000124_app_tls.up.sql", create + "\nINSERT INTO t SELECT key_ciphertext FROM app_certificate_keys;", true},
	} {
		if got := keyMigration(tt.file, tt.content); (len(got) > 0) != tt.bad {
			t.Errorf("%s: problems %v, want bad=%v", name, got, tt.bad)
		}
	}
}
