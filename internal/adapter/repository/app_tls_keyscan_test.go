package repository

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

// keyStatement judges one SQL string of the program. delivery is true for the one statement that may
// select the sealed key of a certificate; problem is "" when the string is allowed.
//
// Allowed: the delivery query (CertificateForDelivery, in the TLS repository), and the statements
// that write the column: the insert of an upload and the updates that clear it, without RETURNING.
// Never allowed: the column anywhere else, and a query that reads every column of the table.
func keyStatement(sql, fn string, inTLSRepo bool) (delivery bool, problem string) {
	lower := strings.ToLower(sql)
	if strings.Contains(lower, "app_certificates") && (strings.Contains(lower, "select *") || strings.Contains(lower, "returning *") || strings.Contains(lower, ".*")) {
		return false, "reads every column of app_certificates"
	}
	if !strings.Contains(lower, "key_ciphertext") {
		return false, ""
	}
	trimmed := strings.TrimSpace(lower)
	switch {
	case !inTLSRepo:
		return false, "names key_ciphertext outside the TLS repository"
	case fn == "CertificateForDelivery":
		return true, ""
	case (strings.HasPrefix(trimmed, "insert into app_certificates") || strings.HasPrefix(trimmed, "update app_certificates")) && !strings.Contains(lower, "returning"):
		return false, ""
	}
	return false, "names key_ciphertext in " + fn + ", which is neither the delivery query nor a plain write"
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
		t.Fatalf("found %d statements of CertificateForDelivery that name key_ciphertext, want 1: the scan is blind", delivery)
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
		{"the delivery query", `SELECT c.key_ciphertext FROM app_certificates c`, "CertificateForDelivery", true, true, false},
		{"the same query under another name", `SELECT c.key_ciphertext FROM app_certificates c`, "GetTLS", true, false, true},
		{"the same query elsewhere", `SELECT c.key_ciphertext FROM app_certificates c`, "CertificateForDelivery", false, false, true},
		{"a select that is not the delivery", `SELECT key_ciphertext IS NOT NULL FROM app_certificates`, "UpdateTLS", true, false, true},
		{"the insert of an upload", "\n INSERT INTO app_certificates (id, key_ciphertext) VALUES ($1, $2)", "InsertCertificate", true, false, false},
		{"clearing the key", `UPDATE app_certificates SET key_ciphertext = NULL WHERE app_id = $1`, "DeleteCertificate", true, false, false},
		{"clearing the key and reading it back", `UPDATE app_certificates SET key_ciphertext = NULL RETURNING key_ciphertext`, "DeleteCertificate", true, false, true},
		{"inserting and reading it back", `INSERT INTO app_certificates (key_ciphertext) VALUES ($1) RETURNING key_ciphertext`, "InsertCertificate", true, false, true},
		{"a write outside the repository", `UPDATE app_certificates SET key_ciphertext = NULL`, "Other", false, false, true},
		{"every column", `SELECT * FROM app_certificates WHERE id = $1`, "GetTLS", true, false, true},
		{"every column of an alias", `SELECT c.* FROM app_certificates c`, "GetTLS", true, false, true},
		{"returning every column", `UPDATE app_certificates SET replaced_at = NOW() RETURNING *`, "X", true, false, true},
		{"a query without the key", `SELECT c.id FROM app_certificates c`, "GetTLS", true, false, false},
		{"another table", `SELECT * FROM apps`, "X", true, false, false},
	}
	for _, tt := range tests {
		delivery, problem := keyStatement(tt.sql, tt.fn, tt.inTLSRepo)
		if delivery != tt.delivery || (problem != "") != tt.bad {
			t.Errorf("%s: delivery=%v problem=%q, want delivery=%v bad=%v", tt.name, delivery, problem, tt.delivery, tt.bad)
		}
	}
}
