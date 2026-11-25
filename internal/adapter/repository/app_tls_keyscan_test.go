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
// The key lives in app_certificate_keys. It is selected only by CertificateForDelivery, inserted
// only by InsertCertificate and deleted only by retireCertificates (a replace and a delete of the
// certificate both go through it; an application or project that goes takes its keys by the foreign
// key, and nothing else deletes them), and none of the writes returns the row. The one other reader
// and writer is the rotation of totp.enc_key: sealedKeys reads the keys still sealed and
// replaceSealedKey puts them back sealed with the new key, both inside its transaction. The table
// and the column are named nowhere else, and no query reads every column of either table.
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
	case fn == "CertificateForDelivery" && strings.HasPrefix(trimmed, "select"):
		return true, ""
	case fn == "InsertCertificate" && strings.HasPrefix(trimmed, "insert into app_certificate_keys") && !strings.Contains(lower, "returning"):
		return false, ""
	case fn == "retireCertificates" && strings.HasPrefix(trimmed, "delete from app_certificate_keys") && !strings.Contains(lower, "returning"):
		return false, ""
	case fn == "sealedKeys" && trimmed == sealedKeysSQL:
		return false, ""
	case fn == "replaceSealedKey" && trimmed == replaceSealedKeySQL:
		return false, ""
	}
	return false, "names the key table or column in " + fn + ", which may not"
}

// The two statements of the rotation, pinned to the letter: the column list of the read is the ids
// and the sealed key, and the write changes the key of one certificate of one project.
const (
	sealedKeysSQL       = "select project_id::text, certificate_id::text, key_ciphertext from app_certificate_keys order by certificate_id"
	replaceSealedKeySQL = "update app_certificate_keys set key_ciphertext = $3 where certificate_id = $2 and project_id = $1"
)

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

// keyCall judges one mention of a function that opens or hands out sealed keys. sealedKeys and
// replaceSealedKey are the rotation's alone, used by the loader of the certificate keys; OpenBound is
// used by the rotation to read what it rewrites, and by the delivery to an agent, nowhere else. An
// agent that is sent a key opens it in agentserver/certificate_install.go.
func keyCall(callee, file, fn string) string {
	file = filepath.ToSlash(file)
	switch callee {
	case "sealedKeys", "replaceSealedKey":
		if strings.HasSuffix(file, "internal/adapter/repository/rekey.go") && fn == "loadCertificateKeys" {
			return ""
		}
	case "OpenBound":
		if strings.HasSuffix(file, "internal/adapter/repository/rekey.go") && fn == "open" {
			return ""
		}
		if strings.HasSuffix(file, "internal/agentserver/certificate_install.go") {
			return ""
		}
	}
	return callee + " is used by " + fn + " in " + file
}

var keyHelperNames = map[string]bool{"sealedKeys": true, "replaceSealedKey": true, "OpenBound": true}

// keyRef is one mention of a key helper: the name, the function it is in, and where.
type keyRef struct {
	name, fn string
	pos      token.Pos
}

// keyReferences finds every mention of a key helper in a file, not only the calls: a function value
// (f := sealedKeys, passing replaceSealedKey on), a method value (g := enc.OpenBound) and a method
// expression ((*otp.Encryptor).OpenBound) reach the same key as a call does. The declaration of a
// helper is not a mention. A method named OpenBound in an interface or a struct is one, which is more
// than needed and errs on the side of asking.
func keyReferences(file *ast.File) []keyRef {
	var out []keyRef
	for _, decl := range file.Decls {
		fn := ""
		var declared *ast.Ident
		if f, ok := decl.(*ast.FuncDecl); ok {
			fn, declared = f.Name.Name, f.Name
		}
		qualified := map[token.Pos]bool{}
		ast.Inspect(decl, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.SelectorExpr:
				// The selected name is also visited as an identifier of its own: count it once.
				qualified[x.Sel.Pos()] = true
				if keyHelperNames[x.Sel.Name] {
					out = append(out, keyRef{x.Sel.Name, fn, x.Sel.Pos()})
				}
			case *ast.Ident:
				if keyHelperNames[x.Name] && x != declared && !qualified[x.Pos()] {
					out = append(out, keyRef{x.Name, fn, x.Pos()})
				}
			}
			return true
		})
	}
	return out
}

// The two helpers of the rotation and OpenBound are the ways to a sealed key. This test finds every
// mention of them in the program, calls and values alike, and fails on one that is not where it may be.
func TestKeyHelpersAreUsedOnlyWhereTheyMayBe(t *testing.T) {
	root := filepath.Join("..", "..", "..")
	fset := token.NewFileSet()
	mentions := map[string]int{}
	for _, dir := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, dir), func(path string, d fs.DirEntry, err error) error {
			if err != nil || d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return err
			}
			file, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				return err
			}
			for _, ref := range keyReferences(file) {
				mentions[ref.name]++
				if problem := keyCall(ref.name, path, ref.fn); problem != "" {
					t.Errorf("%s: %s", fset.Position(ref.pos), problem)
				}
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	if mentions["sealedKeys"] != 1 || mentions["replaceSealedKey"] != 1 || mentions["OpenBound"] < 1 {
		t.Fatalf("mentions found: %v; the scan is blind (want sealedKeys 1, replaceSealedKey 1, OpenBound at least 1)", mentions)
	}
}

// The scan finds a helper however it is reached.
func TestKeyReferencesFindEveryWayToAHelper(t *testing.T) {
	for name, tt := range map[string]struct {
		src  string
		want []string // name in fn, in source order
	}{
		"a call":                          {`func f() { sealedKeys(ctx, tx, true) }`, []string{"sealedKeys in f"}},
		"a function value":                {`func f() { g := sealedKeys; _ = g }`, []string{"sealedKeys in f"}},
		"a function passed on":            {`func f() { use(replaceSealedKey) }`, []string{"replaceSealedKey in f"}},
		"a function in a struct":          {`func f() { _ = loader{read: sealedKeys} }`, []string{"sealedKeys in f"}},
		"a method call":                   {`func f() { enc.OpenBound(a, b) }`, []string{"OpenBound in f"}},
		"a method value":                  {`func f() { g := enc.OpenBound; _ = g }`, []string{"OpenBound in f"}},
		"a method expression":             {`func f() { g := (*otp.Encryptor).OpenBound; _ = g }`, []string{"OpenBound in f"}},
		"a method value of a field":       {`func f() { g := s.KeyCrypto.OpenBound; _ = g }`, []string{"OpenBound in f"}},
		"in a function literal":           {`func f() { go func() { sealedKeys(ctx, tx, false) }() }`, []string{"sealedKeys in f"}},
		"in a package variable":           {`var open = enc.OpenBound`, []string{"OpenBound in "}},
		"two in one function":             {`func f() { replaceSealedKey(b); sealedKeys(c) }`, []string{"replaceSealedKey in f", "sealedKeys in f"}},
		"the declaration of a function":   {`func sealedKeys() {}`, nil},
		"the declaration of a method":     {`func (e *Encryptor) OpenBound() {}`, nil},
		"the declaration of the other":    {`func replaceSealedKey() {}`, nil},
		"a method in an interface":        {`type opener interface{ OpenBound(a, b string) ([]byte, error) }`, []string{"OpenBound in "}},
		"other names":                     {`func f() { sealedKey(); enc.Open(); OpenBounds() }`, nil},
		"a helper named in a string only": {`func f() { _ = "sealedKeys OpenBound" }`, nil},
	} {
		file, err := parser.ParseFile(token.NewFileSet(), "x.go", "package x\n"+tt.src, 0)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var got []string
		for _, r := range keyReferences(file) {
			got = append(got, r.name+" in "+r.fn)
		}
		if strings.Join(got, ",") != strings.Join(tt.want, ",") {
			t.Errorf("%s: found %v, want %v", name, got, tt.want)
		}
	}
}

func TestKeyCallRules(t *testing.T) {
	const rekey = "internal/adapter/repository/rekey.go"
	for name, tt := range map[string]struct {
		callee, file, fn string
		bad              bool
	}{
		"the loader reads the sealed keys":        {"sealedKeys", rekey, "loadCertificateKeys", false},
		"the loader writes them back":             {"replaceSealedKey", rekey, "loadCertificateKeys", false},
		"another function of the rotation reads":  {"sealedKeys", rekey, "Rekey", true},
		"another function of the rotation writes": {"replaceSealedKey", rekey, "Rekey", true},
		"the TLS repository reads them":           {"sealedKeys", "internal/adapter/repository/app_tls.go", "CertificateForDelivery", true},
		"a handler reads them":                    {"sealedKeys", "internal/adapter/http/handlers/app_tls.go", "Upload", true},
		"a command writes them":                   {"replaceSealedKey", "cmd/wafio/rekey.go", "runRekey", true},
		"the rotation opens a key":                {"OpenBound", rekey, "open", false},
		"the rotation opens a key elsewhere":      {"OpenBound", rekey, "Rekey", true},
		"the delivery opens a key":                {"OpenBound", "internal/agentserver/certificate_install.go", "deliverCertificate", false},
		"a handler opens a key":                   {"OpenBound", "internal/adapter/http/handlers/app_tls.go", "Upload", true},
		"the stream opens a key":                  {"OpenBound", "internal/agentserver/stream.go", "handle", true},
		"a command opens a key":                   {"OpenBound", "cmd/wafio/rekey.go", "runRekey", true},
	} {
		got := keyCall(tt.callee, tt.file, tt.fn)
		if (got != "") != tt.bad {
			t.Errorf("%s: %q, want bad=%v", name, got, tt.bad)
		}
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
		{"an insert of a key elsewhere", `INSERT INTO app_certificate_keys (certificate_id, project_id, key_ciphertext) VALUES ($1, $2, $3)`, "UpdateTLS", true, false, true},
		{"a delete of keys in the insert", `DELETE FROM app_certificate_keys WHERE project_id = $2`, "InsertCertificate", true, false, true},
		{"a delete of keys elsewhere", `DELETE FROM app_certificate_keys WHERE project_id = $2`, "DeleteAgent", true, false, true},
		{"a delete of keys in the certificate delete itself", `DELETE FROM app_certificate_keys WHERE project_id = $2`, "DeleteCertificate", true, false, true},
		{"an insert in the retire", `INSERT INTO app_certificate_keys (certificate_id) VALUES ($1)`, "retireCertificates", true, false, true},
		{"a select in the retire", `SELECT key_ciphertext FROM app_certificate_keys`, "retireCertificates", true, false, true},
		{"a write in the delivery query", `DELETE FROM app_certificate_keys WHERE certificate_id = $1`, "CertificateForDelivery", true, false, true},
		{"deleting keys", `DELETE FROM app_certificate_keys WHERE project_id = $2 AND certificate_id IN (SELECT id FROM app_certificates WHERE app_id = $1`, "retireCertificates", true, false, false},
		{"deleting a key and reading it back", `DELETE FROM app_certificate_keys WHERE certificate_id = $1 RETURNING key_ciphertext`, "DeleteCertificate", true, false, true},
		{"inserting and reading it back", `INSERT INTO app_certificate_keys (key_ciphertext) VALUES ($1) RETURNING key_ciphertext`, "InsertCertificate", true, false, true},
		{"a write outside the repository", `DELETE FROM app_certificate_keys`, "Other", false, false, true},
		{"updating the key", `UPDATE app_certificate_keys SET key_ciphertext = $2 WHERE certificate_id = $1`, "InsertCertificate", true, false, true},
		{"the rotation reads the sealed keys", `SELECT project_id::text, certificate_id::text, key_ciphertext FROM app_certificate_keys ORDER BY certificate_id`, "sealedKeys", true, false, false},
		{"the rotation reads them outside the repository", `SELECT key_ciphertext FROM app_certificate_keys`, "sealedKeys", false, false, true},
		{"the rotation reads and returns what it writes", `UPDATE app_certificate_keys SET key_ciphertext = $3 WHERE certificate_id = $2 RETURNING key_ciphertext`, "replaceSealedKey", true, false, true},
		{"the rotation writes the key back", `UPDATE app_certificate_keys SET key_ciphertext = $3 WHERE certificate_id = $2 AND project_id = $1`, "replaceSealedKey", true, false, false},
		{"the rotation writes every key", `UPDATE app_certificate_keys SET key_ciphertext = $3`, "replaceSealedKey", true, false, true},
		{"the rotation writes the key of every project", `UPDATE app_certificate_keys SET key_ciphertext = $3 WHERE certificate_id = $2`, "replaceSealedKey", true, false, true},
		{"the rotation reads one more column", `SELECT project_id::text, certificate_id::text, key_ciphertext, certificate_id FROM app_certificate_keys ORDER BY certificate_id`, "sealedKeys", true, false, true},
		{"the rotation reads fewer columns", `SELECT key_ciphertext FROM app_certificate_keys ORDER BY certificate_id`, "sealedKeys", true, false, true},
		{"the rotation reads through a join", `SELECT project_id::text, certificate_id::text, key_ciphertext FROM app_certificate_keys JOIN app_certificates USING (project_id) ORDER BY certificate_id`, "sealedKeys", true, false, true},
		{"the rotation reads a filtered set", `SELECT project_id::text, certificate_id::text, key_ciphertext FROM app_certificate_keys WHERE true ORDER BY certificate_id`, "sealedKeys", true, false, true},
		{"the rotation deletes a key", `DELETE FROM app_certificate_keys WHERE certificate_id = $1`, "replaceSealedKey", true, false, true},
		{"a read under the name of the rotation write", `SELECT key_ciphertext FROM app_certificate_keys`, "replaceSealedKey", true, false, true},
		{"a write under the name of the rotation read", `UPDATE app_certificate_keys SET key_ciphertext = $3`, "sealedKeys", true, false, true},
		{"the rotation reads every column", `SELECT * FROM app_certificate_keys`, "sealedKeys", true, false, true},
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
