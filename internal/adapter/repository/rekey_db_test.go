package repository

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/wafio/wafio-cp-backend/internal/application"
	"github.com/wafio/wafio-cp-backend/internal/domain"
	"github.com/wafio/wafio-cp-backend/internal/otp"
)

func rekeyKey(seed string) *otp.Encryptor {
	e, err := otp.NewEncryptor(strings.Repeat(seed, 32))
	if err != nil {
		panic(err)
	}
	return e
}

// rekeyFixture is a database of its own: a schema that holds copies of the tables Rekey reads and
// writes, so the test sees only its own rows (Rekey reads every row of those tables, and the shared
// test database holds the rows of the tests that run beside this one). The key lock is its own as
// well, since advisory locks belong to the whole database.
type rekeyFixture struct {
	t                        *testing.T
	repo                     *Repository
	oldKey, newKey, thirdKey *otp.Encryptor
	project                  string
}

func newRekeyFixture(t *testing.T) *rekeyFixture {
	t.Helper()
	dsn := os.Getenv("TEST_DB_URL")
	if dsn == "" {
		t.Skip("TEST_DB_URL not set")
	}
	t.Setenv("WAFIO_MALWARE_AUTH_KEY", "")
	ctx := context.Background()
	admin, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(admin.Close)
	schema := "rekey_" + strings.ReplaceAll(uuid.NewString(), "-", "")[:12]
	quoted := pgx.Identifier{schema}.Sanitize()
	if _, err := admin.Exec(ctx, "CREATE SCHEMA "+quoted); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if _, err := admin.Exec(ctx, "DROP SCHEMA "+quoted+" CASCADE"); err != nil {
			t.Error(err)
		}
	})
	for _, table := range []string{"users", "system_settings", "app_certificate_keys", "system_audit"} {
		if _, err := admin.Exec(ctx, "CREATE TABLE "+quoted+"."+table+" (LIKE public."+table+" INCLUDING ALL)"); err != nil {
			t.Fatal(err)
		}
	}
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	cfg.ConnConfig.RuntimeParams["search_path"] = schema
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(pool.Close)
	repo := FromPool(pool)
	id := uuid.New()
	repo.keyTuning = keyTuning{
		lockKey:  int64(binary.BigEndian.Uint64(id[:8])),
		lockWait: 300 * time.Millisecond,
		ping:     50 * time.Millisecond,
	}
	return &rekeyFixture{t: t, repo: repo, project: uuid.NewString(),
		oldKey: rekeyKey("1a"), newKey: rekeyKey("2b"), thirdKey: rekeyKey("3c")}
}

func (f *rekeyFixture) exec(sql string, args ...any) {
	f.t.Helper()
	if _, err := f.repo.DB.Exec(context.Background(), sql, args...); err != nil {
		f.t.Fatalf("%s: %v", sql, err)
	}
}

// user inserts a user with the stored values given as they are.
func (f *rekeyFixture) user(secret, pending string) string {
	f.t.Helper()
	id := uuid.NewString()
	f.exec(`INSERT INTO users (id, email, password_hash, name, totp_secret, totp_pending_secret) VALUES ($1, $2, 'x', 'rekey', $3, $4)`,
		id, "rekey-"+id+"@wafio.test", secret, pending)
	return id
}

func (f *rekeyFixture) sealedKey(e *otp.Encryptor, project, cert string) string {
	f.t.Helper()
	sealed, err := e.SealBound([]byte(plainKeyOf(cert)), domain.CertificateKeyAAD(project, cert))
	if err != nil {
		f.t.Fatal(err)
	}
	return sealed
}

// certKey inserts a certificate key sealed with e for the ids it is stored under.
func (f *rekeyFixture) certKey(e *otp.Encryptor) (cert, sealed string) {
	f.t.Helper()
	cert = uuid.NewString()
	sealed = f.sealedKey(e, f.project, cert)
	f.exec(`INSERT INTO app_certificate_keys (certificate_id, project_id, key_ciphertext) VALUES ($1, $2, $3)`, cert, f.project, sealed)
	return cert, sealed
}

func (f *rekeyFixture) enc(e *otp.Encryptor, plain string) string {
	f.t.Helper()
	s, err := e.Encrypt(plain)
	if err != nil {
		f.t.Fatal(err)
	}
	return s
}

// saveSettings stores the SMTP password and the malware key through the writers the control plane
// uses, sealed with e.
func (f *rekeyFixture) saveSettings(e *otp.Encryptor) {
	f.t.Helper()
	ctx := context.Background()
	mail := &application.MailSettings{Store: f.repo.SystemSettings, Crypto: e}
	host, user, pass, from, base := "smtp.example.test", "mailer", "smtp-pass-8f3a", "noreply@example.test", "https://dash.example.test"
	port := 2525
	if _, err := mail.Update(ctx, application.MailSettingsUpdate{Host: &host, Port: &port, Username: &user, Password: &pass, FromAddress: &from, BaseURL: &base}); err != nil {
		f.t.Fatalf("save mail settings: %v", err)
	}
	if err := (&application.MalwareCredentials{Store: f.repo.SystemSettings, Crypto: e}).Save(ctx, "malware-key-77c1"); err != nil {
		f.t.Fatalf("save malware key: %v", err)
	}
}

// snapshot is every stored value of the three tables, by row.
func (f *rekeyFixture) snapshot() map[string]string {
	f.t.Helper()
	rows, err := f.repo.DB.Query(context.Background(), `
		SELECT 'user-secret ' || id::text, COALESCE(totp_secret, '') FROM users
		UNION ALL SELECT 'user-pending ' || id::text, totp_pending_secret FROM users
		UNION ALL SELECT 'setting ' || key, value::text FROM system_settings
		UNION ALL SELECT 'key ' || certificate_id::text, key_ciphertext FROM app_certificate_keys`)
	if err != nil {
		f.t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, v string
		if err := rows.Scan(&k, &v); err != nil {
			f.t.Fatal(err)
		}
		out[k] = v
	}
	if err := rows.Err(); err != nil {
		f.t.Fatal(err)
	}
	return out
}

func (f *rekeyFixture) count(report RekeyReport, kind string) RekeyCount {
	f.t.Helper()
	for _, c := range report.Counts {
		if c.Kind == kind {
			return c
		}
	}
	f.t.Fatalf("no count for %s in %+v", kind, report)
	return RekeyCount{}
}

func (f *rekeyFixture) rekey(apply bool) (RekeyReport, error) {
	return f.repo.Rekey(context.Background(), f.oldKey, f.newKey, apply)
}

// seedAll stores one or more values of every kind under the old key and returns what is needed to
// check them.
type rekeySeed struct {
	userSecret, userPending, userBoth string
	certs                             map[string]bool // certificate id, all under f.project
}

func (f *rekeyFixture) seedAll() rekeySeed {
	f.t.Helper()
	s := rekeySeed{certs: map[string]bool{}}
	s.userSecret = f.user(f.enc(f.oldKey, "SECRET-A"), "")
	s.userPending = f.user("", f.enc(f.oldKey, "PENDING-B"))
	s.userBoth = f.user(f.enc(f.oldKey, "SECRET-C"), f.enc(f.oldKey, "PENDING-C"))
	f.user("", "") // a user without 2FA
	f.saveSettings(f.oldKey)
	for i := 0; i < 3; i++ {
		cert, _ := f.certKey(f.oldKey)
		s.certs[cert] = true
	}
	return s
}

// The dry run runs in a read-only transaction, so it could not write or lock a row if it tried.
func TestRekeyDryRunChangesNothing(t *testing.T) {
	f := newRekeyFixture(t)
	f.seedAll()
	before := f.snapshot()

	report, err := f.rekey(false)
	if err != nil {
		t.Fatal(err)
	}
	if report.Applied {
		t.Error("a dry run says it applied")
	}
	want := map[string]int{RekeyKindTOTPSecret: 2, RekeyKindTOTPPending: 2, RekeyKindSMTPPassword: 1, RekeyKindMalwareKey: 1, RekeyKindCertificateKey: 3}
	var kinds []string
	for _, c := range report.Counts {
		kinds = append(kinds, c.Kind)
		if c.ToRewrite != want[c.Kind] || c.AlreadyNew != 0 || c.NotSealed != 0 || c.Unreadable != 0 {
			t.Errorf("%s: %+v, want %d to rewrite", c.Kind, c, want[c.Kind])
		}
	}
	if !slices.Equal(kinds, []string{RekeyKindTOTPSecret, RekeyKindTOTPPending, RekeyKindSMTPPassword, RekeyKindMalwareKey, RekeyKindCertificateKey}) {
		t.Errorf("kinds in the report: %v", kinds)
	}
	if after := f.snapshot(); !equalStrings(before, after) {
		t.Fatal("a dry run changed a stored value")
	}
}

func equalStrings(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func TestRekeyApplyRewritesEveryKind(t *testing.T) {
	f := newRekeyFixture(t)
	seed := f.seedAll()
	before := f.snapshot()

	report, err := f.rekey(true)
	if err != nil {
		t.Fatal(err)
	}
	if !report.Applied || report.ToRewrite() != 9 || report.Unreadable() != 0 {
		t.Fatalf("report %+v", report)
	}
	after := f.snapshot()
	// One row more: the id of the new key.
	if len(after) != len(before)+1 {
		t.Fatalf("rows: %d before, %d after", len(before), len(after))
	}
	if got := f.storedKeyID(); got != f.newKey.KeyID() {
		t.Errorf("stored key id %q, want %q", got, f.newKey.KeyID())
	}
	f.checkAuditRow(report, "SECRET-A", "smtp-pass-8f3a", "malware-key-77c1")

	// TOTP secrets: every sealed column opens with the new key to the same secret, and no longer with
	// the old key.
	for col, want := range map[string]string{
		"user-secret " + seed.userSecret:   "SECRET-A",
		"user-pending " + seed.userPending: "PENDING-B",
		"user-secret " + seed.userBoth:     "SECRET-C",
		"user-pending " + seed.userBoth:    "PENDING-C",
	} {
		if got, err := f.newKey.Decrypt(after[col]); err != nil || got != want {
			t.Errorf("%s does not open with the new key: %q %v", col, got, err)
		}
		if _, err := f.oldKey.Decrypt(after[col]); err == nil {
			t.Errorf("%s still opens with the old key", col)
		}
		if after[col] == before[col] {
			t.Errorf("%s was not rewritten", col)
		}
	}
	for id, v := range after {
		if strings.HasPrefix(id, "user-") && v == "" && before[id] != "" {
			t.Errorf("%s was emptied", id)
		}
	}

	// The settings read back through the writers' own readers with the new key.
	ctx := context.Background()
	state, err := (&application.MailSettings{Store: f.repo.SystemSettings, Crypto: f.newKey}).Current(ctx)
	if err != nil || state.Server.Password != "smtp-pass-8f3a" || state.Server.Host != "smtp.example.test" || state.Server.Port != 2525 ||
		state.Server.Username != "mailer" || state.BaseURL != "https://dash.example.test" {
		t.Errorf("mail settings after the rekey: %+v %v", state.Server.Host, err)
	}
	if _, err := (&application.MailSettings{Store: f.repo.SystemSettings, Crypto: f.oldKey}).Current(ctx); err == nil {
		t.Error("the SMTP password still opens with the old key")
	}
	if key, err := (&application.MalwareCredentials{Store: f.repo.SystemSettings, Crypto: f.newKey}).Resolve(ctx); err != nil || key != "malware-key-77c1" {
		t.Errorf("malware key after the rekey: %q %v", key, err)
	}
	if _, err := (&application.MalwareCredentials{Store: f.repo.SystemSettings, Crypto: f.oldKey}).Resolve(ctx); err == nil {
		t.Error("the malware key still opens with the old key")
	}
	// The other fields of the settings row are as they were.
	var before1, after1 map[string]json.RawMessage
	if err := json.Unmarshal([]byte(before["setting smtp_settings"]), &before1); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(after["setting smtp_settings"]), &after1); err != nil {
		t.Fatal(err)
	}
	for k, v := range before1 {
		if k == "password_ciphertext" {
			continue
		}
		if string(after1[k]) != string(v) {
			t.Errorf("field %s of the SMTP settings changed", k)
		}
	}
	if len(after1) != len(before1) {
		t.Errorf("fields of the SMTP settings: %d before, %d after", len(before1), len(after1))
	}

	// Certificate keys open with the new key and the ids they are stored under, and with nothing else.
	for cert := range seed.certs {
		sealed := after["key "+cert]
		got, err := f.newKey.OpenBound(sealed, domain.CertificateKeyAAD(f.project, cert))
		if err != nil || string(got) != plainKeyOf(cert) {
			t.Errorf("certificate key %s after the rekey: %v", cert, err)
		}
		if _, err := f.newKey.OpenBound(sealed, domain.CertificateKeyAAD(f.project, uuid.NewString())); err == nil {
			t.Errorf("certificate key %s opens for another certificate", cert)
		}
		if _, err := f.newKey.OpenBound(sealed, domain.CertificateKeyAAD(uuid.NewString(), cert)); err == nil {
			t.Errorf("certificate key %s opens for another project", cert)
		}
		if _, err := f.oldKey.OpenBound(sealed, domain.CertificateKeyAAD(f.project, cert)); err == nil {
			t.Errorf("certificate key %s still opens with the old key", cert)
		}
		if !strings.HasPrefix(sealed, "encb:v1:"+f.newKey.KeyID()+":") {
			t.Errorf("certificate key %s is not sealed under the new key id", cert)
		}
	}
}

func TestRekeyAppliedTwiceIsTheSameAsOnce(t *testing.T) {
	f := newRekeyFixture(t)
	f.seedAll()
	if _, err := f.rekey(true); err != nil {
		t.Fatal(err)
	}
	once := f.snapshot()

	report, err := f.rekey(true)
	if err != nil {
		t.Fatal(err)
	}
	if report.ToRewrite() != 0 || report.Unreadable() != 0 {
		t.Fatalf("second run: %+v", report)
	}
	for _, c := range report.Counts {
		if c.AlreadyNew == 0 {
			t.Errorf("%s: the second run found no value under the new key", c.Kind)
		}
	}
	if !equalStrings(once, f.snapshot()) {
		t.Fatal("the second run changed a stored value")
	}
}

// An interrupted rotation, or a control plane that started with the new key before rekey ran, leaves
// values of both kinds in the same table. The old ones are rewritten, the new ones are left alone.
func TestRekeyFinishesAMixedState(t *testing.T) {
	f := newRekeyFixture(t)
	oldUser := f.user(f.enc(f.oldKey, "OLD"), "")
	newUser := f.user(f.enc(f.newKey, "NEW"), "")
	newCert, newSealed := f.certKey(f.newKey)
	oldCert, _ := f.certKey(f.oldKey)
	before := f.snapshot()

	report, err := f.rekey(true)
	if err != nil {
		t.Fatal(err)
	}
	if c := f.count(report, RekeyKindTOTPSecret); c.ToRewrite != 1 || c.AlreadyNew != 1 {
		t.Errorf("totp: %+v", c)
	}
	if c := f.count(report, RekeyKindCertificateKey); c.ToRewrite != 1 || c.AlreadyNew != 1 {
		t.Errorf("keys: %+v", c)
	}
	after := f.snapshot()
	if after["user-secret "+newUser] != before["user-secret "+newUser] {
		t.Error("a value under the new key was rewritten")
	}
	if after["key "+newCert] != newSealed {
		t.Error("a certificate key under the new key was rewritten")
	}
	if got, err := f.newKey.Decrypt(after["user-secret "+oldUser]); err != nil || got != "OLD" {
		t.Errorf("the old value: %q %v", got, err)
	}
	if got, err := f.newKey.OpenBound(after["key "+oldCert], domain.CertificateKeyAAD(f.project, oldCert)); err != nil || string(got) != plainKeyOf(oldCert) {
		t.Errorf("the old certificate key: %v", err)
	}
}

// One value that neither key opens stops the whole apply: nothing is written, not even what the old
// key opens. The dry run says so too.
func TestRekeyRefusesAValueUnderAThirdKeyAndChangesNothing(t *testing.T) {
	cases := map[string]func(f *rekeyFixture) (kind, label string){
		"a TOTP secret": func(f *rekeyFixture) (string, string) {
			return RekeyKindTOTPSecret, "user " + f.user(f.enc(f.thirdKey, "X"), "")
		},
		"a pending TOTP secret": func(f *rekeyFixture) (string, string) {
			return RekeyKindTOTPPending, "user " + f.user("", f.enc(f.thirdKey, "X"))
		},
		"a certificate key": func(f *rekeyFixture) (string, string) {
			cert, _ := f.certKey(f.thirdKey)
			return RekeyKindCertificateKey, "certificate " + cert
		},
		"a certificate key sealed for another certificate": func(f *rekeyFixture) (string, string) {
			// A key copied to the row of another certificate: right key, wrong context.
			cert := uuid.NewString()
			f.exec(`INSERT INTO app_certificate_keys (certificate_id, project_id, key_ciphertext) VALUES ($1, $2, $3)`,
				cert, f.project, f.sealedKey(f.oldKey, f.project, uuid.NewString()))
			return RekeyKindCertificateKey, "certificate " + cert
		},
		"a certificate key that is not sealed": func(f *rekeyFixture) (string, string) {
			cert := uuid.NewString()
			f.exec(`INSERT INTO app_certificate_keys (certificate_id, project_id, key_ciphertext) VALUES ($1, $2, 'not a sealed key')`, cert, f.project)
			return RekeyKindCertificateKey, "certificate " + cert
		},
		"the SMTP password": func(f *rekeyFixture) (string, string) {
			f.exec(`INSERT INTO system_settings (key, value) VALUES ('smtp_settings', $1::jsonb)`, `{"host":"h","password_ciphertext":"`+f.enc(f.thirdKey, "x")+`"}`)
			return RekeyKindSMTPPassword, "setting smtp_settings"
		},
		"the malware key": func(f *rekeyFixture) (string, string) {
			f.exec(`INSERT INTO system_settings (key, value) VALUES ('malware_bazaar_credentials', $1::jsonb)`, `{"ciphertext":"`+f.enc(f.thirdKey, "x")+`"}`)
			return RekeyKindMalwareKey, "setting malware_bazaar_credentials"
		},
	}
	for name, plant := range cases {
		t.Run(name, func(t *testing.T) {
			f := newRekeyFixture(t)
			// Plenty that the old key opens, in every table.
			f.user(f.enc(f.oldKey, "A"), f.enc(f.oldKey, "B"))
			f.certKey(f.oldKey)
			kind, label := plant(f)
			if kind != RekeyKindSMTPPassword && kind != RekeyKindMalwareKey {
				f.saveSettings(f.oldKey)
			}
			before := f.snapshot()

			for _, apply := range []bool{false, true} {
				report, err := f.rekey(apply)
				if !errors.Is(err, ErrRekeyUnreadable) {
					t.Fatalf("apply=%v: error %v, want ErrRekeyUnreadable", apply, err)
				}
				if report.Applied || report.Unreadable() != 1 {
					t.Fatalf("apply=%v: report %+v", apply, report)
				}
				c := f.count(report, kind)
				if c.Unreadable != 1 || len(c.UnreadableRows) != 1 || c.UnreadableRows[0] != label {
					t.Errorf("apply=%v: %s names %v, want %q", apply, kind, c.UnreadableRows, label)
				}
				if !equalStrings(before, f.snapshot()) {
					t.Fatalf("apply=%v changed a stored value", apply)
				}
			}
		})
	}
}

func TestRekeyLeavesPlainTextAndEmptyRowsAlone(t *testing.T) {
	f := newRekeyFixture(t)
	plain := f.user("LEGACYPLAINSECRET", "")
	sealed := f.user(f.enc(f.oldKey, "SEALED"), "")
	empty := f.user("", "")
	f.exec(`UPDATE users SET totp_secret = NULL WHERE id = $1`, empty)
	// A settings row without a password, and one that is no JSON object.
	f.exec(`INSERT INTO system_settings (key, value) VALUES ('smtp_settings', '{"host":"h"}'::jsonb)`)
	f.exec(`INSERT INTO system_settings (key, value) VALUES ('malware_bazaar_credentials', '"text"'::jsonb)`)
	before := f.snapshot()

	report, err := f.rekey(true)
	if err != nil {
		t.Fatal(err)
	}
	if c := f.count(report, RekeyKindTOTPSecret); c.ToRewrite != 1 || c.NotSealed != 1 {
		t.Errorf("totp: %+v", c)
	}
	for _, kind := range []string{RekeyKindSMTPPassword, RekeyKindMalwareKey} {
		if c := f.count(report, kind); c.ToRewrite+c.AlreadyNew+c.NotSealed+c.Unreadable != 0 {
			t.Errorf("%s: %+v", kind, c)
		}
	}
	after := f.snapshot()
	if after["user-secret "+plain] != "LEGACYPLAINSECRET" {
		t.Error("a plain text secret was changed")
	}
	if after["user-secret "+empty] != before["user-secret "+empty] {
		t.Error("a user without a secret was changed")
	}
	if got, err := f.newKey.Decrypt(after["user-secret "+sealed]); err != nil || got != "SEALED" {
		t.Errorf("the sealed secret: %q %v", got, err)
	}
	if after["setting smtp_settings"] != before["setting smtp_settings"] || after["setting malware_bazaar_credentials"] != before["setting malware_bazaar_credentials"] {
		t.Error("a settings row without a secret was changed")
	}
}

func TestRekeyOnAnEmptyDatabase(t *testing.T) {
	f := newRekeyFixture(t)
	report, err := f.rekey(true)
	if err != nil || !report.Applied || report.ToRewrite() != 0 || len(report.Counts) != 5 {
		t.Fatalf("%+v %v", report, err)
	}
}

func TestRekeyNeedsBothKeys(t *testing.T) {
	f := newRekeyFixture(t)
	if _, err := f.repo.Rekey(context.Background(), nil, f.newKey, true); err == nil {
		t.Error("no old key accepted")
	}
	if _, err := f.repo.Rekey(context.Background(), f.oldKey, nil, true); err == nil {
		t.Error("no new key accepted")
	}
}

// The report names a bounded number of rows, and never a value.
func TestRekeyReportNamesFewRowsAndNoValue(t *testing.T) {
	f := newRekeyFixture(t)
	for i := 0; i < rekeyNamedRows+5; i++ {
		f.user(f.enc(f.thirdKey, fmt.Sprintf("THIRD-%d", i)), "")
	}
	report, err := f.rekey(false)
	if !errors.Is(err, ErrRekeyUnreadable) {
		t.Fatalf("error %v", err)
	}
	c := f.count(report, RekeyKindTOTPSecret)
	if c.Unreadable != rekeyNamedRows+5 || len(c.UnreadableRows) != rekeyNamedRows {
		t.Fatalf("%d unreadable, %d named", c.Unreadable, len(c.UnreadableRows))
	}
	for _, row := range c.UnreadableRows {
		if !strings.HasPrefix(row, "user ") || strings.Contains(row, "enc:v1:") || strings.Contains(row, "THIRD") {
			t.Errorf("row name %q", row)
		}
	}
}

// The keys an upload writes are the keys Rekey opens: the upload seals with SealBound under the ids
// of the certificate, and the scoped copy of the table holds the very text it stored.
func TestRekeyOpensTheKeysAnUploadWrites(t *testing.T) {
	f := newRekeyFixture(t)
	pub := newTLSDB(t)
	app := pub.app("rekey", "", 0)
	cert := newCert("rekey.example.com")
	pub.mustUpload(app, cert)
	stored := pub.key(cert.ID)
	if stored == nil {
		t.Fatal("the upload stored no key")
	}
	sealed := *stored
	f.exec(`INSERT INTO app_certificate_keys (certificate_id, project_id, key_ciphertext) VALUES ($1, $2, $3)`, cert.ID, pub.project, sealed)

	report, err := f.repo.Rekey(context.Background(), testEncryptor, f.newKey, true)
	if err != nil || f.count(report, RekeyKindCertificateKey).ToRewrite != 1 {
		t.Fatalf("%+v %v", report, err)
	}
	var moved string
	if err := f.repo.DB.QueryRow(context.Background(), `SELECT key_ciphertext FROM app_certificate_keys WHERE certificate_id = $1`, cert.ID).Scan(&moved); err != nil {
		t.Fatal(err)
	}
	got, err := f.newKey.OpenBound(moved, domain.CertificateKeyAAD(pub.project, cert.ID))
	if err != nil || string(got) != plainKeyOf(cert.ID) {
		t.Fatalf("the uploaded key after the rekey: %v", err)
	}
}

// With apply the rows are locked: a rekey waits for a transaction that holds one, then reads what
// that transaction committed.
func TestRekeyApplyWaitsForALockedRow(t *testing.T) {
	f := newRekeyFixture(t)
	id := f.user(f.enc(f.oldKey, "BEFORE"), "")
	ctx := context.Background()
	tx, err := f.repo.DB.Begin(ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	// Another process saves a secret under the new key and holds the row.
	if _, err := tx.Exec(ctx, `UPDATE users SET totp_secret = $2 WHERE id = $1`, id, f.enc(f.newKey, "DURING")); err != nil {
		t.Fatal(err)
	}

	type result struct {
		report RekeyReport
		err    error
	}
	done := make(chan result, 1)
	go func() {
		r, err := f.rekey(true)
		done <- result{r, err}
	}()
	select {
	case r := <-done:
		t.Fatalf("rekey did not wait for the locked row: %+v %v", r.report, r.err)
	case <-time.After(500 * time.Millisecond):
	}
	if err := tx.Commit(ctx); err != nil {
		t.Fatal(err)
	}
	select {
	case r := <-done:
		if r.err != nil {
			t.Fatal(r.err)
		}
		if c := f.count(r.report, RekeyKindTOTPSecret); c.AlreadyNew != 1 || c.ToRewrite != 0 {
			t.Errorf("after the lock was released: %+v", c)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("rekey did not finish after the lock was released")
	}
	if got, err := f.newKey.Decrypt(f.snapshot()["user-secret "+id]); err != nil || got != "DURING" {
		t.Errorf("the committed value: %q %v", got, err)
	}
}

// storedKeyID is the id of the key in force, as the database holds it.
func (f *rekeyFixture) storedKeyID() string {
	f.t.Helper()
	var id string
	err := f.repo.DB.QueryRow(context.Background(), `SELECT COALESCE(value->>'key_id', '') FROM system_settings WHERE key = $1`, encKeySetting).Scan(&id)
	if errors.Is(err, pgx.ErrNoRows) {
		return ""
	}
	if err != nil {
		f.t.Fatal(err)
	}
	return id
}

func (f *rekeyFixture) auditRows() []map[string]any {
	f.t.Helper()
	rows, err := f.repo.DB.Query(context.Background(), `SELECT action, target_type, COALESCE(target_id, ''), outcome, COALESCE(user_agent, ''), COALESCE(metadata::text, '') FROM system_audit ORDER BY created_at`)
	if err != nil {
		f.t.Fatal(err)
	}
	defer rows.Close()
	var out []map[string]any
	for rows.Next() {
		var action, targetType, targetID, outcome, agent, meta string
		if err := rows.Scan(&action, &targetType, &targetID, &outcome, &agent, &meta); err != nil {
			f.t.Fatal(err)
		}
		out = append(out, map[string]any{"action": action, "target_type": targetType, "target_id": targetID, "outcome": outcome, "agent": agent, "meta": meta})
	}
	if err := rows.Err(); err != nil {
		f.t.Fatal(err)
	}
	return out
}

// checkAuditRow expects the one row of a rotation, with the key ids and the counts, and no secret.
func (f *rekeyFixture) checkAuditRow(report RekeyReport, secrets ...string) {
	f.t.Helper()
	rows := f.auditRows()
	if len(rows) != 1 {
		f.t.Fatalf("%d audit rows, want 1: %v", len(rows), rows)
	}
	row := rows[0]
	if row["action"] != "admin.encryption_key_rotated" || row["target_type"] != "system" || row["target_id"] != "totp.enc_key" || row["outcome"] != "success" || row["agent"] != "wafio rekey" {
		f.t.Errorf("audit row %v", row)
	}
	var meta struct {
		Old       string         `json:"old_key_id"`
		New       string         `json:"new_key_id"`
		Rewritten map[string]int `json:"rewritten"`
	}
	text := row["meta"].(string)
	if err := json.Unmarshal([]byte(text), &meta); err != nil {
		f.t.Fatal(err)
	}
	if meta.Old != f.oldKey.KeyID() || meta.New != f.newKey.KeyID() {
		f.t.Errorf("audit key ids %s %s", meta.Old, meta.New)
	}
	for _, c := range report.Counts {
		if meta.Rewritten[c.Kind] != c.ToRewrite {
			f.t.Errorf("audit counts %v, report %+v", meta.Rewritten, report.Counts)
		}
	}
	for _, secret := range append(secrets, "enc:v1:", "encb:v1:") {
		if strings.Contains(text, secret) {
			f.t.Errorf("the audit row holds %q", secret)
		}
	}
}
