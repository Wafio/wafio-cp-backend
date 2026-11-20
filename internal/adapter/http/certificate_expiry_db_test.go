package httpadapter

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/wafio/wafio-cp-backend/internal/application"
	"github.com/wafio/wafio-cp-backend/internal/config"
	"github.com/wafio/wafio-cp-backend/internal/domain"
	"github.com/wafio/wafio-cp-backend/internal/testutil/dbfixture"
)

// onlyProject keeps a pass to the project of the test: the database is shared with tests that run
// beside this one, and a pass reads every project.
type onlyProject struct {
	certificateExpiryStore
	project string
}

func (s onlyProject) ListExpiryCandidates(ctx context.Context) ([]domain.ExpiryCandidate, error) {
	all, err := s.certificateExpiryStore.ListExpiryCandidates(ctx)
	var mine []domain.ExpiryCandidate
	for _, c := range all {
		if c.ProjectID == s.project {
			mine = append(mine, c)
		}
	}
	return mine, err
}

func (s *mailSink) count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.msgs)
}

// The warnings against a real database and a mail server: the owner and the member of a project get
// one mail for a certificate that expires in ten days and the viewer none, a second pass and a second
// service mail nothing, a pass under another replica's lock mails nothing, and a replaced certificate
// is mailed again from its own level.
func TestDBCertificateExpiryMailsOwnersAndMembersOnce(t *testing.T) {
	f := newMailFixture(t)
	sink := newMailSink(t)
	f.saveSink(t, sink)
	ctx := context.Background()

	project, ownerID := dbfixture.SeedProject(t, f.repo.DB)
	addUser := func(role string) (id, email string) {
		email = "expiry-" + role + "-" + uuid.NewString() + "@mail.test"
		u, err := f.repo.User.CreateWithRole(ctx, email, "fixture-hash", role, "user")
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = f.repo.User.Delete(context.Background(), u.ID) })
		return u.ID, email
	}
	ownerEmail := ""
	if err := f.repo.DB.QueryRow(ctx, `SELECT email FROM users WHERE id = $1`, ownerID).Scan(&ownerEmail); err != nil {
		t.Fatal(err)
	}
	memberID, memberEmail := addUser("member")
	viewerID, viewerEmail := addUser("viewer")
	for id, role := range map[string]string{ownerID: "owner", memberID: "member", viewerID: "viewer"} {
		if err := f.repo.ProjectMember.Add(ctx, project, id, role); err != nil {
			t.Fatal(err)
		}
	}

	var appID string
	if err := f.repo.DB.QueryRow(ctx, `INSERT INTO apps (project_id, name) VALUES ($1, $2) RETURNING id`, project, "storefront-"+uuid.NewString()[:6]).Scan(&appID); err != nil {
		t.Fatal(err)
	}
	var appName string
	if err := f.repo.DB.QueryRow(ctx, `SELECT name FROM apps WHERE id = $1`, appID).Scan(&appName); err != nil {
		t.Fatal(err)
	}
	install := func(left time.Duration) string {
		t.Helper()
		id := uuid.NewString()
		if _, err := f.repo.DB.Exec(ctx, `UPDATE app_certificates SET replaced_at = NOW() WHERE app_id = $1 AND replaced_at IS NULL`, appID); err != nil {
			t.Fatal(err)
		}
		if _, err := f.repo.DB.Exec(ctx, `INSERT INTO app_certificates (id, project_id, app_id, chain_pem, leaf_sha256, names, issuer, key_type, not_before, not_after, trusted)
			VALUES ($1, $2, $3, 'chain', $4, ARRAY['shop.example.test'], 'Test CA', 'ecdsa-p256', NOW() - interval '30 days', $5, TRUE)`,
			id, project, appID, strings.ReplaceAll(id, "-", "")+strings.ReplaceAll(id, "-", ""), time.Now().Add(left)); err != nil {
			t.Fatal(err)
		}
		if _, err := f.repo.DB.Exec(ctx, `UPDATE apps SET tls_mode = 'gateway', tls_source = 'uploaded', tls_hosts = ARRAY['shop.example.test'], tls_certificate_id = $2 WHERE id = $1`, appID, id); err != nil {
			t.Fatal(err)
		}
		return id
	}
	install(10*24*time.Hour + time.Hour)

	// The saved settings apply: the server configuration sets no mail server.
	mail := newMailSettings(&config.Config{}, f.repo)
	svc := func() *application.CertificateExpiry {
		return &application.CertificateExpiry{
			Store: onlyProject{certificateExpiryStore{TLSRepo: f.repo.TLS, members: f.repo.ProjectMember}, project},
			Mail:  mail,
		}
	}

	svc().Check(ctx)
	link := "https://dash.example.test/projects/" + project + "/apps/" + appID
	for _, addr := range []string{ownerEmail, memberEmail} {
		data := sink.await(t, addr, "expires in 10 days")
		for _, want := range []string{"Application: " + appName, "Hosts:\n  shop.example.test\n", "Upload a new certificate", link} {
			if !strings.Contains(data, want) {
				t.Errorf("mail to %s lacks %q:\n%s", addr, want, data)
			}
		}
	}
	level := func() *int {
		var n *int
		if err := f.repo.DB.QueryRow(ctx, `SELECT expiry_notified_days FROM app_certificates WHERE app_id = $1 AND replaced_at IS NULL`, appID).Scan(&n); err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := level(); n == nil || *n != 14 {
		t.Fatalf("stored level %v, want 14", n)
	}
	if sink.count() != 2 {
		t.Fatalf("%d mails after the first pass, want 2", sink.count())
	}

	// The same pass again, and a restart (a new service over the same database): nothing more.
	svc().Check(ctx)
	svc().Check(ctx)
	if sink.count() != 2 {
		t.Fatalf("%d mails after two more passes, want 2", sink.count())
	}

	// Another replica holds the lock: the next level is due, and nobody mails it.
	if _, err := f.repo.DB.Exec(ctx, `UPDATE app_certificates SET not_after = NOW() + interval '2 days' WHERE app_id = $1 AND replaced_at IS NULL`, appID); err != nil {
		t.Fatal(err)
	}
	release, ok, err := f.repo.TLS.TryExpiryLock(ctx)
	if err != nil || !ok {
		t.Fatalf("lock: %v %v", ok, err)
	}
	svc().Check(ctx)
	if sink.count() != 2 || *level() != 14 {
		t.Fatalf("a pass under another replica's lock mailed (%d mails, level %d)", sink.count(), *level())
	}
	release()
	svc().Check(ctx)
	sink.await(t, ownerEmail, "expires in 1 day")
	if n := level(); n == nil || *n != 3 || sink.count() != 4 {
		t.Fatalf("after the lock was free: level %v, %d mails", n, sink.count())
	}

	// A replaced certificate starts again.
	install(20*24*time.Hour + time.Hour)
	if n := level(); n != nil {
		t.Fatalf("a new certificate carries level %d", *n)
	}
	svc().Check(ctx)
	sink.await(t, memberEmail, "expires in 20 days")
	if n := level(); n == nil || *n != 30 || sink.count() != 6 {
		t.Fatalf("after the replace: level %v, %d mails", n, sink.count())
	}

	// The viewer got none of it.
	sink.mu.Lock()
	defer sink.mu.Unlock()
	for _, m := range sink.msgs {
		if m.rcpt == viewerEmail {
			t.Errorf("the viewer was mailed:\n%s", m.data)
		}
	}
}
