package application

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/wafio/wafio-cp-backend/internal/domain"
	"github.com/wafio/wafio-cp-backend/shared/email"
)

const expiryDay = 24 * time.Hour

// fakeExpiryStore keeps what the real one persists: the level mailed for each certificate stays
// with the candidate, so a second service over the same store is a restart.
type fakeExpiryStore struct {
	mu         sync.Mutex
	candidates []domain.ExpiryCandidate
	members    map[string][]ExpiryMember
	// lockHeld: another replica holds the lock.
	lockHeld  bool
	lockErr   error
	locks     int
	lists     int
	listErr   error
	memberErr error
}

func (s *fakeExpiryStore) TryExpiryLock(context.Context) (func(), bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.locks++
	if s.lockErr != nil {
		return func() {}, false, s.lockErr
	}
	if s.lockHeld {
		return func() {}, false, nil
	}
	s.lockHeld = true
	return func() { s.mu.Lock(); s.lockHeld = false; s.mu.Unlock() }, true, nil
}

func (s *fakeExpiryStore) ListExpiryCandidates(context.Context) ([]domain.ExpiryCandidate, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.lists++
	if s.listErr != nil {
		return nil, s.listErr
	}
	out := make([]domain.ExpiryCandidate, len(s.candidates))
	for i, c := range s.candidates {
		if c.NotifiedDays != nil {
			n := *c.NotifiedDays
			c.NotifiedDays = &n
		}
		out[i] = c
	}
	return out, nil
}

func (s *fakeExpiryStore) MarkExpiryNotified(_ context.Context, c domain.ExpiryCandidate, days int) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i, have := range s.candidates {
		if have.AppID == c.AppID && have.CertificateID == c.CertificateID && have.LeafSHA256 == c.LeafSHA256 {
			s.candidates[i].NotifiedDays = &days
			return true, nil
		}
	}
	return false, nil
}

func (s *fakeExpiryStore) Members(_ context.Context, projectID string) ([]ExpiryMember, error) {
	if s.memberErr != nil {
		return nil, s.memberErr
	}
	return s.members[projectID], nil
}

// notified is the level stored for the application, -1 for none.
func (s *fakeExpiryStore) notified(appID string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, c := range s.candidates {
		if c.AppID == appID && c.NotifiedDays != nil {
			return *c.NotifiedDays
		}
	}
	return -1
}

type expirySent struct{ to, subject, body string }

type fakeExpiryMail struct {
	mu      sync.Mutex
	host    string
	base    string
	stateEr error
	failFor map[string]bool
	sent    []expirySent
}

func (m *fakeExpiryMail) Current(context.Context) (MailState, error) {
	return MailState{Server: email.Config{Host: m.host}, BaseURL: m.base}, m.stateEr
}

func (m *fakeExpiryMail) Mailer() domain.Mailer { return expiryMailer{m} }

type expiryMailer struct{ m *fakeExpiryMail }

func (f expiryMailer) Send(to, subject, body string) error {
	f.m.mu.Lock()
	defer f.m.mu.Unlock()
	if f.m.failFor[to] || f.m.failFor["*"] {
		return errors.New("smtp refused")
	}
	f.m.sent = append(f.m.sent, expirySent{to, subject, body})
	return nil
}

func (m *fakeExpiryMail) take() []expirySent {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := m.sent
	m.sent = nil
	return out
}

type expiryRig struct {
	store *fakeExpiryStore
	mail  *fakeExpiryMail
	now   time.Time
}

// service returns a service over the rig, on the rig's clock. Calling it again is a restart.
func (r *expiryRig) service() *CertificateExpiry {
	return &CertificateExpiry{Store: r.store, Mail: r.mail, Now: func() time.Time { return r.now }}
}

// check runs one pass and returns what it mailed.
func (r *expiryRig) check(t *testing.T) []expirySent {
	t.Helper()
	r.service().Check(context.Background())
	return r.mail.take()
}

func (r *expiryRig) expiresIn(d time.Duration) { r.setAt(r.now.Add(d)) }

// setAt gives every candidate the expiry date t.
func (r *expiryRig) setAt(t time.Time) {
	for i := range r.store.candidates {
		r.store.candidates[i].NotAfter = t
	}
}

var rigStart = time.Date(2026, 11, 1, 9, 0, 0, 0, time.UTC)

func newExpiryRig(source string) *expiryRig {
	c := domain.ExpiryCandidate{
		ProjectID: "11111111-1111-4111-8111-111111111111", ProjectName: "Shop", AppID: "22222222-2222-4222-8222-222222222222",
		AppName: "storefront", Hosts: []string{"shop.example.com", "www.shop.example.com"}, Source: source,
		LeafSHA256: strings.Repeat("ab", 32), NotAfter: rigStart.Add(90 * expiryDay),
	}
	if source == domain.TLSSourceUploaded {
		c.CertificateID = "33333333-3333-4333-8333-333333333333"
	}
	return &expiryRig{
		store: &fakeExpiryStore{
			candidates: []domain.ExpiryCandidate{c},
			members: map[string][]ExpiryMember{c.ProjectID: {
				{Email: "owner@example.com", Role: "owner"},
				{Email: "dev@example.com", Role: "member"},
				{Email: "reader@example.com", Role: "viewer"},
			}},
		},
		mail: &fakeExpiryMail{host: "smtp.example.com", base: "https://dash.example.com"},
		now:  rigStart,
	}
}

func recipientsOf(mails []expirySent) string {
	var to []string
	for _, m := range mails {
		to = append(to, m.to)
	}
	return strings.Join(to, ",")
}

func TestExpiryLevel(t *testing.T) {
	for _, c := range []struct {
		source string
		left   time.Duration
		days   int
		due    bool
	}{
		{domain.TLSSourceUploaded, 31 * expiryDay, 0, false},
		{domain.TLSSourceUploaded, 30*expiryDay + time.Second, 0, false},
		{domain.TLSSourceUploaded, 30 * expiryDay, 30, true},
		{domain.TLSSourceUploaded, 29 * expiryDay, 30, true},
		{domain.TLSSourceUploaded, 14*expiryDay + time.Hour, 30, true},
		{domain.TLSSourceUploaded, 14 * expiryDay, 14, true},
		{domain.TLSSourceUploaded, 3*expiryDay + time.Hour, 14, true},
		{domain.TLSSourceUploaded, 3 * expiryDay, 3, true},
		{domain.TLSSourceUploaded, time.Hour, 3, true},
		{domain.TLSSourceUploaded, -time.Hour, 3, true},
		{domain.TLSSourceACME, 40 * expiryDay, 0, false},
		{domain.TLSSourceACME, 15 * expiryDay, 0, false},
		{domain.TLSSourceACME, 14 * expiryDay, 14, true},
		{domain.TLSSourceACME, 4 * expiryDay, 14, true},
		{domain.TLSSourceACME, 3 * expiryDay, 3, true},
		{domain.TLSSourceACME, -expiryDay, 3, true},
		{"", expiryDay, 0, false},
		{"other", expiryDay, 0, false},
	} {
		days, due := expiryLevel(c.source, c.left)
		if days != c.days || due != c.due {
			t.Errorf("%q with %s left: level %d due %v, want %d %v", c.source, c.left, days, due, c.days, c.due)
		}
	}
}

func TestUploadedCertificateIsMailedOncePerLevel(t *testing.T) {
	r := newExpiryRig(domain.TLSSourceUploaded)
	steps := []struct {
		left      time.Duration
		mails     int
		level     int
		inSubject string
	}{
		{40 * expiryDay, 0, -1, ""},
		{31 * expiryDay, 0, -1, ""},
		{29*expiryDay + time.Hour, 2, 30, "expires in 29 days"},
		{29*expiryDay + time.Hour, 0, 30, ""},
		{20 * expiryDay, 0, 30, ""},
		{13*expiryDay + time.Hour, 2, 14, "expires in 13 days"},
		{13*expiryDay + time.Hour, 0, 14, ""},
		{2*expiryDay + time.Hour, 2, 3, "expires in 2 days"},
		{12 * time.Hour, 0, 3, ""},
		{-expiryDay, 0, 3, ""},
	}
	notAfter := r.now.Add(90 * expiryDay)
	for _, s := range steps {
		r.now = notAfter.Add(-s.left)
		r.setAt(notAfter)
		got := r.check(t)
		if len(got) != s.mails {
			t.Fatalf("%s left: %d mails, want %d (%v)", s.left, len(got), s.mails, got)
		}
		if s.mails > 0 {
			if recipientsOf(got) != "dev@example.com,owner@example.com" {
				t.Errorf("%s left: mailed %s", s.left, recipientsOf(got))
			}
			if !strings.Contains(got[0].subject, s.inSubject) {
				t.Errorf("%s left: subject %q lacks %q", s.left, got[0].subject, s.inSubject)
			}
		}
		if n := r.store.notified(r.store.candidates[0].AppID); n != s.level {
			t.Errorf("%s left: stored level %d, want %d", s.left, n, s.level)
		}
	}
}

func TestACMECertificateIsMailedOnlyWhenRenewalIsLate(t *testing.T) {
	r := newExpiryRig(domain.TLSSourceACME)
	notAfter := r.now.Add(90 * expiryDay)
	for _, s := range []struct {
		left  time.Duration
		mails int
		level int
	}{
		{60 * expiryDay, 0, -1},
		{29 * expiryDay, 0, -1},
		{15 * expiryDay, 0, -1},
		{13*expiryDay + time.Hour, 2, 14},
		{13*expiryDay + time.Hour, 0, 14},
		{2*expiryDay + time.Hour, 2, 3},
		{expiryDay, 0, 3},
	} {
		r.now = notAfter.Add(-s.left)
		r.setAt(notAfter)
		if got := r.check(t); len(got) != s.mails {
			t.Fatalf("%s left: %d mails, want %d", s.left, len(got), s.mails)
		}
		if n := r.store.notified(r.store.candidates[0].AppID); n != s.level {
			t.Errorf("%s left: stored level %d, want %d", s.left, n, s.level)
		}
	}
}

// A pass after a long pause (or the first pass on a certificate that is already close) mails the
// level it is at now, not the ones it skipped.
func TestCertificateCloseToExpiryGetsOneMail(t *testing.T) {
	r := newExpiryRig(domain.TLSSourceUploaded)
	r.expiresIn(2*expiryDay + time.Hour)
	if got := r.check(t); len(got) != 2 {
		t.Fatalf("%d mails, want 2", len(got))
	}
	if got := r.check(t); len(got) != 0 {
		t.Fatalf("second pass mailed %d", len(got))
	}
	if n := r.store.notified(r.store.candidates[0].AppID); n != 3 {
		t.Errorf("stored level %d, want 3", n)
	}
}

func TestExpiredCertificateIsMailedOnceAsExpired(t *testing.T) {
	r := newExpiryRig(domain.TLSSourceUploaded)
	r.expiresIn(-2 * time.Hour)
	got := r.check(t)
	if len(got) != 2 || !strings.Contains(got[0].subject, "has expired") || !strings.Contains(got[0].body, "has expired") || !strings.Contains(got[0].body, "(expired)") {
		t.Fatalf("mails: %+v", got)
	}
	if again := r.check(t); len(again) != 0 {
		t.Fatalf("an expired certificate was mailed twice")
	}
}

func TestMailIsNotRepeatedAfterARestart(t *testing.T) {
	r := newExpiryRig(domain.TLSSourceUploaded)
	r.expiresIn(10 * expiryDay)
	if got := r.check(t); len(got) != 2 {
		t.Fatalf("first run mailed %d", len(got))
	}
	// A new service over the same store is a restart, a second replica or a pass after a crash.
	for i := 0; i < 3; i++ {
		if got := r.check(t); len(got) != 0 {
			t.Fatalf("restart %d mailed %d", i, len(got))
		}
	}
	// Later the next level is reached and is mailed once.
	r.now = r.now.Add(8 * expiryDay)
	if got := r.check(t); len(got) != 2 || !strings.Contains(got[0].subject, "expires in 1 day") && !strings.Contains(got[0].subject, "expires in 2 days") {
		t.Fatalf("next level: %+v", got)
	}
}

func TestNewCertificateStartsAgain(t *testing.T) {
	r := newExpiryRig(domain.TLSSourceUploaded)
	r.expiresIn(2 * expiryDay)
	if got := r.check(t); len(got) != 2 {
		t.Fatalf("mailed %d", len(got))
	}
	// The dashboard replaced the certificate: another id, another leaf, nothing mailed for it yet.
	c := r.store.candidates[0]
	c.CertificateID = "44444444-4444-4444-8444-444444444444"
	c.LeafSHA256 = strings.Repeat("cd", 32)
	c.NotAfter = r.now.Add(20 * expiryDay)
	c.NotifiedDays = nil
	r.store.candidates[0] = c
	if got := r.check(t); len(got) != 2 || !strings.Contains(got[0].subject, "expires in 20 days") {
		t.Fatalf("new certificate: %+v", got)
	}
	if n := r.store.notified(c.AppID); n != 30 {
		t.Errorf("stored level %d, want 30", n)
	}
}

func TestCertificateReplacedWhileMailingIsNotMarked(t *testing.T) {
	r := newExpiryRig(domain.TLSSourceUploaded)
	r.expiresIn(5 * expiryDay)
	svc := r.service()
	// The certificate is swapped after the list was read: the mark finds no such certificate.
	store := &replaceOnMark{fakeExpiryStore: r.store}
	svc.Store = store
	svc.Check(context.Background())
	if got := r.mail.take(); len(got) != 2 {
		t.Fatalf("mailed %d", len(got))
	}
	if n := r.store.notified(r.store.candidates[0].AppID); n != -1 {
		t.Errorf("the replacement was marked with level %d", n)
	}
}

// replaceOnMark swaps the certificate just before the mark is written.
type replaceOnMark struct{ *fakeExpiryStore }

func (s *replaceOnMark) MarkExpiryNotified(ctx context.Context, c domain.ExpiryCandidate, days int) (bool, error) {
	s.mu.Lock()
	s.candidates[0].CertificateID = "55555555-5555-4555-8555-555555555555"
	s.mu.Unlock()
	return s.fakeExpiryStore.MarkExpiryNotified(ctx, c, days)
}

func TestNoMailWithoutAMailServer(t *testing.T) {
	r := newExpiryRig(domain.TLSSourceUploaded)
	r.expiresIn(10 * expiryDay)
	r.mail.host = ""
	if got := r.check(t); len(got) != 0 {
		t.Fatalf("mailed %d without a mail server", len(got))
	}
	if n := r.store.notified(r.store.candidates[0].AppID); n != -1 {
		t.Fatalf("a warning nobody got was marked as sent (level %d)", n)
	}
	if r.store.lists != 0 {
		t.Errorf("the candidates were read without a mail server")
	}
	// The server is set later: the level that is due now goes out then.
	r.mail.host = "smtp.example.com"
	if got := r.check(t); len(got) != 2 {
		t.Fatalf("after the server was set: %d mails, want 2", len(got))
	}
}

func TestNoMailWhenTheMailSettingsAreUnreadable(t *testing.T) {
	r := newExpiryRig(domain.TLSSourceUploaded)
	r.expiresIn(10 * expiryDay)
	r.mail.stateEr = ErrMailSettingsUnavailable
	if got := r.check(t); len(got) != 0 || r.store.notified(r.store.candidates[0].AppID) != -1 {
		t.Fatalf("mailed %d, level %d", len(got), r.store.notified(r.store.candidates[0].AppID))
	}
}

func TestViewersAreNotMailed(t *testing.T) {
	r := newExpiryRig(domain.TLSSourceUploaded)
	r.expiresIn(10 * expiryDay)
	got := r.check(t)
	if recipientsOf(got) != "dev@example.com,owner@example.com" {
		t.Fatalf("mailed %s", recipientsOf(got))
	}

	// A project with viewers only has nobody to ask: nothing is mailed and nothing is marked, so a
	// member who joins later still hears about it.
	r2 := newExpiryRig(domain.TLSSourceUploaded)
	r2.expiresIn(10 * expiryDay)
	pid := r2.store.candidates[0].ProjectID
	r2.store.members[pid] = []ExpiryMember{{Email: "reader@example.com", Role: "viewer"}, {Email: "", Role: "owner"}}
	if got := r2.check(t); len(got) != 0 || r2.store.notified(r2.store.candidates[0].AppID) != -1 {
		t.Fatalf("mailed %d, level %d", len(got), r2.store.notified(r2.store.candidates[0].AppID))
	}
	r2.store.members[pid] = append(r2.store.members[pid], ExpiryMember{Email: "new@example.com", Role: "member"})
	if got := r2.check(t); recipientsOf(got) != "new@example.com" {
		t.Fatalf("after a member joined: %s", recipientsOf(got))
	}
}

func TestEachAddressIsMailedOnce(t *testing.T) {
	r := newExpiryRig(domain.TLSSourceUploaded)
	r.expiresIn(10 * expiryDay)
	pid := r.store.candidates[0].ProjectID
	r.store.members[pid] = []ExpiryMember{
		{Email: "Owner@Example.com", Role: "owner"}, {Email: " owner@example.com ", Role: "member"}, {Email: "a@example.com", Role: "member"},
	}
	if got := r.check(t); recipientsOf(got) != "Owner@Example.com,a@example.com" {
		t.Fatalf("mailed %s", recipientsOf(got))
	}
}

func TestNoMailWhileAnotherReplicaHoldsTheLock(t *testing.T) {
	r := newExpiryRig(domain.TLSSourceUploaded)
	r.expiresIn(10 * expiryDay)
	r.store.lockHeld = true
	if got := r.check(t); len(got) != 0 {
		t.Fatalf("mailed %d while another replica held the lock", len(got))
	}
	if r.store.lists != 0 || r.store.notified(r.store.candidates[0].AppID) != -1 {
		t.Errorf("the pass read or marked without the lock (lists %d)", r.store.lists)
	}
	r.store.lockHeld = false
	if got := r.check(t); len(got) != 2 {
		t.Fatalf("after the lock was free: %d mails", len(got))
	}
	if r.store.lockHeld {
		t.Error("the lock was not released")
	}
}

func TestPassIsSkippedWhenTheStoreFails(t *testing.T) {
	r := newExpiryRig(domain.TLSSourceUploaded)
	r.expiresIn(10 * expiryDay)
	r.store.lockErr = errors.New("db down")
	if got := r.check(t); len(got) != 0 {
		t.Fatalf("mailed %d after a lock error", len(got))
	}
	r.store.lockErr = nil
	r.store.listErr = errors.New("db down")
	if got := r.check(t); len(got) != 0 || r.store.lockHeld {
		t.Fatalf("mailed %d after a list error, lock held %v", len(got), r.store.lockHeld)
	}
	r.store.listErr = nil
	r.store.memberErr = errors.New("db down")
	if got := r.check(t); len(got) != 0 || r.store.notified(r.store.candidates[0].AppID) != -1 {
		t.Fatalf("mailed %d after a members error", len(got))
	}
	r.store.memberErr = nil
	if got := r.check(t); len(got) != 2 {
		t.Fatalf("after recovery: %d mails", len(got))
	}
}

func TestFailedDeliveryIsRetriedAndPartialIsRecorded(t *testing.T) {
	r := newExpiryRig(domain.TLSSourceUploaded)
	r.expiresIn(10 * expiryDay)
	r.mail.failFor = map[string]bool{"*": true}
	if got := r.check(t); len(got) != 0 || r.store.notified(r.store.candidates[0].AppID) != -1 {
		t.Fatalf("a mail nobody got was recorded")
	}
	// One address works: the level is recorded, the other address does not block it.
	r.mail.failFor = map[string]bool{"dev@example.com": true}
	if got := r.check(t); recipientsOf(got) != "owner@example.com" || r.store.notified(r.store.candidates[0].AppID) != 14 {
		t.Fatalf("partial delivery: %s, level %d", recipientsOf(got), r.store.notified(r.store.candidates[0].AppID))
	}
	r.mail.failFor = nil
	if got := r.check(t); len(got) != 0 {
		t.Fatalf("a recorded level was mailed again")
	}
}

func TestOnlyCandidatesWithAnExpiryAreChecked(t *testing.T) {
	r := newExpiryRig(domain.TLSSourceUploaded)
	r.expiresIn(10 * expiryDay)
	other := r.store.candidates[0]
	other.AppID, other.AppName, other.CertificateID = "66666666-6666-4666-8666-666666666666", "blog", "77777777-7777-4777-8777-777777777777"
	other.NotAfter = r.now.Add(200 * expiryDay)
	r.store.candidates = append(r.store.candidates, other)
	got := r.check(t)
	if len(got) != 2 || !strings.Contains(got[0].subject, "storefront") {
		t.Fatalf("mails: %+v", got)
	}
	if n := r.store.notified(other.AppID); n != -1 {
		t.Errorf("a certificate with 200 days left was marked with %d", n)
	}
}

func TestMailNamesWhatToDo(t *testing.T) {
	r := newExpiryRig(domain.TLSSourceUploaded)
	// 15:05 at +09:00 is 06:05 UTC.
	notAfter := time.Date(2026, 11, 11, 15, 5, 0, 0, time.FixedZone("far", 9*3600))
	r.now = notAfter.Add(-10*expiryDay - 5*time.Hour)
	r.setAt(notAfter)
	got := r.check(t)
	if len(got) != 2 {
		t.Fatalf("mailed %d", len(got))
	}
	m := got[0]
	for _, want := range []string{
		"Project: Shop", "Application: storefront", "Hosts: shop.example.com, www.shop.example.com",
		"Expires: 2026-11-11 06:05 UTC (in 10 days)", "Upload a new certificate",
		"https://dash.example.com/projects/11111111-1111-4111-8111-111111111111/apps/22222222-2222-4222-8222-222222222222",
	} {
		if !strings.Contains(m.body, want) {
			t.Errorf("body lacks %q:\n%s", want, m.body)
		}
	}
	if m.subject != "Wafio: the certificate of storefront expires in 10 days" {
		t.Errorf("subject %q", m.subject)
	}
	if strings.Contains(m.subject+m.body, "\u2014") {
		t.Error("an em dash in the mail")
	}

	acme := newExpiryRig(domain.TLSSourceACME)
	acme.expiresIn(5 * expiryDay)
	got = acme.check(t)
	if len(got) != 2 || !strings.Contains(got[0].body, "renewal is late") || !strings.Contains(got[0].body, "WAF agent") || strings.Contains(got[0].body, "Upload a new certificate") {
		t.Fatalf("ACME mail: %+v", got)
	}

	noLink := newExpiryRig(domain.TLSSourceUploaded)
	noLink.expiresIn(5 * expiryDay)
	noLink.mail.base = ""
	got = noLink.check(t)
	if len(got) != 2 || strings.Contains(got[0].body, "http") || strings.Contains(got[0].body, "/projects/") {
		t.Fatalf("mail without a base URL: %+v", got)
	}
}

func TestMailWithLessThanADayAndOneDay(t *testing.T) {
	for _, c := range []struct {
		left time.Duration
		want string
	}{
		{5 * time.Hour, "expires in less than a day"},
		{expiryDay + time.Hour, "expires in 1 day"},
	} {
		r := newExpiryRig(domain.TLSSourceUploaded)
		r.expiresIn(c.left)
		got := r.check(t)
		if len(got) != 2 || !strings.Contains(got[0].subject, c.want) {
			t.Errorf("%s left: %+v", c.left, got)
		}
	}
}

func TestLongHostListIsCut(t *testing.T) {
	r := newExpiryRig(domain.TLSSourceUploaded)
	r.expiresIn(5 * expiryDay)
	var hosts []string
	for i := 0; i < 25; i++ {
		hosts = append(hosts, fmt.Sprintf("h%02d.example.com", i))
	}
	r.store.candidates[0].Hosts = hosts
	got := r.check(t)
	if len(got) != 2 || !strings.Contains(got[0].body, "h09.example.com and 15 more") || strings.Contains(got[0].body, "h10.example.com") {
		t.Fatalf("host list: %+v", got)
	}
}

// Names are typed by users. A line break in one of them must not open a header or a line of the
// body, and the mailer's own check must still accept what is sent.
func TestNamesCannotInjectHeadersOrLines(t *testing.T) {
	r := newExpiryRig(domain.TLSSourceUploaded)
	r.expiresIn(5 * expiryDay)
	r.store.candidates[0].AppName = "shop\r\nBcc: evil@example.com\nX-Evil: 1\u2028more"
	r.store.candidates[0].ProjectName = "Shop\r\nBcc: evil@example.com"
	got := r.check(t)
	if len(got) != 2 {
		t.Fatalf("mailed %d", len(got))
	}
	for _, m := range got {
		if err := email.ValidateHeaderValue(m.subject); err != nil {
			t.Errorf("subject %q: %v", m.subject, err)
		}
		if strings.ContainsAny(m.subject, "\r\n\u2028") {
			t.Errorf("subject %q holds a line break", m.subject)
		}
		for _, line := range strings.Split(m.body, "\n") {
			if strings.HasPrefix(line, "Bcc:") || strings.HasPrefix(line, "X-Evil:") {
				t.Errorf("a name opened a line: %q", line)
			}
		}
		if strings.Contains(m.body, "\r") {
			t.Errorf("a carriage return in the body")
		}
	}

	// A long name is cut.
	r2 := newExpiryRig(domain.TLSSourceUploaded)
	r2.expiresIn(5 * expiryDay)
	r2.store.candidates[0].AppName = strings.Repeat("n", 500)
	if got := r2.check(t); len(got) != 2 || len(got[0].subject) > 200 {
		t.Fatalf("long name: %d mails, subject of %d bytes", len(got), len(got[0].subject))
	}
}

// The real mailer refuses a header with a line break; the subject built here never has one, so the
// check cannot be what stops the mail.
func TestSubjectPassesTheMailersHeaderCheck(t *testing.T) {
	for _, name := range []string{"plain", "a\rb", "a\nb", "a\x00b", "tab\there", "\u2029", ""} {
		c := domain.ExpiryCandidate{ProjectID: "p", AppID: "a", AppName: name, NotAfter: rigStart.Add(expiryDay), Source: domain.TLSSourceUploaded}
		subject, _ := expiryMail(c, rigStart, "")
		if err := email.ValidateHeaderValue(subject); err != nil {
			t.Errorf("%q: %v", name, err)
		}
	}
}

func TestRunChecksOnATimerAndStops(t *testing.T) {
	r := newExpiryRig(domain.TLSSourceUploaded)
	r.expiresIn(100 * expiryDay)
	svc := r.service()
	svc.Interval, svc.FirstDelay = 5*time.Millisecond, 5*time.Millisecond
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { svc.Run(ctx); close(done) }()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		r.store.mu.Lock()
		n := r.store.locks
		r.store.mu.Unlock()
		if n >= 3 {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop")
	}
	if r.store.locks < 3 {
		t.Fatalf("only %d passes", r.store.locks)
	}
}

func TestRunWaitsBeforeTheFirstPass(t *testing.T) {
	r := newExpiryRig(domain.TLSSourceUploaded)
	svc := r.service()
	svc.FirstDelay = time.Hour
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { svc.Run(ctx); close(done) }()
	time.Sleep(50 * time.Millisecond)
	cancel()
	<-done
	if r.store.locks != 0 {
		t.Fatalf("a pass ran before the first delay ended")
	}
}
