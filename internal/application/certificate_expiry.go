package application

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/wafio/wafio-cp-backend/internal/domain"
)

// Expiry warnings for the certificate an application serves in gateway mode. The owners and members
// of its project get one email for each warning level of each certificate, while a mail server is in
// force. The level that was mailed is stored with the certificate, so a restart or a second control
// plane does not repeat a mail, and a new certificate starts again from nothing.

const (
	defaultExpiryInterval = 6 * time.Hour
	// A control plane that has just started waits before its first pass, so that a restart loop does
	// not mail again and again while it comes up.
	defaultExpiryFirstDelay = time.Minute
)

// ExpiryMember is a member of a project as the warnings see it.
type ExpiryMember struct {
	Email string
	Role  string
}

// CertificateExpiryStore is what the warnings read and write.
type CertificateExpiryStore interface {
	// ListExpiryCandidates returns the certificate in use of every application in gateway mode.
	ListExpiryCandidates(ctx context.Context) ([]domain.ExpiryCandidate, error)
	// MarkExpiryNotified stores the level that was mailed. It reports false when the certificate is
	// no longer the one in use.
	MarkExpiryNotified(ctx context.Context, c domain.ExpiryCandidate, days int) (bool, error)
	// TryExpiryLock takes the lock that lets one control plane replica mail at a time; ok is false
	// while another one holds it.
	TryExpiryLock(ctx context.Context) (release func(), ok bool, err error)
	// Members lists the members of a project with their roles.
	Members(ctx context.Context, projectID string) ([]ExpiryMember, error)
}

// ExpiryMailSource is the live mail configuration (*MailSettings).
type ExpiryMailSource interface {
	Current(ctx context.Context) (MailState, error)
	Mailer() domain.Mailer
}

// CertificateExpiry is the loop that warns before a certificate expires.
type CertificateExpiry struct {
	Store CertificateExpiryStore
	Mail  ExpiryMailSource
	// Now is the clock (tests); nil = time.Now.
	Now func() time.Time
	// Interval between two passes (0 = 6 h) and FirstDelay before the first one (0 = 1 min).
	Interval   time.Duration
	FirstDelay time.Duration
}

func (s *CertificateExpiry) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

// Run checks until ctx ends.
func (s *CertificateExpiry) Run(ctx context.Context) {
	interval, first := s.Interval, s.FirstDelay
	if interval <= 0 {
		interval = defaultExpiryInterval
	}
	if first <= 0 {
		first = defaultExpiryFirstDelay
	}
	timer := time.NewTimer(first)
	defer timer.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			s.Check(ctx)
			timer.Reset(interval)
		}
	}
}

// Check is one pass: it mails what is due and stores what it mailed. It does nothing while another
// replica holds the lock, and nothing without a mail server, so that a warning is not marked as
// sent when nobody got it.
func (s *CertificateExpiry) Check(ctx context.Context) {
	release, ok, err := s.Store.TryExpiryLock(ctx)
	if err != nil {
		slog.Warn("certificate expiry: pass skipped", "err", err)
		return
	}
	if !ok {
		return
	}
	defer release()

	state, err := s.Mail.Current(ctx)
	if err != nil {
		slog.Warn("certificate expiry: mail settings unreadable; pass skipped", "err", err)
		return
	}
	if state.Server.Host == "" {
		return
	}
	candidates, err := s.Store.ListExpiryCandidates(ctx)
	if err != nil {
		slog.Warn("certificate expiry: pass skipped", "err", err)
		return
	}
	mailer := s.Mail.Mailer()
	now := s.now()
	recipients := map[string][]string{}
	for _, c := range candidates {
		if ctx.Err() != nil {
			return
		}
		level, due := domain.ExpiryLevel(c.Source, c.NotBefore, c.NotAfter, now)
		if !due || (c.NotifiedDays != nil && *c.NotifiedDays <= level) {
			continue
		}
		to, ok := recipients[c.ProjectID]
		if !ok {
			if to, err = s.recipients(ctx, c.ProjectID); err != nil {
				slog.Warn("certificate expiry: members unreadable", "project", c.ProjectID, "err", err)
				continue
			}
			recipients[c.ProjectID] = to
		}
		if len(to) == 0 {
			continue
		}
		subject, body := expiryMail(c, now, state.BaseURL)
		delivered := 0
		for _, addr := range to {
			if err := mailer.Send(addr, subject, body); err != nil {
				slog.Warn("certificate expiry: email failed", "app", c.AppID, "level", level, "err", err)
				continue
			}
			delivered++
		}
		if delivered == 0 {
			continue
		}
		marked, err := s.Store.MarkExpiryNotified(ctx, c, level)
		switch {
		case err != nil:
			slog.Warn("certificate expiry: mail not recorded", "app", c.AppID, "level", level, "err", err)
		case !marked:
			slog.Info("certificate expiry: certificate was replaced while mailing", "app", c.AppID)
		default:
			slog.Info("certificate expiry: warning mailed", "app", c.AppID, "level", level, "recipients", delivered)
		}
	}
}

// recipients are the addresses of the owners and members of a project, once each. A viewer reads the
// project and is not asked to act on it.
func (s *CertificateExpiry) recipients(ctx context.Context, projectID string) ([]string, error) {
	members, err := s.Store.Members(ctx, projectID)
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	var to []string
	for _, m := range members {
		addr := strings.TrimSpace(m.Email)
		if (m.Role != "owner" && m.Role != "member") || addr == "" || seen[strings.ToLower(addr)] {
			continue
		}
		seen[strings.ToLower(addr)] = true
		to = append(to, addr)
	}
	sort.Strings(to)
	return to, nil
}

// expiryMail writes the mail for a certificate. The project and application names come from users, so
// control characters and line breaks are replaced before a name reaches the subject or a line of the
// body; the mailer refuses a header that still holds one.
func expiryMail(c domain.ExpiryCandidate, now time.Time, baseURL string) (subject, body string) {
	expired := !c.NotAfter.After(now)
	app := oneLine(c.AppName)
	when := "expired"
	if expired {
		subject = "Wafio: the certificate of " + app + " has expired"
	} else {
		when = "in " + daysText(domain.DaysLeft(c.NotAfter, now))
		subject = "Wafio: the certificate of " + app + " expires " + when
	}

	var b strings.Builder
	if expired {
		b.WriteString("The certificate that WAFio serves for an application of your project has expired.\n\n")
	} else {
		b.WriteString("The certificate that WAFio serves for an application of your project expires soon.\n\n")
	}
	fmt.Fprintf(&b, "Project: %s\n", oneLine(c.ProjectName))
	fmt.Fprintf(&b, "Application: %s\n", oneLine(c.AppName))
	// One host to a line: a mail line may not pass 998 bytes, and a project can name 100 hosts.
	b.WriteString("Hosts:\n")
	for _, h := range c.Hosts {
		b.WriteString("  " + singleLine(h) + "\n")
	}
	if len(c.Hosts) == 0 {
		b.WriteString("  none\n")
	}
	fmt.Fprintf(&b, "Expires: %s (%s)\n\n", c.NotAfter.UTC().Format("2006-01-02 15:04 UTC"), when)
	if c.Source == domain.TLSSourceACME {
		b.WriteString("The agent renews an ACME certificate well before it expires, so a warning now means that the renewal is late. " +
			"Check the certificate status of the application, and check that the WAF agent is running and can reach the certificate authority.\n")
	} else {
		b.WriteString("Upload a new certificate for this application before that date. Visitors get a certificate error once it has expired.\n")
	}
	if baseURL != "" {
		b.WriteString("\nOpen the application:\n" + baseURL + "/projects/" + c.ProjectID + "/apps/" + c.AppID + "\n")
	}
	b.WriteString("\nThis email is sent once for each warning level of a certificate.\n")
	return subject, b.String()
}

// daysText writes the whole days left as the dashboard counts them (domain.DaysLeft).
func daysText(days int) string {
	switch days {
	case 0:
		return "less than a day"
	case 1:
		return "1 day"
	default:
		return fmt.Sprintf("%d days", days)
	}
}

// singleLine keeps text on its line: control characters and line separators become a space, and the
// invisible format characters (zero width, bidirectional overrides) are dropped, so a name cannot
// hide what it is or reorder the text around it.
func singleLine(s string) string {
	return strings.TrimSpace(strings.Map(func(r rune) rune {
		switch {
		case unicode.IsControl(r) || r == '\u2028' || r == '\u2029':
			return ' '
		case unicode.Is(unicode.Cf, r):
			return -1
		}
		return r
	}, s))
}

// oneLine is a user's name for one line: single, and at most 80 characters.
func oneLine(s string) string {
	s = singleLine(s)
	if r := []rune(s); len(r) > 80 {
		s = string(r[:80]) + "..."
	}
	return s
}
