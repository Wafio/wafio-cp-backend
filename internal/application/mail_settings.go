package application

// MailSettings is the control plane's email configuration, read live: the
// server configuration (config.yaml / WAFIO_*) where it sets a value, else
// what a system administrator saved under Administration › Email (SMTP)
// (system_settings key "smtp_settings"). Every mail path — invitations,
// password recovery, its change notice, the test email — asks Current per
// send; a short cache is dropped on every save.
//
// Precedence:
//   - A non-empty smtp.host in the server configuration makes the whole mail
//     server (host, port, security, username, password, sender) config-
//     managed: those values apply and the saved ones are ignored.
//   - A non-empty server.base_url makes the dashboard base URL config-managed.
//   - Otherwise the saved values apply; unset ones fall back to defaults
//     (port by security mode, security "auto").
//
// The SMTP password is stored encrypted with the shared otp.Encryptor and a
// purpose prefix, never in plain text, and never returned by View.

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode"

	"github.com/wafio/wafio-cp-backend/internal/domain"
	"github.com/wafio/wafio-cp-backend/internal/otp"
	"github.com/wafio/wafio-cp-backend/shared/email"
)

const (
	mailSettingsKey     = "smtp_settings"
	mailPasswordPurpose = "wafio:smtp-password:"
	// mailSettingsTTL bounds how long a read is reused; saves drop it at once.
	mailSettingsTTL = 30 * time.Second

	maxMailHost     = 253
	maxMailUsername = 256
	maxMailPassword = 1024
	maxMailAddress  = 254
	maxMailFromName = 128
)

// Security modes as stored and shown. email.Config.Mode gets "ssl" for TLS.
const (
	MailSecurityAuto     = "auto"     // by port: 465 TLS, 587/2525 STARTTLS, else STARTTLS when offered
	MailSecuritySTARTTLS = "starttls" // STARTTLS required
	MailSecurityTLS      = "tls"      // implicit TLS (SMTPS)
	MailSecurityNone     = "none"     // no TLS required (STARTTLS used when offered)
)

// Where a mail setting comes from.
const (
	MailSourceConfig  = "config"  // config.yaml / WAFIO_*: read-only in the dashboard
	MailSourceSaved   = "saved"   // saved by an administrator
	MailSourceDefault = "default" // not set, a default applies
	MailSourceNone    = "none"    // not set, nothing applies
)

var (
	ErrMailSettingsUnavailable = errors.New("mail settings storage unavailable")
	ErrMailSettingsManaged     = errors.New("mail setting is managed by the server configuration")
	ErrMailNotConfigured       = errors.New("no mail server configured")
)

// MailSettingsInvalid is a rejected value; Message is safe to show.
type MailSettingsInvalid struct {
	Field   string
	Message string
}

func (e *MailSettingsInvalid) Error() string { return e.Field + ": " + e.Message }

// MailSettingsManaged names a setting the request tried to change although
// the server configuration sets it.
type MailSettingsManaged struct{ Field string }

func (e *MailSettingsManaged) Error() string {
	return e.Field + " is managed by the server configuration"
}
func (e *MailSettingsManaged) Is(target error) bool {
	return target == ErrMailSettingsManaged
}

// MailServerConfig is the server configuration's mail block and base URL,
// read at boot (cfg.SMTP, cfg.Server.BaseURL).
type MailServerConfig struct {
	Host       string
	Port       int
	Encryption string
	Username   string
	Password   string
	From       string
	BaseURL    string
}

// MailSettingsStore persists JSON settings (repository.SystemSettingsRepo).
type MailSettingsStore interface {
	GetJSON(context.Context, string, any) error
	SetJSON(context.Context, string, any) error
}

// MailSettings serves the effective mail configuration. Store and Crypto may
// be nil (no saved settings; saving refused).
type MailSettings struct {
	Store  MailSettingsStore
	Crypto *otp.Encryptor
	Server MailServerConfig
	// Timeout of one delivery; 0 = email.DefaultTimeout (30 s).
	Timeout time.Duration
	// Now is the clock (tests); nil = time.Now.
	Now func() time.Time

	mu     sync.Mutex
	gen    uint64
	cached *mailCache
}

type mailCache struct {
	state MailState
	at    time.Time
}

type mailSettingsRecord struct {
	Host               string `json:"host,omitempty"`
	Port               int    `json:"port,omitempty"`
	Security           string `json:"security,omitempty"`
	Username           string `json:"username,omitempty"`
	PasswordCiphertext string `json:"password_ciphertext,omitempty"`
	FromAddress        string `json:"from_address,omitempty"`
	FromName           string `json:"from_name,omitempty"`
	BaseURL            string `json:"base_url,omitempty"`
}

// MailState is the mail configuration in force.
type MailState struct {
	// Server is the mail server; Host "" = none.
	Server email.Config
	// BaseURL is the dashboard URL for links in emails: an absolute http(s)
	// URL without a trailing slash, "" when unset or invalid. It never comes
	// from a request's Host header.
	BaseURL string
	// BaseURLProblem says why BaseURL is "" although one is set.
	BaseURLProblem string
	// LinkBase is the base of invitation links: BaseURL, else a configured
	// value as written (older installs), else "" (relative links).
	LinkBase string

	record   mailSettingsRecord
	password bool // a saved password exists (decrypted fine)
}

// MailSettingsView is GET /api/admin/smtp-settings: effective values and
// where each comes from. It never carries the password.
type MailSettingsView struct {
	Host        string            `json:"host"`
	Port        int               `json:"port"`
	Security    string            `json:"security"`
	Username    string            `json:"username"`
	PasswordSet bool              `json:"password_set"`
	FromAddress string            `json:"from_address"`
	FromName    string            `json:"from_name"`
	BaseURL     string            `json:"base_url"`
	Sources     map[string]string `json:"sources"`
	// SMTPManaged: smtp.host is set in the server configuration, so every
	// mail server field is read-only here.
	SMTPManaged bool `json:"smtp_managed_by_config"`
	// BaseURLManaged: server.base_url is set in the server configuration.
	BaseURLManaged bool `json:"base_url_managed_by_config"`
	// Editable: storage and encryption are available for saving.
	Editable bool `json:"editable"`
	// MailConfigured: a mail server is in force.
	MailConfigured bool `json:"mail_configured"`
	// RecoveryAvailable: password recovery by email is offered (a mail
	// server and a valid base URL).
	RecoveryAvailable bool   `json:"recovery_available"`
	BaseURLProblem    string `json:"base_url_problem,omitempty"`
}

// MailSettingsUpdate is a partial update: nil = keep. An empty Password
// keeps the saved one; ClearPassword removes it.
type MailSettingsUpdate struct {
	Host          *string `json:"host"`
	Port          *int    `json:"port"`
	Security      *string `json:"security"`
	Username      *string `json:"username"`
	Password      *string `json:"password"`
	ClearPassword bool    `json:"clear_password"`
	FromAddress   *string `json:"from_address"`
	FromName      *string `json:"from_name"`
	BaseURL       *string `json:"base_url"`
}

func (s *MailSettings) now() time.Time {
	if s.Now != nil {
		return s.Now()
	}
	return time.Now()
}

func (s *MailSettings) smtpManaged() bool { return strings.TrimSpace(s.Server.Host) != "" }
func (s *MailSettings) baseManaged() bool { return strings.TrimSpace(s.Server.BaseURL) != "" }

// Invalidate drops the cached state; the next read loads it again.
func (s *MailSettings) Invalidate() {
	s.mu.Lock()
	s.gen++
	s.cached = nil
	s.mu.Unlock()
}

// Current returns the mail configuration in force, from a cache of at most
// 30 seconds that every save drops. On a storage error it returns the server
// configuration's part and the error.
func (s *MailSettings) Current(ctx context.Context) (MailState, error) {
	if s.smtpManaged() && s.baseManaged() {
		// The server configuration sets everything; saved values are unused.
		return s.compute(mailSettingsRecord{}, ""), nil
	}
	s.mu.Lock()
	if c := s.cached; c != nil && s.now().Sub(c.at) < mailSettingsTTL {
		st := c.state
		s.mu.Unlock()
		return st, nil
	}
	gen := s.gen
	s.mu.Unlock()

	rec, password, err := s.load(ctx)
	if err != nil {
		return s.compute(mailSettingsRecord{}, ""), err
	}
	st := s.compute(rec, password)
	s.mu.Lock()
	if s.gen == gen { // no save since the read began
		s.cached = &mailCache{state: st, at: s.now()}
	}
	s.mu.Unlock()
	return st, nil
}

// load reads the saved record and decrypts its password. A password that
// is not a ciphertext of this feature, or does not decrypt, is an error:
// the settings are never used half-read.
func (s *MailSettings) load(ctx context.Context) (mailSettingsRecord, string, error) {
	var rec mailSettingsRecord
	if s == nil || s.Store == nil {
		return rec, "", nil
	}
	if err := s.Store.GetJSON(ctx, mailSettingsKey, &rec); err != nil {
		return mailSettingsRecord{}, "", ErrMailSettingsUnavailable
	}
	if rec.PasswordCiphertext == "" {
		return rec, "", nil
	}
	// The shared encryptor accepts legacy plaintext for TOTP; this never does.
	if s.Crypto == nil || !strings.HasPrefix(rec.PasswordCiphertext, "enc:v1:") {
		return mailSettingsRecord{}, "", ErrMailSettingsUnavailable
	}
	value, err := s.Crypto.Decrypt(rec.PasswordCiphertext)
	if err != nil || !strings.HasPrefix(value, mailPasswordPurpose) {
		return mailSettingsRecord{}, "", ErrMailSettingsUnavailable
	}
	return rec, strings.TrimPrefix(value, mailPasswordPurpose), nil
}

func (s *MailSettings) compute(rec mailSettingsRecord, password string) MailState {
	st := MailState{record: rec, password: rec.PasswordCiphertext != ""}
	switch {
	case s.smtpManaged():
		st.Server = email.Config{
			Host: strings.TrimSpace(s.Server.Host), Port: mailPort(s.Server.Port, securityOfConfig(s.Server.Encryption)), Mode: s.Server.Encryption,
			Username: s.Server.Username, Password: s.Server.Password, From: s.Server.From,
		}
	case rec.Host != "":
		st.Server = email.Config{
			Host: rec.Host, Port: mailPort(rec.Port, rec.Security), Mode: emailMode(rec.Security),
			Username: rec.Username, Password: password, From: formatFrom(rec.FromName, rec.FromAddress),
		}
	}
	st.Server.Timeout = s.Timeout
	raw := rec.BaseURL
	if s.baseManaged() {
		raw = s.Server.BaseURL
	}
	if raw = strings.TrimSpace(raw); raw != "" {
		if base, err := NormalizeRecoveryBaseURL(raw); err == nil {
			st.BaseURL, st.LinkBase = base, base
		} else {
			st.BaseURLProblem = err.Error()
			st.LinkBase = strings.TrimRight(raw, "/")
		}
	}
	return st
}

// mailPort is the saved port, else the default of the security mode.
func mailPort(port int, security string) int {
	if port > 0 {
		return port
	}
	if security == MailSecurityTLS {
		return 465
	}
	return 587
}

func emailMode(security string) string {
	switch security {
	case MailSecurityTLS:
		return "ssl"
	case MailSecuritySTARTTLS, MailSecurityNone:
		return security
	}
	return "auto"
}

// securityOfConfig maps smtp.encryption to the four modes shown.
func securityOfConfig(enc string) string {
	switch strings.ToLower(strings.TrimSpace(enc)) {
	case "", "auto":
		return MailSecurityAuto
	case "ssl", "smtps", "tls":
		return MailSecurityTLS
	case "starttls":
		return MailSecuritySTARTTLS
	case "none", "plain":
		return MailSecurityNone
	}
	return enc
}

func formatFrom(name, address string) string {
	if address == "" {
		return ""
	}
	if name == "" {
		return address
	}
	// Quotes or RFC 2047-encodes the name as needed.
	return (&mail.Address{Name: name, Address: address}).String()
}

// View reports the effective settings and their sources, without the
// password.
func (s *MailSettings) View(ctx context.Context) (MailSettingsView, error) {
	st, err := s.Current(ctx)
	if err != nil {
		return MailSettingsView{}, err
	}
	rec := st.record
	v := MailSettingsView{
		Sources:        map[string]string{},
		SMTPManaged:    s.smtpManaged(),
		BaseURLManaged: s.baseManaged(),
		Editable:       s.Store != nil && s.Crypto != nil,
		MailConfigured: st.Server.Host != "",
		BaseURLProblem: st.BaseURLProblem,
	}
	v.RecoveryAvailable = v.MailConfigured && st.BaseURL != ""
	saved := func(field string, set bool) {
		if set {
			v.Sources[field] = MailSourceSaved
		} else {
			v.Sources[field] = MailSourceNone
		}
	}
	if v.SMTPManaged {
		v.Host, v.Port, v.Username = st.Server.Host, st.Server.Port, st.Server.Username
		v.Security = securityOfConfig(s.Server.Encryption)
		v.PasswordSet = s.Server.Password != ""
		if a, err := mail.ParseAddress(s.Server.From); err == nil {
			v.FromAddress, v.FromName = a.Address, a.Name
		} else {
			v.FromAddress = s.Server.From
		}
		for _, f := range []string{"host", "port", "security", "username", "password", "from_address", "from_name"} {
			v.Sources[f] = MailSourceConfig
		}
	} else {
		v.Host, v.Username, v.FromAddress, v.FromName = rec.Host, rec.Username, rec.FromAddress, rec.FromName
		v.PasswordSet = st.password
		v.Security = rec.Security
		v.Sources["security"] = MailSourceSaved
		if v.Security == "" {
			v.Security, v.Sources["security"] = MailSecurityAuto, MailSourceDefault
		}
		v.Port = mailPort(rec.Port, v.Security)
		v.Sources["port"] = MailSourceSaved
		if rec.Port == 0 {
			v.Sources["port"] = MailSourceDefault
		}
		saved("host", rec.Host != "")
		saved("username", rec.Username != "")
		saved("password", st.password)
		saved("from_address", rec.FromAddress != "")
		saved("from_name", rec.FromName != "")
	}
	if v.BaseURLManaged {
		v.BaseURL = strings.TrimSpace(s.Server.BaseURL)
		v.Sources["base_url"] = MailSourceConfig
	} else {
		v.BaseURL = rec.BaseURL
		saved("base_url", rec.BaseURL != "")
	}
	return v, nil
}

func (s *MailSettings) writable() error {
	if s == nil || s.Store == nil || s.Crypto == nil {
		return ErrMailSettingsUnavailable
	}
	return nil
}

var mailHostname = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$`)

func invalid(field, msg string) error { return &MailSettingsInvalid{Field: field, Message: msg} }

// plainText rejects control characters (header and protocol injection).
func plainText(v string) bool {
	return strings.IndexFunc(v, unicode.IsControl) < 0
}

// Password outcomes of an update, as audited (never the value).
const (
	MailPasswordChanged = "changed"
	MailPasswordCleared = "cleared"
)

// MailSettingsChange is what an Update changed, for the audit trail. It
// never carries the password: Password is "", "changed" or "cleared", and
// PasswordClearedBy names the fields whose change cleared it automatically.
type MailSettingsChange struct {
	// Fields lists the changed settings in a fixed order (password last).
	Fields []string
	// Values holds the new value of every changed non-secret field.
	Values map[string]any
	// Password is MailPasswordChanged, MailPasswordCleared or "".
	Password string
	// PasswordClearedBy is set when the password was cleared because the
	// host and/or username changed without a new password ("host",
	// "username", "host and username").
	PasswordClearedBy string
}

// AuditDetails is the change as audit details: "fields" (the changed
// names), the new non-secret values, and for the password only its
// outcome ("changed", "cleared", "cleared (host changed)").
func (c MailSettingsChange) AuditDetails() map[string]any {
	d := map[string]any{"fields": append([]string{}, c.Fields...)}
	for k, v := range c.Values {
		d[k] = v
	}
	switch {
	case c.Password == MailPasswordCleared && c.PasswordClearedBy != "":
		d["password"] = MailPasswordCleared + " (" + c.PasswordClearedBy + " changed)"
	case c.Password != "":
		d["password"] = c.Password
	}
	return d
}

func diffMailRecords(old, rec mailSettingsRecord, passwordSent bool, clearedBy string) MailSettingsChange {
	ch := MailSettingsChange{Values: map[string]any{}}
	add := func(name string, changed bool, value any) {
		if changed {
			ch.Fields = append(ch.Fields, name)
			ch.Values[name] = value
		}
	}
	add("host", old.Host != rec.Host, rec.Host)
	add("port", old.Port != rec.Port, rec.Port)
	add("security", old.Security != rec.Security, rec.Security)
	add("username", old.Username != rec.Username, rec.Username)
	add("from_address", old.FromAddress != rec.FromAddress, rec.FromAddress)
	add("from_name", old.FromName != rec.FromName, rec.FromName)
	add("base_url", old.BaseURL != rec.BaseURL, rec.BaseURL)
	switch {
	case passwordSent:
		ch.Password = MailPasswordChanged
	case old.PasswordCiphertext != "" && rec.PasswordCiphertext == "":
		ch.Password = MailPasswordCleared
		ch.PasswordClearedBy = clearedBy
	}
	if ch.Password != "" {
		ch.Fields = append(ch.Fields, "password")
	}
	return ch
}

// Update applies a partial update to the saved settings and drops the
// cache, and reports what changed. Changing a config-managed setting is
// refused (MailSettingsManaged).
//
// The password is bound to the server and account it was entered for: an
// update that changes the host or the username (normalized; re-sending the
// stored value is no change) without a new password clears the saved one,
// so a changed host never receives it. A security downgrade on the same
// host keeps it: net/smtp's PlainAuth (used by shared/email) refuses to
// send it over an unencrypted connection to anything but localhost.
func (s *MailSettings) Update(ctx context.Context, u MailSettingsUpdate) (MailSettingsChange, error) {
	var ch MailSettingsChange
	if err := s.update(ctx, u, &ch); err != nil {
		return MailSettingsChange{}, err
	}
	return ch, nil
}

func (s *MailSettings) update(ctx context.Context, u MailSettingsUpdate, change *MailSettingsChange) error {
	if err := s.writable(); err != nil {
		return err
	}
	smtpFields := []struct {
		name string
		set  bool
	}{
		{"host", u.Host != nil}, {"port", u.Port != nil}, {"security", u.Security != nil},
		{"username", u.Username != nil}, {"password", (u.Password != nil && *u.Password != "") || u.ClearPassword},
		{"from_address", u.FromAddress != nil}, {"from_name", u.FromName != nil},
	}
	touchesSMTP := false
	for _, f := range smtpFields {
		if f.set {
			touchesSMTP = true
			if s.smtpManaged() {
				return &MailSettingsManaged{Field: f.name}
			}
		}
	}
	if u.BaseURL != nil && s.baseManaged() {
		return &MailSettingsManaged{Field: "base_url"}
	}

	var rec mailSettingsRecord
	if err := s.Store.GetJSON(ctx, mailSettingsKey, &rec); err != nil {
		return ErrMailSettingsUnavailable
	}
	old := rec
	if u.Host != nil {
		h := strings.ToLower(strings.TrimSpace(*u.Host))
		if h != "" && (len(h) > maxMailHost || (net.ParseIP(h) == nil && !mailHostname.MatchString(h))) {
			return invalid("host", "Enter a host name or an IP address.")
		}
		rec.Host = h
	}
	if u.Port != nil {
		if *u.Port < 0 || *u.Port > 65535 {
			return invalid("port", "Enter a port from 1 to 65535, or leave it empty for the default.")
		}
		rec.Port = *u.Port
	}
	if u.Security != nil {
		sec := strings.ToLower(strings.TrimSpace(*u.Security))
		switch sec {
		case "", MailSecurityAuto:
			sec = ""
		case MailSecuritySTARTTLS, MailSecurityTLS, MailSecurityNone:
		default:
			return invalid("security", "Choose auto, starttls, tls or none.")
		}
		rec.Security = sec
	}
	if u.Username != nil {
		name := strings.TrimSpace(*u.Username)
		if len(name) > maxMailUsername || !plainText(name) {
			return invalid("username", "The username can have at most 256 characters and no control characters.")
		}
		rec.Username = name
	}
	passwordSent := u.Password != nil && *u.Password != ""
	// A changed host or account without a new password must not inherit
	// the saved one (it was entered for the old server and account).
	clearedBy := ""
	switch hostChanged, userChanged := rec.Host != old.Host, rec.Username != old.Username; {
	case hostChanged && userChanged:
		clearedBy = "host and username"
	case hostChanged:
		clearedBy = "host"
	case userChanged:
		clearedBy = "username"
	}
	switch {
	case u.ClearPassword && passwordSent:
		return invalid("password", "Send a new password or clear_password, not both.")
	case u.ClearPassword:
		rec.PasswordCiphertext = ""
		clearedBy = ""
	case !passwordSent && clearedBy != "":
		rec.PasswordCiphertext = ""
	case passwordSent:
		pw := *u.Password
		if len(pw) > maxMailPassword || !plainText(pw) {
			return invalid("password", "The password can have at most 1024 bytes and no control characters.")
		}
		enc, err := s.Crypto.Encrypt(mailPasswordPurpose + pw)
		if err != nil {
			return ErrMailSettingsUnavailable
		}
		rec.PasswordCiphertext = enc
	}
	if u.FromAddress != nil {
		addr := strings.TrimSpace(*u.FromAddress)
		if addr != "" {
			a, err := mail.ParseAddress(addr)
			if err != nil || a.Name != "" || a.Address != addr || len(addr) > maxMailAddress {
				return invalid("from_address", "Enter one email address, for example noreply@example.com.")
			}
		}
		rec.FromAddress = addr
	}
	if u.FromName != nil {
		name := strings.TrimSpace(*u.FromName)
		if len(name) > maxMailFromName || !plainText(name) {
			return invalid("from_name", "The sender name can have at most 128 characters and no control characters.")
		}
		rec.FromName = name
	}
	if u.BaseURL != nil {
		raw := strings.TrimSpace(*u.BaseURL)
		if raw != "" {
			base, err := NormalizeRecoveryBaseURL(raw)
			if err != nil {
				return invalid("base_url", "Enter the dashboard address as an absolute http:// or https:// URL without a query or fragment.")
			}
			raw = base
		}
		rec.BaseURL = raw
	}
	if touchesSMTP && rec.Host != "" && rec.FromAddress == "" {
		return invalid("from_address", "A sender address is required with a mail server.")
	}
	if err := s.Store.SetJSON(ctx, mailSettingsKey, rec); err != nil {
		return ErrMailSettingsUnavailable
	}
	s.Invalidate()
	*change = diffMailRecords(old, rec, passwordSent, clearedBy)
	return nil
}

// Clear removes every saved setting (config-managed ones stay in force).
func (s *MailSettings) Clear(ctx context.Context) error {
	if s == nil || s.Store == nil {
		return ErrMailSettingsUnavailable
	}
	if err := s.Store.SetJSON(ctx, mailSettingsKey, mailSettingsRecord{}); err != nil {
		return ErrMailSettingsUnavailable
	}
	s.Invalidate()
	return nil
}

const testMailSubject = "Wafio test email"

// SendTest sends a test email to `to` with the settings in force and the
// delivery bound (email.DefaultTimeout when Timeout is 0). A delivery
// failure is an *email.DeliveryError.
func (s *MailSettings) SendTest(ctx context.Context, to string) error {
	server, err := s.sendServer(ctx)
	if err != nil {
		return err
	}
	body := "This test email was sent from the Wafio control plane to check its email settings.\n\n" +
		"If you can read it, invitation and password reset emails can be delivered with these settings.\n"
	return email.SendText(server, to, testMailSubject, body)
}

// sendServer is the mail server for a send. A storage error only matters
// when no server is in force: a server from the configuration still sends.
func (s *MailSettings) sendServer(ctx context.Context) (email.Config, error) {
	st, err := s.Current(ctx)
	switch {
	case st.Server.Host != "":
		return st.Server, nil
	case err != nil:
		return email.Config{}, err
	}
	return email.Config{}, ErrMailNotConfigured
}

// SendHTML sends an HTML email with the settings in force
// (ErrMailNotConfigured without a mail server).
func (s *MailSettings) SendHTML(ctx context.Context, to, subject, body string) error {
	server, err := s.sendServer(ctx)
	if err != nil {
		return err
	}
	return email.SendHTML(server, to, subject, body)
}

// Mailer is a domain.Mailer that reads the settings in force at every send.
func (s *MailSettings) Mailer() domain.Mailer { return liveMailer{s: s} }

type liveMailer struct{ s *MailSettings }

func (m liveMailer) Send(to, subject, body string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	server, err := m.s.sendServer(ctx)
	if err != nil {
		return err
	}
	return email.SendText(server, to, subject, body)
}

// RecoveryMail implements RecoveryMailSource: the live mailer and link
// base, with a reason when email recovery is off right now.
func (s *MailSettings) RecoveryMail(ctx context.Context) (domain.Mailer, string, string) {
	st, err := s.Current(ctx)
	switch {
	case err != nil:
		return nil, "", fmt.Sprintf("email settings unreadable: %v", err)
	case st.Server.Host == "":
		return nil, "", "no mail server (smtp.host or Administration › Email (SMTP))"
	case st.BaseURL == "" && st.BaseURLProblem != "":
		return s.Mailer(), "", st.BaseURLProblem
	case st.BaseURL == "":
		return s.Mailer(), "", "no dashboard base URL (server.base_url or Administration › Email (SMTP))"
	}
	return s.Mailer(), st.BaseURL, ""
}
