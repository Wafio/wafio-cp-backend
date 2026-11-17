// Package email sends transactional email via SMTP (e.g. OTP).
package email

import (
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/mail"
	"net/smtp"
	"net/textproto"
	"os"
	"strconv"
	"strings"
	"time"
)

// Config holds SMTP connection settings.
type Config struct {
	Host     string
	Port     int
	Username string
	Password string
	From     string
	UseTLS   bool   // backward-compatible alias for STARTTLS
	Mode     string // auto | starttls | ssl | none
	// Timeout bounds one delivery: connect plus the whole SMTP conversation.
	// Zero means DefaultTimeout. Without it a server that accepts the
	// connection and never answers held the sender forever.
	Timeout time.Duration
}

// DefaultTimeout is the delivery bound when Config.Timeout is zero.
const DefaultTimeout = 30 * time.Second

// Configured reports whether a mail server is set (host and port).
func (cfg Config) Configured() bool { return cfg.Host != "" && cfg.Port > 0 }

// ErrHeaderInjection is returned when a header value (To, From, Subject)
// contains CR, LF or NUL. Such a value could add headers or start the body
// early, so the message is refused before any connection is made.
var ErrHeaderInjection = errors.New("email: header value contains CR, LF or NUL")

// ValidateHeaderValue reports ErrHeaderInjection when v contains CR, LF or NUL.
// Callers that build a header from user input can use it to return a 400
// before calling Send.
func ValidateHeaderValue(v string) error {
	if strings.ContainsAny(v, "\r\n\x00") {
		return ErrHeaderInjection
	}
	return nil
}

// buildMessage assembles the header block and body. withFromMIME selects the
// full layout (From, Date and MIME-Version headers) used by SendHTML and
// SendText; Send keeps its historical layout. Every header value is checked
// with ValidateHeaderValue.
func buildMessage(from, to, subject, contentType, body string, withFromMIME bool) ([]byte, error) {
	for _, v := range []string{from, to, subject} {
		if err := ValidateHeaderValue(v); err != nil {
			return nil, err
		}
	}
	var b strings.Builder
	b.WriteString("To: " + to + "\r\n")
	if withFromMIME {
		b.WriteString("From: " + from + "\r\n")
		b.WriteString("Date: " + time.Now().UTC().Format(time.RFC1123Z) + "\r\n")
	}
	b.WriteString("Subject: " + subject + "\r\n")
	if withFromMIME {
		b.WriteString("MIME-Version: 1.0\r\n")
	}
	b.WriteString("Content-Type: " + contentType + "; charset=UTF-8\r\n\r\n")
	b.WriteString(body)
	return []byte(b.String()), nil
}

// Send sends a plain-text email in the historical header layout (To,
// Subject, Content-Type). If cfg.Username is set, uses PLAIN auth. Header
// values containing CR, LF or NUL are rejected with ErrHeaderInjection.
func Send(cfg Config, to, subject, body string) error {
	return send(cfg, to, subject, "text/plain", body, false)
}

// SendText sends a plain-text email with From, Date and MIME-Version
// headers (same ErrHeaderInjection check).
func SendText(cfg Config, to, subject, body string) error {
	return send(cfg, to, subject, "text/plain", body, true)
}

// SendHTML sends an HTML email. Identical to SendText but sets Content-Type
// to text/html (same ErrHeaderInjection check).
func SendHTML(cfg Config, to, subject, body string) error {
	return send(cfg, to, subject, "text/html", body, true)
}

func send(cfg Config, to, subject, contentType, body string, withFromMIME bool) error {
	if !cfg.Configured() {
		return fmt.Errorf("email: SMTP host and port required")
	}
	from := cfg.From
	if from == "" {
		from = cfg.Username
	}
	msg, err := buildMessage(from, to, subject, contentType, body, withFromMIME)
	if err != nil {
		return err
	}
	var auth smtp.Auth
	if cfg.Username != "" && cfg.Password != "" {
		auth = smtp.PlainAuth("", cfg.Username, cfg.Password, cfg.Host)
	}
	return deliver(cfg, resolveMode(cfg), auth, envelopeAddress(from), to, msg)
}

// resolveMode maps Config.Mode to ssl, starttls or none. Empty and "auto"
// pick by port: 465 implicit TLS, 587 and 2525 STARTTLS, anything else
// STARTTLS when UseTLS is set and opportunistic otherwise.
func resolveMode(cfg Config) string {
	mode := strings.ToLower(strings.TrimSpace(cfg.Mode))
	switch mode {
	case "", "auto":
		switch {
		case cfg.Port == 465:
			return "ssl"
		case cfg.Port == 587, cfg.Port == 2525, cfg.UseTLS:
			return "starttls"
		default:
			return "none"
		}
	case "smtps", "tls":
		return "ssl"
	case "plain":
		return "none"
	}
	return mode
}

// envelopeAddress is the bare address for MAIL FROM: a From of the form
// "Wafio <noreply@example.com>" would otherwise be sent as
// MAIL FROM:<Wafio <noreply@example.com>>, which servers refuse.
func envelopeAddress(from string) string {
	if a, err := mail.ParseAddress(from); err == nil {
		return a.Address
	}
	return from
}

// deliver runs one SMTP conversation under a single deadline. mode is ssl
// (implicit TLS), starttls (required) or none (STARTTLS when the server
// offers it, as net/smtp.SendMail does).
func deliver(cfg Config, mode string, auth smtp.Auth, from, to string, msg []byte) error {
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = DefaultTimeout
	}
	deadline := time.Now().Add(timeout)
	addr := net.JoinHostPort(cfg.Host, strconv.Itoa(cfg.Port))
	dialer := &net.Dialer{Deadline: deadline}
	tlsConfig := &tls.Config{ServerName: cfg.Host, MinVersion: tls.VersionTLS12}

	var conn net.Conn
	var err error
	switch mode {
	case "ssl":
		conn, err = tls.DialWithDialer(dialer, "tcp", addr, tlsConfig)
		var op *net.OpError
		if err != nil && (!errors.As(err, &op) || op.Op != "dial") {
			return deliveryError(StageTLS, addr, err)
		}
	case "starttls", "none":
		conn, err = dialer.Dial("tcp", addr)
	default:
		return fmt.Errorf("email: invalid SMTP mode %q", cfg.Mode)
	}
	if err != nil {
		return deliveryError(StageConnect, addr, err)
	}
	defer func() { _ = conn.Close() }() // shutdown path; nothing left to report
	if err := conn.SetDeadline(deadline); err != nil {
		return deliveryError(StageConnect, addr, err)
	}

	client, err := smtp.NewClient(conn, cfg.Host)
	if err != nil {
		return deliveryError(StageConnect, addr, err)
	}
	defer func() { _ = client.Close() }() // shutdown path; nothing left to report

	startTLS := mode == "starttls"
	if mode == "none" {
		startTLS, _ = client.Extension("STARTTLS")
	}
	if startTLS {
		if err := client.StartTLS(tlsConfig); err != nil {
			return deliveryError(StageTLS, addr, err)
		}
	}
	if auth != nil {
		if ok, _ := client.Extension("AUTH"); !ok {
			return deliveryError(StageAuth, addr, errNoAuth)
		}
		if err := client.Auth(auth); err != nil {
			return deliveryError(StageAuth, addr, err)
		}
	}
	if err := client.Mail(from); err != nil {
		return deliveryError(StageSender, addr, err)
	}
	if err := client.Rcpt(to); err != nil {
		return deliveryError(StageRecipient, addr, err)
	}
	w, err := client.Data()
	if err != nil {
		return deliveryError(StageMessage, addr, err)
	}
	if _, err := w.Write(msg); err != nil {
		return deliveryError(StageMessage, addr, err)
	}
	if err := w.Close(); err != nil {
		return deliveryError(StageMessage, addr, err)
	}
	// The server accepted the message; a failed QUIT does not undo that.
	_ = client.Quit()
	return nil
}

// Delivery stages reported by DeliveryError.
const (
	StageConnect   = "connect"   // TCP connect or the server greeting
	StageTLS       = "tls"       // implicit TLS or STARTTLS handshake
	StageAuth      = "auth"      // authentication
	StageSender    = "sender"    // MAIL FROM refused
	StageRecipient = "recipient" // RCPT TO refused
	StageMessage   = "message"   // DATA refused or cut
)

// DeliveryError is a failed SMTP delivery with the stage it failed at. Its
// Error text may carry the server's reply; Summary never does.
type DeliveryError struct {
	Stage string
	// Addr is host:port of the mail server.
	Addr string
	// Code is the SMTP reply code when the server answered with one.
	Code int
	// Timeout: the delivery deadline (Config.Timeout) passed.
	Timeout bool
	err     error
}

func (e *DeliveryError) Error() string { return "smtp " + e.Stage + ": " + e.err.Error() }
func (e *DeliveryError) Unwrap() error { return e.err }

// Summary is a sentence about the failure that is safe to show to an
// administrator: the stage, the server address and the SMTP reply code,
// never the server's reply text (it can echo the account name) nor any
// credential.
func (e *DeliveryError) Summary() string {
	var msg string
	switch {
	case e.Timeout:
		msg = "The mail server " + e.Addr + " did not answer in time."
	case e.Stage == StageConnect:
		msg = "Could not connect to the mail server " + e.Addr + "."
	case e.Stage == StageTLS:
		msg = "The TLS handshake with " + e.Addr + " failed. Check the security mode and the server certificate."
	case e.Stage == StageAuth && errors.Is(e.err, errNoAuth):
		msg = "The mail server does not offer authentication on this connection. Check the security mode."
	case e.Stage == StageAuth && strings.Contains(e.err.Error(), "unencrypted connection"):
		msg = "The connection is not encrypted, so the password was not sent. Choose STARTTLS or TLS."
	case e.Stage == StageAuth:
		msg = "The mail server refused the username or password."
	case e.Stage == StageSender:
		msg = "The mail server refused the sender address."
	case e.Stage == StageRecipient:
		msg = "The mail server refused the recipient address."
	default:
		msg = "The mail server refused the message."
	}
	if e.Code > 0 {
		msg += " (SMTP " + strconv.Itoa(e.Code) + ")"
	}
	return msg
}

var errNoAuth = errors.New("server does not support AUTH")

func deliveryError(stage, addr string, err error) error {
	de := &DeliveryError{Stage: stage, Addr: addr, err: err}
	var tp *textproto.Error
	if errors.As(err, &tp) {
		de.Code = tp.Code
	}
	var ne net.Error
	if errors.Is(err, os.ErrDeadlineExceeded) || (errors.As(err, &ne) && ne.Timeout()) {
		de.Timeout = true
	}
	return de
}

// SendMail is a convenience that uses Send with a Config built from host/port/user/pass/from.
// useSTARTTLS should be true for port 587.
func SendMail(host string, port int, username, password, from, to, subject, body string, useSTARTTLS bool) error {
	return Send(Config{
		Host:     host,
		Port:     port,
		Username: username,
		Password: password,
		From:     from,
		UseTLS:   useSTARTTLS,
		Mode:     "auto",
	}, to, subject, body)
}

// Mailer sends plain-text email (SendText) with a fixed Config. It
// implements domain.Mailer.
type Mailer struct {
	Config Config
}

// Send implements domain.Mailer.
func (m Mailer) Send(to, subject, body string) error {
	return SendText(m.Config, to, subject, body)
}

// NormalizeEmail lowercases and trims (for OTP key).
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}
