package application

// PasswordRecovery is password reset by email: a request for
// an address mails a single-use link, the link sets a new password.
//
// A request never answers anything about the account: the HTTP handler
// queues it (Request) and returns the same response for every address, and
// the per-account work — lookup, throttle, token, audit, email — runs on
// the background worker (Run). The response path is the same work whether or
// not the account exists, so its timing cannot tell them apart either.

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log"
	"net/url"
	"strings"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/wafio/wafio-cp-backend/internal/domain"
	"golang.org/x/crypto/bcrypt"
)

const (
	// PasswordResetTokenTTL is how long a reset link works.
	PasswordResetTokenTTL = 30 * time.Minute
	// PasswordResetThrottle: at most one reset email per account per window.
	PasswordResetThrottle = 5 * time.Minute
	// passwordResetPurgeEvery is how often expired tokens are deleted.
	passwordResetPurgeEvery = 15 * time.Minute
	// passwordRecoveryQueue bounds the requests and notifications waiting
	// for the worker; past it they are dropped (and counted).
	passwordRecoveryQueue = 128
	// passwordRecoveryJobTimeout bounds the database work of one job (the
	// SMTP delivery has its own bound, email.Config.Timeout).
	passwordRecoveryJobTimeout = time.Minute
	// passwordResetTokenBytes is the entropy of a reset token.
	passwordResetTokenBytes = 32

	// MinPasswordLength is the account password policy minimum, in
	// characters (the same rule as the validate:"min=8" tags elsewhere).
	MinPasswordLength = 8
	// MaxPasswordBytes is bcrypt's input limit; longer passwords are refused
	// rather than silently cut.
	MaxPasswordBytes = 72
)

// Password policy errors.
var (
	ErrPasswordTooShort = errors.New("password shorter than 8 characters")
	ErrPasswordTooLong  = errors.New("password longer than 72 bytes")
)

// ValidateNewPassword applies the account password policy.
func ValidateNewPassword(pw string) error {
	if utf8.RuneCountInString(pw) < MinPasswordLength {
		return ErrPasswordTooShort
	}
	if len(pw) > MaxPasswordBytes {
		return ErrPasswordTooLong
	}
	return nil
}

// RecoveryMailSource tells, at each use, how recovery email is sent
// (MailSettings in production: server configuration, else the settings
// saved under Administration, read live).
type RecoveryMailSource interface {
	// RecoveryMail returns the mailer (nil = no mail server), the
	// normalised dashboard base URL for links, and a non-empty reason when
	// email recovery is off right now.
	RecoveryMail(ctx context.Context) (mailer domain.Mailer, baseURL string, reason string)
}

// PasswordRecoveryConfig configures NewPasswordRecovery.
type PasswordRecoveryConfig struct {
	Store domain.PasswordResetStore
	// Mail is the live mail configuration. When nil, Mailer and BaseURL
	// are a fixed one (tests).
	Mail RecoveryMailSource
	// Mailer sends the emails; nil means no mail server is configured.
	Mailer domain.Mailer
	// BaseURL is the dashboard address the link points to. It must be an
	// absolute http(s) URL: the link is never built from the request's Host
	// header, which a caller controls.
	BaseURL string
}

// PasswordRecovery serves the recovery endpoints. Create it with
// NewPasswordRecovery and start Run once.
type PasswordRecovery struct {
	store   domain.PasswordResetStore
	mail    RecoveryMailSource
	jobs    chan recoveryJob
	dropped atomic.Uint64
}

// fixedRecoveryMail is a RecoveryMailSource that never changes.
type fixedRecoveryMail struct {
	mailer domain.Mailer
	base   string
	reason string
}

func (f fixedRecoveryMail) RecoveryMail(context.Context) (domain.Mailer, string, string) {
	return f.mailer, f.base, f.reason
}

func newFixedRecoveryMail(mailer domain.Mailer, baseURL string) fixedRecoveryMail {
	if mailer == nil {
		return fixedRecoveryMail{reason: "smtp.host is not set"}
	}
	base, err := NormalizeRecoveryBaseURL(baseURL)
	if err != nil {
		return fixedRecoveryMail{mailer: mailer, reason: err.Error()}
	}
	return fixedRecoveryMail{mailer: mailer, base: base}
}

type recoveryJobKind int

const (
	jobRequest recoveryJobKind = iota
	jobNotify
	jobBarrier
)

type recoveryJob struct {
	kind  recoveryJobKind
	email string
	actor domain.AuditActor
	at    time.Time
	done  chan struct{}
}

// NewPasswordRecovery builds the service. Email recovery is available while
// the mail source has a mail server and a valid base URL (checked at every
// use: a request made while it is off is dropped by the worker, and
// UnavailableReason says why). Reset works either way for links already
// sent.
func NewPasswordRecovery(cfg PasswordRecoveryConfig) *PasswordRecovery {
	mail := cfg.Mail
	if mail == nil {
		mail = newFixedRecoveryMail(cfg.Mailer, cfg.BaseURL)
	}
	return &PasswordRecovery{
		store: cfg.Store,
		mail:  mail,
		jobs:  make(chan recoveryJob, passwordRecoveryQueue),
	}
}

// NormalizeRecoveryBaseURL checks server.base_url for reset links: an
// absolute http or https URL with a host, no user info, query or fragment.
// It returns the URL without a trailing slash.
func NormalizeRecoveryBaseURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("the dashboard base URL is not set")
	}
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.Hostname() == "" {
		return "", errors.New("the dashboard base URL is not an absolute http(s) URL")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return "", errors.New("the dashboard base URL must not carry user info, a query or a fragment")
	}
	return strings.TrimRight(u.Scheme+"://"+u.Host+u.EscapedPath(), "/"), nil
}

// Available reports whether reset emails can be sent right now.
func (r *PasswordRecovery) Available(ctx context.Context) bool {
	return r.UnavailableReason(ctx) == ""
}

// UnavailableReason is why email recovery is off right now, "" when it is
// on.
func (r *PasswordRecovery) UnavailableReason(ctx context.Context) string {
	if r.store == nil {
		return "no database"
	}
	_, _, reason := r.mail.RecoveryMail(ctx)
	return reason
}

// Dropped is the number of jobs dropped because the queue was full.
func (r *PasswordRecovery) Dropped() uint64 { return r.dropped.Load() }

// Request queues a reset request for a normalised email and returns at once,
// whatever the outcome will be. It reads no settings and no account: the
// worker decides (recovery off → the request is dropped there).
func (r *PasswordRecovery) Request(email string, actor domain.AuditActor) {
	if r.store == nil || email == "" {
		return
	}
	r.enqueue(recoveryJob{kind: jobRequest, email: email, actor: actor})
}

func (r *PasswordRecovery) enqueue(job recoveryJob) {
	select {
	case r.jobs <- job:
	default:
		r.dropped.Add(1)
		log.Printf("password recovery: queue full, job dropped (%d dropped so far)", r.dropped.Load())
	}
}

// Flush waits until every job queued before it has been handled (tests,
// shutdown). It returns ctx's error if ctx ends first.
func (r *PasswordRecovery) Flush(ctx context.Context) error {
	done := make(chan struct{})
	select {
	case r.jobs <- recoveryJob{kind: jobBarrier, done: done}:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Run handles queued jobs and purges expired tokens until ctx ends. One
// worker: requests are handled in order, and a slow mail server delays
// recovery emails, never an HTTP response.
func (r *PasswordRecovery) Run(ctx context.Context) {
	purge := time.NewTicker(passwordResetPurgeEvery)
	defer purge.Stop()
	r.purge(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case job := <-r.jobs:
			r.handle(ctx, job)
		case <-purge.C:
			r.purge(ctx)
		}
	}
}

// purge deletes expired tokens. With recovery off nothing new is issued and
// leftovers are never valid (every check reads expires_at), so it skips.
func (r *PasswordRecovery) purge(ctx context.Context) {
	if r.store == nil || !r.Available(ctx) {
		return
	}
	jctx, cancel := context.WithTimeout(ctx, passwordRecoveryJobTimeout)
	defer cancel()
	if _, err := r.store.PurgeExpiredPasswordResets(jctx); err != nil && ctx.Err() == nil {
		log.Printf("password recovery: purge expired tokens: %v", err)
	}
}

func (r *PasswordRecovery) handle(ctx context.Context, job recoveryJob) {
	switch job.kind {
	case jobBarrier:
		close(job.done)
	case jobRequest:
		r.issue(ctx, job)
	case jobNotify:
		r.notify(ctx, job)
	}
}

// issue looks the account up, stores a token unless throttled and mails the
// link. Nothing about the outcome reaches the caller; the log names user ids
// only, never an address or a token. With email recovery off right now the
// request is dropped before any lookup.
func (r *PasswordRecovery) issue(ctx context.Context, job recoveryJob) {
	mailer, baseURL, reason := r.mail.RecoveryMail(ctx)
	if reason != "" {
		return
	}
	token, hash, err := newResetToken()
	if err != nil {
		log.Printf("password recovery: token: %v", err)
		return
	}
	jctx, cancel := context.WithTimeout(ctx, passwordRecoveryJobTimeout)
	issued, err := r.store.IssuePasswordReset(jctx, job.email, hash, PasswordResetTokenTTL, PasswordResetThrottle, job.actor)
	cancel()
	if err != nil {
		if ctx.Err() == nil {
			log.Printf("password recovery: issue token: %v", err)
		}
		return
	}
	if !issued.Found || issued.Throttled {
		return
	}
	link := baseURL + "/reset-password#token=" + token
	if err := mailer.Send(issued.Email, resetRequestSubject, resetRequestBody(issued.Email, link, job.actor.IP)); err != nil {
		log.Printf("password recovery: send reset email for user %s: %v", issued.UserID, err)
	}
}

// notify mails the password-changed notice when a mail server is in force
// (it needs no base URL).
func (r *PasswordRecovery) notify(ctx context.Context, job recoveryJob) {
	mailer, _, _ := r.mail.RecoveryMail(ctx)
	if mailer == nil {
		return
	}
	if err := mailer.Send(job.email, resetDoneSubject, resetDoneBody(job.email, job.at, job.actor.IP)); err != nil {
		log.Printf("password recovery: send password-changed notice: %v", err)
	}
}

// Reset sets a new password with a reset token. A policy violation returns
// ErrPasswordTooShort or ErrPasswordTooLong; a token that is malformed,
// unknown, expired, used or replaced returns
// domain.ErrPasswordResetTokenInvalid. On success the account's
// token_version has moved on (every session ends) and a notice is mailed.
func (r *PasswordRecovery) Reset(ctx context.Context, token, newPassword string, actor domain.AuditActor) (domain.PasswordResetAccount, error) {
	if err := ValidateNewPassword(newPassword); err != nil {
		return domain.PasswordResetAccount{}, err
	}
	hash, ok := resetTokenHash(token)
	if !ok || r.store == nil {
		return domain.PasswordResetAccount{}, domain.ErrPasswordResetTokenInvalid
	}
	// Cheap check first, so an unknown token costs no bcrypt work.
	valid, err := r.store.PasswordResetTokenValid(ctx, hash)
	if err != nil {
		return domain.PasswordResetAccount{}, fmt.Errorf("check reset token: %w", err)
	}
	if !valid {
		return domain.PasswordResetAccount{}, domain.ErrPasswordResetTokenInvalid
	}
	pwHash, err := bcrypt.GenerateFromPassword([]byte(newPassword), bcrypt.DefaultCost)
	if err != nil {
		return domain.PasswordResetAccount{}, fmt.Errorf("hash password: %w", err)
	}
	acct, err := r.store.CompletePasswordReset(ctx, hash, string(pwHash), actor)
	if err != nil {
		return domain.PasswordResetAccount{}, err
	}
	r.enqueue(recoveryJob{kind: jobNotify, email: acct.Email, actor: actor, at: time.Now().UTC()})
	return acct, nil
}

// newResetToken returns a URL-safe token (32 random bytes, unpadded
// base64url, 43 characters) and the SHA-256 digest that is stored.
func newResetToken() (string, []byte, error) {
	raw := make([]byte, passwordResetTokenBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", nil, err
	}
	sum := sha256.Sum256(raw)
	return base64.RawURLEncoding.EncodeToString(raw), sum[:], nil
}

// resetTokenHash decodes a token strictly (exactly 43 unpadded base64url
// characters) and returns its digest.
func resetTokenHash(token string) ([]byte, bool) {
	if len(token) != base64.RawURLEncoding.EncodedLen(passwordResetTokenBytes) {
		return nil, false
	}
	raw, err := base64.RawURLEncoding.Strict().DecodeString(token)
	if err != nil || len(raw) != passwordResetTokenBytes {
		return nil, false
	}
	sum := sha256.Sum256(raw)
	return sum[:], true
}

const (
	resetRequestSubject = "Reset your Wafio password"
	resetDoneSubject    = "Your Wafio password was changed"
)

func resetRequestBody(email, link, ip string) string {
	var b strings.Builder
	b.WriteString("Someone asked to reset the password of the Wafio account " + email + ".\n\n")
	b.WriteString("To choose a new password, open this link within 30 minutes:\n\n")
	b.WriteString(link + "\n\n")
	b.WriteString("The link works once. Asking for another reset makes this link stop working.\n")
	b.WriteString("Two-factor authentication, if it is on, stays on.\n\n")
	b.WriteString("If you did not ask for this, ignore this email. Your password stays as it is.\n")
	if ip != "" {
		b.WriteString("\nThe request came from IP address " + ip + ".\n")
	}
	return b.String()
}

func resetDoneBody(email string, at time.Time, ip string) string {
	var b strings.Builder
	b.WriteString("The password of the Wafio account " + email + " was changed with a password reset link on " + at.Format("2006-01-02 15:04") + " UTC.\n\n")
	b.WriteString("Every session of this account was signed out. Two-factor authentication, if it is on, stays on.\n\n")
	b.WriteString("If you did not do this, contact your Wafio administrator now: someone who can read your email may have changed your password.\n")
	if ip != "" {
		b.WriteString("\nThe reset came from IP address " + ip + ".\n")
	}
	return b.String()
}
