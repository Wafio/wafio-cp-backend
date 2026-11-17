package domain

import (
	"context"
	"errors"
	"regexp"
	"time"
)

// Host-key enrollment.
// The installer on a host generates its private key, sends a CSR
// authenticated by the host key, and receives a client certificate bound to
// that host and to one agent (kind + name). The private key never leaves
// the host; the control plane stores the certificate and its fingerprint
// only.

const (
	// HostEnrollWindow is how long after a host is created or its key is
	// rotated the key can enroll. Outside it the key only binds agents at
	// Hello, as before; a rotation opens a new window.
	HostEnrollWindow = 24 * time.Hour

	// MaxEnrolledCredentialsPerHost bounds the active (unexpired) enrolled
	// credentials of one host: one per agent identity, e.g. the host agent
	// plus up to three WAF agents. Renewing an identity replaces its
	// credential and does not count twice. An identity enrolls once per
	// window; within the same window only a request with the same public key
	// (the installer retrying with the key it already holds) renews it.
	MaxEnrolledCredentialsPerHost = 4

	// EnrolledCertValidity is the lifetime of an enrolled client
	// certificate (cut at the CA's own expiry). Renewal = rotate the host
	// key (opens a window) and run the same enrollment again.
	EnrolledCertValidity = 365 * 24 * time.Hour

	// MaxEnrollAgentName bounds an enrolled agent name.
	MaxEnrollAgentName = 128
)

// Agent kinds a credential can be bound to.
const (
	AgentKindHost = "host"
	AgentKindWAF  = "waf"
)

// enrollAgentNameRE: printable, no spaces or shell metacharacters; the name
// ends up in an env file and in the certificate's URI SAN (escaped).
var enrollAgentNameRE = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._@:-]*$`)

// ValidEnrollAgentName reports whether name may be enrolled.
func ValidEnrollAgentName(name string) bool {
	return len(name) >= 1 && len(name) <= MaxEnrollAgentName && enrollAgentNameRE.MatchString(name)
}

var (
	// ErrHostKeyInvalid: the key does not verify (unknown, wrong, revoked
	// host, or the previous key of a rotation where only the current key is
	// accepted).
	ErrHostKeyInvalid = errors.New("host key invalid or revoked")
	// ErrEnrollWindowClosed: the host's enrollment window is not open.
	ErrEnrollWindowClosed = errors.New("enrollment window closed")
	// ErrEnrollLimit: the host already has MaxEnrolledCredentialsPerHost
	// active enrolled credentials for other agents.
	ErrEnrollLimit = errors.New("enrolled credential limit reached for the host")
	// ErrEnrollAgentNameTaken: the agent name is used in the project by
	// anything but this identity on this host: an agent row of another host,
	// of no host, or of the other kind, or an enrolled credential of another
	// host or kind. Enrolled names are unique per project across kinds, so
	// the name lookups after Hello resolve to the enrolled agent.
	ErrEnrollAgentNameTaken = errors.New("agent name is already used in the project")
	// ErrEnrollUsed: the identity already enrolled during the current window
	// and the request does not prove possession of that credential's key. A
	// leaked host key therefore cannot take over an identity the host has
	// enrolled; the operator renews by rotating the key (new window).
	ErrEnrollUsed = errors.New("agent already enrolled in this enrollment window")
	// ErrEnrollHostRevoked: the host was revoked (or deleted) after its key
	// verified.
	ErrEnrollHostRevoked = errors.New("host revoked")
	// ErrEnrollUnavailable: no agent CA (the gRPC listener never started).
	ErrEnrollUnavailable = errors.New("enrollment unavailable: no agent CA")
)

// HostEnrollIssue is one issuance request to the store.
type HostEnrollIssue struct {
	ProjectID string
	HostID    string
	AgentKind string
	AgentName string
	// KeyLookup is the lookup id (keyauth.LookupID) of the key that
	// verified. Under the host row lock it must still be the host's current
	// key: a rotation that lands between the verification and the lock
	// leaves the verified key retired, and a retired key never enrolls.
	KeyLookup string
	// PublicKeyDER is the CSR's SubjectPublicKeyInfo (DER). Re-enrolling an
	// identity that already enrolled in the current window is allowed only
	// with the same public key (an installer retry on the same host), and
	// then returns the stored credential while it is still usable (see
	// HostEnrollResult.Replayed).
	PublicKeyDER []byte
	// CACertPEM is the agent CA the response carries (AgentCA). A stored
	// credential is replayed only while its certificate chains to it, so a
	// CA rotation still re-issues.
	CACertPEM string
	// SourceIP and UserAgent go into the audit rows.
	SourceIP  string
	UserAgent string
	// Sign returns the certificate PEM and its NotAfter. The store calls it
	// inside its transaction after every check passed, so nothing is signed
	// for a refused request.
	Sign func() (certPEM string, notAfter time.Time, err error)
}

// HostEnrollResult is what the store issued, or, when Replayed, the stored
// credential it returned unchanged.
type HostEnrollResult struct {
	CredentialID string
	Fingerprint  string
	HostName     string
	CertPEM      string
	NotAfter     time.Time
	// EnrollExpiresAt is the end of the window the enrollment used.
	EnrollExpiresAt time.Time
	// Superseded lists the credentials of the same agent identity this
	// renewal deleted; their open streams must be closed.
	Superseded []string
	// Replayed: the identity's credential issued in the current window has
	// the request's public key, is not expired and chains to CACertPEM, so
	// the store returned it as stored (same id, certificate, fingerprint
	// and NotAfter) and changed nothing: no signature, no row deleted or
	// inserted, no audit row, nothing superseded. A same-key retry (an
	// installer whose response was lost) is idempotent.
	Replayed bool
}

// HostEnrollRefusal is an audited refusal of a request whose host key
// verified (window closed, limit, name taken): a valid key used outside its
// window is a sign the key leaked.
type HostEnrollRefusal struct {
	ProjectID string
	HostID    string
	HostName  string
	Code      string
	AgentKind string
	AgentName string
	SourceIP  string
	UserAgent string
}

// HostEnrollStore is the persistence the enrollment needs.
type HostEnrollStore interface {
	// VerifyCurrentHostKey returns the unrevoked host whose CURRENT key is
	// raw. The previous key of a rotation (grace period) does not enroll.
	// ErrHostKeyInvalid when it does not verify.
	VerifyCurrentHostKey(ctx context.Context, raw string) (*Host, error)
	// AgentCA returns the global agent CA certificate and key PEM;
	// ErrEnrollUnavailable when none exists.
	AgentCA(ctx context.Context) (certPEM, keyPEM string, err error)
	// IssueHostCredential checks the window and the agent name under a lock
	// on the host row; returns the identity's stored credential unchanged
	// for a same-key request it can replay (HostEnrollResult.Replayed);
	// otherwise checks the per-host cap, signs, replaces the identity's
	// previous credential and stores the new one with its audit rows, all in
	// one transaction.
	IssueHostCredential(ctx context.Context, in HostEnrollIssue) (*HostEnrollResult, error)
	// RecordEnrollRefusal writes the audit row of a refusal (best effort).
	RecordEnrollRefusal(ctx context.Context, r HostEnrollRefusal) error
}
