package repository

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"
	"unicode"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/wafio/wafio-cp-backend/internal/domain"
	"github.com/wafio/wafio-cp-backend/internal/otp"
)

// TLSRepo stores how an application is served over TLS: the settings on the application, the
// uploaded certificates with their sealed keys, and what the agent reported.
//
// Every query matches the project. The sealed key of a certificate lives in its own table, which
// CertificateForDelivery reads and no other query does (TestOnlyTheDeliveryQuerySelectsTheKey keeps it
// so), and what it returns is still sealed: opening it is up to the caller.
type TLSRepo struct {
	pool *pgxpool.Pool
}

// The reasons a change of the TLS settings is refused, besides the *domain.TLSFieldError and
// *domain.TLSConflictError that the checks in domain return.
var (
	// ErrTLSUnsupported: the agent that serves the application reported that it cannot serve TLS
	// from the bundle (agents.tls_certificates is false).
	ErrTLSUnsupported = errors.New("the agent does not serve TLS certificates")
	// ErrCertificateRequired: an uploaded certificate is needed and the application has none that is
	// current and not expired.
	ErrCertificateRequired = errors.New("the application has no current certificate")
	// ErrAgentNotHostBound: the key of an uploaded certificate goes only to an agent whose credential
	// is bound to its host, kind and name, and the agent that serves the application has none.
	ErrAgentNotHostBound = errors.New("the agent has no host-bound credential")
	// ErrCertificateInUse: the certificate serves traffic now and cannot be deleted.
	ErrCertificateInUse = errors.New("the certificate is in use")
)

// TLSCoverageError says that the certificate does not cover a host of the application.
type TLSCoverageError struct{ Host string }

func (e *TLSCoverageError) Error() string {
	return "the certificate does not cover " + e.Host
}

// ACMETooSoonError says that an ACME request was made less than ACMERequestInterval ago.
type ACMETooSoonError struct{ RetryAfter time.Duration }

func (e *ACMETooSoonError) Error() string {
	return fmt.Sprintf("an ACME request was made recently; try again in %d seconds", int(e.RetryAfter.Seconds())+1)
}

// ACMERequestInterval is the shortest time between two ACME requests of one application.
const ACMERequestInterval = 5 * time.Minute

// AppTLS is the TLS configuration stored on an application.
type AppTLS struct {
	Mode           string
	Hosts          []string
	Listen         string // never empty: a row that never saved reads as the default listener
	RedirectListen string
	Source         string
	CertificateID  string // the current uploaded certificate, "" when none
	ACMERequestID  string
	// ACMERequestedAt is when ACME was last requested, nil when never.
	ACMERequestedAt *time.Time
}

// sameForAgent says whether two settings give the agent the same bundle entry.
func (t AppTLS) sameForAgent(o AppTLS) bool {
	return t.Mode == o.Mode && t.Listen == o.Listen && t.RedirectListen == o.RedirectListen && t.Source == o.Source &&
		t.CertificateID == o.CertificateID && t.ACMERequestID == o.ACMERequestID && slices.Equal(t.Hosts, o.Hosts)
}

// AppCertificate is an uploaded certificate without its chain and key.
type AppCertificate struct {
	ID, AppID, Source   string
	LeafSHA256          string
	Names               []string
	Issuer, KeyType     string
	NotBefore, NotAfter time.Time
	Trusted             bool
	CreatedBy           string
	CreatedAt           time.Time
	ReplacedAt          *time.Time
	ExpiryNotifiedDays  *int
}

// queryer is what pgx.Tx and *pgxpool.Pool share.
type queryer interface {
	Query(ctx context.Context, sql string, args ...any) (pgx.Rows, error)
	QueryRow(ctx context.Context, sql string, args ...any) pgx.Row
}

func effectiveTLSListen(v string) string {
	if v == "" {
		return domain.DefaultTLSListen
	}
	return v
}

// tlsApp is an application as the TLS checks need it.
type tlsApp struct {
	id, projectID, name string
	AppTLS
	limits domain.ListenerLimits
	// plain is the listener the application opens for itself, nil when it has none.
	plain *domain.PlainListener
	// agentID is the agent that serves the application, "" when none.
	agentID string
}

// plainListenerOf builds the plain listener of an application. A listen host that is not an IP
// address (a legacy name) cannot equal an address and gives none.
func plainListenerOf(appID, name, hostKey string, port *int32) *domain.PlainListener {
	if port == nil {
		return nil
	}
	addr, err := netip.ParseAddr(hostKey)
	if err != nil || *port < 1 || *port > 65535 {
		return nil
	}
	return &domain.PlainListener{AppID: appID, Name: name, Addr: netip.AddrPortFrom(addr, uint16(*port))}
}

// readTLSApp reads the application of the project. With lock the row is locked first, in a statement
// of its own, and the application is read after it in another: a statement that waits for the lock
// still sees the rows its snapshot had when it started, so reading the agent in the locking statement
// could name an agent the application has left meanwhile. A move holds the same row, so once this
// transaction has it the agent cannot change under it. It returns pgx.ErrNoRows when the application
// is not in the project.
func readTLSApp(ctx context.Context, q queryer, projectID, appID string, lock bool) (tlsApp, error) {
	if lock {
		var one int
		if err := q.QueryRow(ctx, `SELECT 1 FROM apps WHERE id = $1 AND project_id = $2 FOR UPDATE`, appID, projectID).Scan(&one); err != nil {
			return tlsApp{}, err
		}
	}
	query := `SELECT a.id::text, a.project_id::text, a.name, a.tls_mode, a.tls_hosts, a.tls_listen, a.tls_redirect_listen,
		a.tls_source, COALESCE(a.tls_certificate_id::text, ''), a.acme_request_id, a.acme_requested_at, a.proxy_config,
		wafio_listen_host_key(a.listen_host), a.listen_port,
		COALESCE((SELECT waa.agent_id::text FROM waf_agent_apps waa WHERE waa.app_id = a.id AND waa.enabled = TRUE LIMIT 1), '')
		FROM apps a WHERE a.id = $1 AND a.project_id = $2`
	var a tlsApp
	var proxy []byte
	var hostKey string
	var port *int32
	if err := q.QueryRow(ctx, query, appID, projectID).Scan(&a.id, &a.projectID, &a.name, &a.Mode, &a.Hosts, &a.Listen, &a.RedirectListen,
		&a.Source, &a.CertificateID, &a.ACMERequestID, &a.ACMERequestedAt, &proxy, &hostKey, &port, &a.agentID); err != nil {
		return tlsApp{}, err
	}
	pc, err := domain.ParseProxyConfig(proxy)
	if err != nil {
		return tlsApp{}, err
	}
	a.limits = domain.ListenerLimitsOf(pc)
	a.plain = plainListenerOf(a.id, a.name, hostKey, port)
	a.Listen = effectiveTLSListen(a.Listen)
	if a.Hosts == nil {
		a.Hosts = []string{}
	}
	return a, nil
}

// site is the application as the placement check sees it. An application that is not in gateway mode
// has no HTTPS listener to place: only its plain listener counts.
func (a tlsApp) site() domain.TLSSite {
	if a.Mode != domain.TLSModeGateway {
		return domain.TLSSite{AppID: a.id, Name: a.name}
	}
	return domain.TLSSite{AppID: a.id, Name: a.name, Listen: a.Listen, RedirectListen: a.RedirectListen, Hosts: a.Hosts, Limits: a.limits}
}

// checkTLSFit checks that a, with the settings it has now, fits next to the other applications of
// the agent, whether it is in gateway mode or only has a plain listener of its own to place. The caller holds the bundle of the agent (lockAgentBundle), which is what makes the
// answer hold until the change is committed. It returns a *domain.TLSConflictError.
func checkTLSFit(ctx context.Context, q queryer, a tlsApp, agentID string) error {
	rows, err := q.Query(ctx, `SELECT a.id::text, a.name, a.tls_mode, a.tls_listen, a.tls_redirect_listen, a.tls_hosts, a.proxy_config,
		wafio_listen_host_key(a.listen_host), a.listen_port
		FROM waf_agent_apps waa JOIN apps a ON a.id = waa.app_id
		WHERE waa.agent_id = $1 AND waa.enabled = TRUE AND a.project_id = $2 AND a.id <> $3
		ORDER BY a.name, a.id`, agentID, a.projectID, a.id)
	if err != nil {
		return err
	}
	defer rows.Close()
	var others []domain.TLSSite
	var plain []domain.PlainListener
	for rows.Next() {
		var o tlsApp
		var listen string
		var proxy []byte
		var hostKey string
		var port *int32
		if err := rows.Scan(&o.id, &o.name, &o.Mode, &listen, &o.RedirectListen, &o.Hosts, &proxy, &hostKey, &port); err != nil {
			return err
		}
		if p := plainListenerOf(o.id, o.name, hostKey, port); p != nil {
			plain = append(plain, *p)
		}
		if o.Mode != domain.TLSModeGateway {
			continue
		}
		pc, err := domain.ParseProxyConfig(proxy)
		if err != nil {
			return err
		}
		o.Listen, o.limits = effectiveTLSListen(listen), domain.ListenerLimitsOf(pc)
		others = append(others, o.site())
	}
	if err := rows.Err(); err != nil {
		return err
	}
	if a.plain != nil {
		plain = append(plain, *a.plain)
	}
	return domain.CheckTLSPlacement(a.site(), others, plain)
}

// readTLSAgent reads the WAF agent of the project. An agent that is gone reads as one that never said
// anything and has no host-bound credential, which refuses every key and nothing else.
func readTLSAgent(ctx context.Context, q queryer, projectID, agentID string) (TLSAgent, error) {
	a := TLSAgent{ID: agentID}
	err := q.QueryRow(ctx, `SELECT ag.name, ag.tls_certificates,
		EXISTS (SELECT 1 FROM mtls_credentials c WHERE c.project_id = ag.project_id AND c.host_id IS NOT NULL
		        AND c.host_id = ag.host_id AND c.agent_kind = 'waf' AND c.agent_name = ag.name)
		FROM agents ag WHERE ag.id = $1 AND ag.project_id = $2 AND ag.kind = 'waf' AND ag.deleted_at IS NULL`,
		agentID, projectID).Scan(&a.Name, &a.Supported, &a.HostBound)
	if errors.Is(err, pgx.ErrNoRows) {
		return a, nil
	}
	return a, err
}

// bumpBundle raises the bundle generation of the agent that serves the application. It reports
// whether there was one.
func bumpBundle(ctx context.Context, tx pgx.Tx, appID string) (bool, error) {
	tag, err := tx.Exec(ctx, `INSERT INTO waf_agent_bundles (agent_id,generation,updated_at)
 SELECT agent_id,1,NOW() FROM waf_agent_apps WHERE app_id=$1 AND enabled=TRUE
 ON CONFLICT(agent_id) DO UPDATE SET generation=waf_agent_bundles.generation+1,updated_at=NOW()`, appID)
	return tag.RowsAffected() > 0, err
}

// GetTLS returns the TLS settings of an application of the project and its current certificate,
// nil when it has none. The key of the certificate is not read. It returns pgx.ErrNoRows when the
// application is not in the project.
func (r *TLSRepo) GetTLS(ctx context.Context, projectID, appID string) (AppTLS, *AppCertificate, error) {
	a, err := readTLSApp(ctx, r.pool, projectID, appID, false)
	if err != nil {
		return AppTLS{}, nil, err
	}
	if a.CertificateID == "" {
		return a.AppTLS, nil, nil
	}
	c, err := scanCertificate(r.pool.QueryRow(ctx, certificateColumns+`
		FROM app_certificates c WHERE c.id = $1 AND c.app_id = $2 AND c.project_id = $3 AND c.replaced_at IS NULL`,
		a.CertificateID, appID, projectID))
	if errors.Is(err, pgx.ErrNoRows) {
		return a.AppTLS, nil, nil
	}
	if err != nil {
		return AppTLS{}, nil, err
	}
	return a.AppTLS, &c, nil
}

// certificateColumns is every column of app_certificates except the chain and the key.
const certificateColumns = `SELECT c.id::text, c.app_id::text, c.source, c.leaf_sha256, c.names, c.issuer, c.key_type,
	c.not_before, c.not_after, c.trusted, COALESCE(c.created_by::text, ''), c.created_at, c.replaced_at, c.expiry_notified_days`

func scanCertificate(row pgx.Row) (AppCertificate, error) {
	var c AppCertificate
	if err := row.Scan(&c.ID, &c.AppID, &c.Source, &c.LeafSHA256, &c.Names, &c.Issuer, &c.KeyType,
		&c.NotBefore, &c.NotAfter, &c.Trusted, &c.CreatedBy, &c.CreatedAt, &c.ReplacedAt, &c.ExpiryNotifiedDays); err != nil {
		return AppCertificate{}, err
	}
	if c.Names == nil {
		c.Names = []string{}
	}
	return c, nil
}

// TLSAgent is what the TLS settings need to know of the agent that serves an application.
type TLSAgent struct {
	ID, Name string
	// Supported is what the agent said in Hello: nil when it never did.
	Supported *bool
	// HostBound says whether the agent has a credential bound to its host, kind and name, which is
	// what an uploaded key needs.
	HostBound bool
}

// GetTLSAgent returns the agent that serves the application, nil when none does.
func (r *TLSRepo) GetTLSAgent(ctx context.Context, projectID, appID string) (*TLSAgent, error) {
	a, err := readTLSApp(ctx, r.pool, projectID, appID, false)
	if err != nil {
		return nil, err
	}
	if a.agentID == "" {
		return nil, nil
	}
	out, err := readTLSAgent(ctx, r.pool, projectID, a.agentID)
	if err != nil {
		return nil, err
	}
	return &out, nil
}

// TLSUpdate is what a change of the TLS settings did.
type TLSUpdate struct {
	Previous, Saved AppTLS
	// AgentID is the agent that serves the application, "" when none.
	AgentID string
	// BundleBumped says that the bundle generation of AgentID went up, so the caller pushes it.
	BundleBumped bool
}

// beginTLSChange opens a transaction that holds the application row and, when an agent serves the
// application, the bundle of that agent. Another change of the TLS of an application on that agent
// waits behind it, so it is measured against what this one stored.
//
// Everything runs on the transaction. The checks of the callers never read through the pool, so no
// enterNestedTx is needed here.
func (r *TLSRepo) beginTLSChange(ctx context.Context, projectID, appID string) (pgx.Tx, tlsApp, error) {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return nil, tlsApp{}, err
	}
	a, err := readTLSApp(ctx, tx, projectID, appID, true)
	if err == nil && a.agentID != "" {
		err = lockAgentBundle(ctx, tx, a.agentID)
	}
	if err != nil {
		_ = tx.Rollback(ctx)
		return nil, tlsApp{}, err
	}
	return tx, a, nil
}

// UpdateTLS stores new TLS settings of an application, which s must have passed through
// domain.TLSSettings.Normalize. In one transaction, with the application row and the bundle of its
// agent held, it checks what needs other applications (hosts, listeners, listener settings), and
// for a switch to gateway or a change of source or hosts what the agent and the certificate must
// satisfy. It then writes the settings and raises the bundle generation. Nothing is written when a
// check fails; the error is returned as it is: a *domain.TLSConflictError, a *TLSCoverageError,
// ErrTLSUnsupported, ErrCertificateRequired or ErrAgentNotHostBound. It returns pgx.ErrNoRows when
// the application is not in the project.
//
// The checks apply to applications in gateway mode only: a proxy application keeps its settings
// as a draft, and the agent never sees them. An application that no agent serves is not checked
// against any agent; a move onto one does that.
func (r *TLSRepo) UpdateTLS(ctx context.Context, projectID, appID string, s domain.TLSSettings, now time.Time) (TLSUpdate, error) {
	tx, a, err := r.beginTLSChange(ctx, projectID, appID)
	if err != nil {
		return TLSUpdate{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	out := TLSUpdate{Previous: a.AppTLS, AgentID: a.agentID}

	saved := a.AppTLS
	saved.Mode, saved.Hosts, saved.Listen, saved.RedirectListen, saved.Source = s.Mode, s.Hosts, s.Listen, s.RedirectListen, s.Source
	if saved.Hosts == nil {
		saved.Hosts = []string{}
	}
	if saved.Mode == domain.TLSModeGateway {
		switched := a.Mode != domain.TLSModeGateway
		if switched || a.Source != saved.Source || !slices.Equal(a.Hosts, saved.Hosts) {
			if err := admitGateway(ctx, tx, a, saved, switched, now); err != nil {
				return TLSUpdate{}, err
			}
		}
		if a.agentID != "" {
			moved := a
			moved.AppTLS = saved
			if err := checkTLSFit(ctx, tx, moved, a.agentID); err != nil {
				return TLSUpdate{}, err
			}
		}
		if saved.Source == domain.TLSSourceACME && saved.ACMERequestID == "" {
			saved.ACMERequestID, saved.ACMERequestedAt = uuid.NewString(), &now
		}
	}
	if _, err := tx.Exec(ctx, `UPDATE apps SET tls_mode = $3, tls_hosts = $4, tls_listen = $5, tls_redirect_listen = $6,
		tls_source = $7, acme_request_id = $8, acme_requested_at = $9, updated_at = NOW() WHERE id = $1 AND project_id = $2`,
		appID, projectID, saved.Mode, saved.Hosts, saved.Listen, saved.RedirectListen, saved.Source, saved.ACMERequestID, saved.ACMERequestedAt); err != nil {
		return TLSUpdate{}, err
	}
	// The agent reports the state of one source and of one agent; once either changes, the old
	// report describes something that no longer runs.
	if _, err := tx.Exec(ctx, `DELETE FROM app_tls_status WHERE app_id = $1 AND project_id = $2 AND ($3 = 'proxy' OR source <> $4)`,
		appID, projectID, saved.Mode, saved.Source); err != nil {
		return TLSUpdate{}, err
	}
	if (a.Mode == domain.TLSModeGateway || saved.Mode == domain.TLSModeGateway) && !a.AppTLS.sameForAgent(saved) {
		if out.BundleBumped, err = bumpBundle(ctx, tx, appID); err != nil {
			return TLSUpdate{}, err
		}
	}
	out.Saved = saved
	return out, tx.Commit(ctx)
}

// admitTLSMove checks a move of an application to another agent, whatever its mode. The caller holds
// the row of the application. The bundle of the target is held for every move, because an
// application of any mode brings a plain listener that a gateway application there may already use.
// An application in gateway mode also needs what a switch to gateway needs: the agent feature and,
// for an uploaded source, a host-bound credential. Nothing is checked for an application that stays
// where it is.
func admitTLSMove(ctx context.Context, tx pgx.Tx, projectID, appID, agentID string) error {
	a, err := readTLSApp(ctx, tx, projectID, appID, false)
	if err != nil {
		return err
	}
	if a.agentID == agentID {
		return nil
	}
	if err := lockAgentBundle(ctx, tx, agentID); err != nil {
		return err
	}
	if a.Mode == domain.TLSModeGateway {
		agent, err := readTLSAgent(ctx, tx, projectID, agentID)
		if err != nil {
			return err
		}
		if agent.Supported != nil && !*agent.Supported {
			return ErrTLSUnsupported
		}
		if a.Source == domain.TLSSourceUploaded && !agent.HostBound {
			return ErrAgentNotHostBound
		}
	}
	return checkTLSFit(ctx, tx, a, agentID)
}

// admitGateway checks what an application in gateway mode needs from its agent and its certificate.
// The feature of the agent is asked only for a switch to gateway: an application that already runs
// there stays editable when the agent reports less later.
func admitGateway(ctx context.Context, tx pgx.Tx, a tlsApp, saved AppTLS, switched bool, now time.Time) error {
	var agent TLSAgent
	if a.agentID != "" {
		var err error
		if agent, err = readTLSAgent(ctx, tx, a.projectID, a.agentID); err != nil {
			return err
		}
		if switched && agent.Supported != nil && !*agent.Supported {
			return ErrTLSUnsupported
		}
	}
	if saved.Source != domain.TLSSourceUploaded {
		return nil
	}
	if err := checkCurrentCertificate(ctx, tx, a.projectID, a.id, a.CertificateID, saved.Hosts, now); err != nil {
		return err
	}
	if a.agentID != "" && !agent.HostBound {
		return ErrAgentNotHostBound
	}
	return nil
}

// checkCurrentCertificate checks that the certificate is current, not expired and covers every host.
func checkCurrentCertificate(ctx context.Context, q queryer, projectID, appID, certID string, hosts []string, now time.Time) error {
	if certID == "" {
		return ErrCertificateRequired
	}
	var names []string
	var notAfter time.Time
	err := q.QueryRow(ctx, `SELECT names, not_after FROM app_certificates
		WHERE id = $1 AND app_id = $2 AND project_id = $3 AND replaced_at IS NULL`, certID, appID, projectID).Scan(&names, &notAfter)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && !notAfter.After(now)) {
		return ErrCertificateRequired
	}
	if err != nil {
		return err
	}
	for _, h := range hosts {
		if !domain.CertificateCoversHost(names, h) {
			return &TLSCoverageError{Host: h}
		}
	}
	return nil
}

// NewCertificate is a checked upload, ready to store.
type NewCertificate struct {
	// ID is chosen by the caller, because the sealed key is bound to it.
	ID string
	domain.CertificateInfo
	KeyType string
	// Key is the private key in plain text (domain.CertificateUpload.KeyPEM). InsertCertificate seals
	// it, and zeroes these bytes, whether or not the upload is stored.
	Key []byte
	// CreatedBy is the user, "" when unknown.
	CreatedBy string
}

// CertificateStored is what an upload did.
type CertificateStored struct {
	// ReplacedID is the certificate that was current before, "" when there was none.
	ReplacedID string
	AgentID    string
	// BundleBumped says that the bundle generation of AgentID went up, so the caller pushes it.
	BundleBumped bool
}

// InsertCertificate stores an uploaded certificate as the current one of the application. The row
// is new, so an id never names other bytes. The certificate that was current is marked replaced and
// its key row is deleted. The key is sealed here, bound to the project and the certificate
// (domain.CertificateKeyAAD) with enc, and nothing else is ever written to the key table: a nil
// enc is refused with otp.ErrNoEncryptionKey, and so is a result that is not in the sealed form.
// The plain key bytes of c are zeroed before the function returns. In the same transaction the
// application becomes an uploaded-source one and, when it is in gateway mode, the bundle generation
// goes up. The hosts of the application are checked against the names again under the row lock,
// since a hosts edit may have come in after the caller read them: a *TLSCoverageError. An
// application in gateway mode that switches to an uploaded source needs a host-bound agent
// (ErrAgentNotHostBound). It returns pgx.ErrNoRows when the application is not in the project.
//
// The deleted key row stays readable in dead tuples until vacuum, and in the write-ahead log and in
// backups, as ciphertext; see migration 000124.
func (r *TLSRepo) InsertCertificate(ctx context.Context, projectID, appID string, c NewCertificate, enc *otp.Encryptor) (CertificateStored, error) {
	defer clear(c.Key)
	if enc == nil {
		return CertificateStored{}, otp.ErrNoEncryptionKey
	}
	if len(c.Key) == 0 {
		return CertificateStored{}, errors.New("the certificate has no key")
	}
	if _, err := uuid.Parse(c.ID); err != nil {
		return CertificateStored{}, errors.New("the certificate id is not a UUID")
	}
	sealed, err := enc.SealBound(c.Key, domain.CertificateKeyAAD(projectID, c.ID))
	clear(c.Key)
	if err != nil {
		return CertificateStored{}, err
	}
	if !otp.IsBound(sealed) {
		return CertificateStored{}, errors.New("the key was not sealed")
	}
	tx, a, err := r.beginTLSChange(ctx, projectID, appID)
	if err != nil {
		return CertificateStored{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	out := CertificateStored{ReplacedID: a.CertificateID, AgentID: a.agentID}

	for _, h := range a.Hosts {
		if !domain.CertificateCoversHost(c.Names, h) {
			return CertificateStored{}, &TLSCoverageError{Host: h}
		}
	}
	if a.Mode == domain.TLSModeGateway && a.Source != domain.TLSSourceUploaded && a.agentID != "" {
		agent, err := readTLSAgent(ctx, tx, projectID, a.agentID)
		if err != nil {
			return CertificateStored{}, err
		}
		if !agent.HostBound {
			return CertificateStored{}, ErrAgentNotHostBound
		}
	}
	if err := retireCertificates(ctx, tx, projectID, appID, true); err != nil {
		return CertificateStored{}, err
	}
	names := c.Names
	if names == nil {
		names = []string{}
	}
	if _, err := tx.Exec(ctx, `INSERT INTO app_certificates (id, project_id, app_id, source, chain_pem, leaf_sha256,
		names, issuer, key_type, not_before, not_after, trusted, created_by)
		VALUES ($1, $2, $3, 'uploaded', $4, $5, $6, $7, $8, $9, $10, $11, NULLIF($12, '')::uuid)`,
		c.ID, projectID, appID, c.ChainPEM, c.LeafSHA256, names, c.Issuer, c.KeyType,
		c.NotBefore, c.NotAfter, c.Trusted, c.CreatedBy); err != nil {
		return CertificateStored{}, err
	}
	if _, err := tx.Exec(ctx, `INSERT INTO app_certificate_keys (certificate_id, project_id, key_ciphertext) VALUES ($1, $2, $3)`,
		c.ID, projectID, sealed); err != nil {
		return CertificateStored{}, err
	}
	if _, err := tx.Exec(ctx, `UPDATE apps SET tls_source = 'uploaded', tls_certificate_id = $3, updated_at = NOW()
		WHERE id = $1 AND project_id = $2`, appID, projectID, c.ID); err != nil {
		return CertificateStored{}, err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM app_tls_status WHERE app_id = $1 AND project_id = $2 AND source <> 'uploaded'`, appID, projectID); err != nil {
		return CertificateStored{}, err
	}
	if a.Mode == domain.TLSModeGateway {
		if out.BundleBumped, err = bumpBundle(ctx, tx, appID); err != nil {
			return CertificateStored{}, err
		}
	}
	return out, tx.Commit(ctx)
}

// retireCertificates deletes the key rows of the application's certificates and marks them
// replaced, so no row is current. onlyCurrent limits it to the certificate that is current now (a
// replace); otherwise it takes every certificate of the application (a delete). The retired rows stay
// as a record of what was uploaded.
func retireCertificates(ctx context.Context, tx pgx.Tx, projectID, appID string, onlyCurrent bool) error {
	current := ""
	if onlyCurrent {
		current = " AND replaced_at IS NULL"
	}
	if _, err := tx.Exec(ctx, `DELETE FROM app_certificate_keys WHERE project_id = $2 AND certificate_id IN
		(SELECT id FROM app_certificates WHERE app_id = $1 AND project_id = $2`+current+`)`, appID, projectID); err != nil {
		return err
	}
	_, err := tx.Exec(ctx, `UPDATE app_certificates SET replaced_at = COALESCE(replaced_at, NOW())
		WHERE app_id = $1 AND project_id = $2`+current, appID, projectID)
	return err
}

// DeleteCertificate removes the keys of every certificate of the application and the pointer to the
// current one, and returns the id of the certificate that was current ("" when none). The rows stay
// as a record of what was uploaded. It returns ErrCertificateInUse while the application serves
// from the uploaded certificate (gateway mode, uploaded source), and pgx.ErrNoRows when the
// application is not in the project. The bundle does not change: a bundle names no certificate
// unless the application is in gateway mode with an uploaded source.
func (r *TLSRepo) DeleteCertificate(ctx context.Context, projectID, appID string) (string, error) {
	tx, a, err := r.beginTLSChange(ctx, projectID, appID)
	if err != nil {
		return "", err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if a.Mode == domain.TLSModeGateway && a.Source == domain.TLSSourceUploaded {
		return "", ErrCertificateInUse
	}
	if err := retireCertificates(ctx, tx, projectID, appID, false); err != nil {
		return "", err
	}
	if _, err := tx.Exec(ctx, `UPDATE apps SET tls_certificate_id = NULL, updated_at = NOW() WHERE id = $1 AND project_id = $2`, appID, projectID); err != nil {
		return "", err
	}
	return a.CertificateID, tx.Commit(ctx)
}

// RequestACME asks the agent to order a certificate: the source becomes acme and the request id
// changes, which the agent reads as "order now". It needs at least one host (a *domain.TLSFieldError)
// and refuses a second request within ACMERequestInterval (an *ACMETooSoonError). The bundle
// generation goes up when the application is in gateway mode. It returns pgx.ErrNoRows when the
// application is not in the project.
func (r *TLSRepo) RequestACME(ctx context.Context, projectID, appID string, now time.Time) (TLSUpdate, error) {
	tx, a, err := r.beginTLSChange(ctx, projectID, appID)
	if err != nil {
		return TLSUpdate{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if len(a.Hosts) == 0 {
		return TLSUpdate{}, &domain.TLSFieldError{Field: "hosts", Msg: "at least one host is required"}
	}
	if a.ACMERequestedAt != nil {
		if wait := a.ACMERequestedAt.Add(ACMERequestInterval).Sub(now); wait > 0 {
			return TLSUpdate{}, &ACMETooSoonError{RetryAfter: wait}
		}
	}
	saved := a.AppTLS
	saved.Source, saved.ACMERequestID, saved.ACMERequestedAt = domain.TLSSourceACME, uuid.NewString(), &now
	if _, err := tx.Exec(ctx, `UPDATE apps SET tls_source = 'acme', acme_request_id = $3, acme_requested_at = $4, updated_at = NOW()
		WHERE id = $1 AND project_id = $2`, appID, projectID, saved.ACMERequestID, now); err != nil {
		return TLSUpdate{}, err
	}
	if _, err := tx.Exec(ctx, `DELETE FROM app_tls_status WHERE app_id = $1 AND project_id = $2 AND source <> 'acme'`, appID, projectID); err != nil {
		return TLSUpdate{}, err
	}
	out := TLSUpdate{Previous: a.AppTLS, Saved: saved, AgentID: a.agentID}
	if a.Mode == domain.TLSModeGateway {
		if out.BundleBumped, err = bumpBundle(ctx, tx, appID); err != nil {
			return TLSUpdate{}, err
		}
	}
	return out, tx.Commit(ctx)
}

// CertificateDelivery is what an agent is sent: the public chain and the sealed key.
type CertificateDelivery struct {
	AppID, CertificateID, LeafSHA256, ChainPEM string
	// KeyCiphertext is sealed; the caller opens it with the project and certificate it belongs to.
	KeyCiphertext string
}

// CertificateForDelivery is the one query that decides whether an agent may get the key of a
// certificate, and the only one that reads the key. Everything must hold at once: the application
// is in the project, is enabled on this agent, is in gateway mode with an uploaded source, names
// exactly this certificate as its current one, and the certificate is not replaced and still has its
// key row. It returns pgx.ErrNoRows otherwise. The agent is checked against its own row too: an agent
// that was removed, or that did not say it serves TLS certificates, gets nothing.
func (r *TLSRepo) CertificateForDelivery(ctx context.Context, projectID, agentID, appID, certID string) (CertificateDelivery, error) {
	d := CertificateDelivery{AppID: appID, CertificateID: certID}
	err := r.pool.QueryRow(ctx, `SELECT c.leaf_sha256, c.chain_pem, k.key_ciphertext
		FROM apps a
		JOIN waf_agent_apps waa ON waa.app_id = a.id
		JOIN agents ag ON ag.id = waa.agent_id
		JOIN app_certificates c ON c.id = a.tls_certificate_id
		JOIN app_certificate_keys k ON k.certificate_id = c.id AND k.project_id = c.project_id
		WHERE a.id = $3 AND a.project_id = $1
		  AND waa.agent_id = $2 AND waa.enabled = TRUE
		  AND ag.project_id = a.project_id AND ag.kind = 'waf' AND ag.deleted_at IS NULL AND ag.tls_certificates IS TRUE
		  AND a.tls_mode = 'gateway' AND a.tls_source = 'uploaded' AND a.tls_certificate_id = $4
		  AND c.app_id = a.id AND c.project_id = a.project_id AND c.replaced_at IS NULL`,
		projectID, agentID, appID, certID).Scan(&d.LeafSHA256, &d.ChainPEM, &d.KeyCiphertext)
	return d, err
}

// TLSStatus is what an agent last said about the TLS of an application.
type TLSStatus struct {
	AppID, AgentID string
	Source, State  string
	CertificateID  string
	LeafSHA256     string
	Error          string
	NextAttemptAt  *time.Time
	RequestID      string
	ReceivedAt     time.Time
	// The chain in use, as the server parsed it.
	Names               []string
	Issuer              string
	NotBefore, NotAfter *time.Time
	ChainPEM            string
	ExpiryNotifiedDays  *int
}

// TLSStatusReport is a status as an agent sent it, after the checks that need no database.
type TLSStatusReport struct {
	ProjectID, AgentID, AppID string
	Source, State             string
	// CertificateID is the uploaded certificate the status is about, "" for acme.
	CertificateID string
	LeafSHA256    string
	// Error is cleaned and cut to 1 KiB here whatever the caller did.
	Error         string
	NextAttemptAt *time.Time
	RequestID     string
	// Chain is the chain in use parsed from what the agent sent, nil when it was not parsed because
	// the leaf is the stored one: the stored chain stays then.
	Chain *domain.CertificateInfo
}

const statusErrorMax = 1024

// cleanStatusError drops control characters and cuts the text to statusErrorMax bytes on a
// character boundary.
func cleanStatusError(s string) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || r == unicode.ReplacementChar {
			return -1
		}
		return r
	}, s)
	if len(s) > statusErrorMax {
		n := statusErrorMax
		for n > 0 && s[n]&0xC0 == 0x80 {
			n--
		}
		s = s[:n]
	}
	return s
}

// UpsertTLSStatus stores the state an agent reported, replacing the row of the application. It
// reports false, and stores nothing, unless all of this holds now: the ids are UUIDs, the
// application is in the project, is enabled on the agent, is in gateway mode with this source, an
// acme report carries the current request id, and an uploaded report names the certificate the
// application names as its current one. Nothing about
// the settings of the application changes. The server's own time is the receive time. When the
// report carries no chain and the leaf is the stored one, the stored chain and the expiry
// threshold already mailed stay; with another leaf both are cleared.
func (r *TLSRepo) UpsertTLSStatus(ctx context.Context, s TLSStatusReport) (bool, error) {
	// A malformed id would otherwise be a database error for what is only a bad report.
	for _, id := range []string{s.ProjectID, s.AgentID, s.AppID} {
		if _, err := uuid.Parse(id); err != nil {
			return false, nil
		}
	}
	if s.CertificateID != "" {
		if _, err := uuid.Parse(s.CertificateID); err != nil {
			return false, nil
		}
	}
	var names []string
	var issuer, chain string
	var notBefore, notAfter *time.Time
	if c := s.Chain; c != nil {
		names, issuer, chain = c.Names, c.Issuer, c.ChainPEM
		notBefore, notAfter = &c.NotBefore, &c.NotAfter
	}
	if names == nil {
		names = []string{}
	}
	tag, err := r.pool.Exec(ctx, `INSERT INTO app_tls_status (app_id, project_id, agent_id, source, state, certificate_id, leaf_sha256,
			error, next_attempt_at, request_id, received_at, names, issuer, not_before, not_after, chain_pem)
		SELECT a.id, a.project_id, waa.agent_id, $4::text, $5::text, CASE WHEN $4::text = 'uploaded' THEN c.id END, $7::text, $8::text, $9::timestamptz, $10::text, NOW(),
			$11::text[], $12::text, $13::timestamptz, $14::timestamptz, $15::text
		FROM apps a
		JOIN waf_agent_apps waa ON waa.app_id = a.id AND waa.enabled = TRUE AND waa.agent_id = $3
		JOIN agents ag ON ag.id = waa.agent_id AND ag.project_id = a.project_id AND ag.kind = 'waf' AND ag.deleted_at IS NULL
		LEFT JOIN app_certificates c ON c.id = a.tls_certificate_id AND c.app_id = a.id AND c.project_id = a.project_id
		WHERE a.id = $1 AND a.project_id = $2 AND a.tls_mode = 'gateway' AND a.tls_source = $4::text
		  AND ($4::text <> 'acme' OR a.acme_request_id = $10::text)
		  AND ($4::text <> 'uploaded' OR c.id = NULLIF($6::text, '')::uuid)
		ON CONFLICT (app_id) DO UPDATE SET
			agent_id = EXCLUDED.agent_id, source = EXCLUDED.source, state = EXCLUDED.state,
			certificate_id = EXCLUDED.certificate_id, leaf_sha256 = EXCLUDED.leaf_sha256, error = EXCLUDED.error,
			next_attempt_at = EXCLUDED.next_attempt_at, request_id = EXCLUDED.request_id, received_at = EXCLUDED.received_at,
			names = CASE WHEN $16::boolean OR app_tls_status.leaf_sha256 <> EXCLUDED.leaf_sha256 THEN EXCLUDED.names ELSE app_tls_status.names END,
			issuer = CASE WHEN $16::boolean OR app_tls_status.leaf_sha256 <> EXCLUDED.leaf_sha256 THEN EXCLUDED.issuer ELSE app_tls_status.issuer END,
			not_before = CASE WHEN $16::boolean OR app_tls_status.leaf_sha256 <> EXCLUDED.leaf_sha256 THEN EXCLUDED.not_before ELSE app_tls_status.not_before END,
			not_after = CASE WHEN $16::boolean OR app_tls_status.leaf_sha256 <> EXCLUDED.leaf_sha256 THEN EXCLUDED.not_after ELSE app_tls_status.not_after END,
			chain_pem = CASE WHEN $16::boolean OR app_tls_status.leaf_sha256 <> EXCLUDED.leaf_sha256 THEN EXCLUDED.chain_pem ELSE app_tls_status.chain_pem END,
			expiry_notified_days = CASE WHEN app_tls_status.leaf_sha256 = EXCLUDED.leaf_sha256 AND EXCLUDED.leaf_sha256 <> ''
				THEN app_tls_status.expiry_notified_days ELSE NULL END`,
		s.AppID, s.ProjectID, s.AgentID, s.Source, s.State, s.CertificateID, s.LeafSHA256,
		cleanStatusError(s.Error), s.NextAttemptAt, s.RequestID, names, issuer, notBefore, notAfter, chain,
		s.Chain != nil)
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}

// GetTLSStatus returns what the agent last reported for the application of the project, nil when
// it reported nothing since the settings last changed.
func (r *TLSRepo) GetTLSStatus(ctx context.Context, projectID, appID string) (*TLSStatus, error) {
	var s TLSStatus
	err := r.pool.QueryRow(ctx, `SELECT s.app_id::text, s.agent_id::text, s.source, s.state, COALESCE(s.certificate_id::text, ''),
		s.leaf_sha256, s.error, s.next_attempt_at, s.request_id, s.received_at, s.names, s.issuer, s.not_before, s.not_after,
		s.chain_pem, s.expiry_notified_days
		FROM app_tls_status s WHERE s.app_id = $1 AND s.project_id = $2`, appID, projectID).
		Scan(&s.AppID, &s.AgentID, &s.Source, &s.State, &s.CertificateID, &s.LeafSHA256, &s.Error, &s.NextAttemptAt,
			&s.RequestID, &s.ReceivedAt, &s.Names, &s.Issuer, &s.NotBefore, &s.NotAfter, &s.ChainPEM, &s.ExpiryNotifiedDays)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if s.Names == nil {
		s.Names = []string{}
	}
	return &s, nil
}

// ExpiryCandidate is the certificate of an application in gateway mode that the expiry warnings
// look at: the uploaded certificate for an uploaded source, the chain the agent reported for acme.
type ExpiryCandidate struct {
	ProjectID, AppID, AppName string
	Hosts                     []string
	Source                    string
	// CertificateID is set for an uploaded source only.
	CertificateID string
	LeafSHA256    string
	NotAfter      time.Time
	// NotifiedDays is the last threshold that was mailed for this certificate, nil when none.
	NotifiedDays *int
}

// ListExpiryCandidates returns the certificate in use of every application in gateway mode that has
// one, for the background loop that warns before expiry. It reads across projects on purpose; every
// row carries its project.
func (r *TLSRepo) ListExpiryCandidates(ctx context.Context) ([]ExpiryCandidate, error) {
	rows, err := r.pool.Query(ctx, `SELECT a.project_id::text, a.id::text, a.name, a.tls_hosts, a.tls_source,
		COALESCE(c.id::text, ''), COALESCE(c.leaf_sha256, s.leaf_sha256, ''), COALESCE(c.not_after, s.not_after),
		COALESCE(c.expiry_notified_days, s.expiry_notified_days)
		FROM apps a
		LEFT JOIN app_certificates c ON a.tls_source = 'uploaded' AND c.id = a.tls_certificate_id AND c.app_id = a.id
			AND c.project_id = a.project_id AND c.replaced_at IS NULL
		LEFT JOIN app_tls_status s ON a.tls_source = 'acme' AND s.app_id = a.id AND s.project_id = a.project_id
		WHERE a.tls_mode = 'gateway' AND COALESCE(c.not_after, s.not_after) IS NOT NULL
		ORDER BY a.project_id, a.id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []ExpiryCandidate
	for rows.Next() {
		var c ExpiryCandidate
		if err := rows.Scan(&c.ProjectID, &c.AppID, &c.AppName, &c.Hosts, &c.Source, &c.CertificateID, &c.LeafSHA256, &c.NotAfter, &c.NotifiedDays); err != nil {
			return nil, err
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// MarkExpiryNotified records that the warning for the threshold (in days) was sent for the
// certificate of c. It reports false when the certificate is no longer the one in use: a certificate
// that was replaced meanwhile starts again from nothing.
func (r *TLSRepo) MarkExpiryNotified(ctx context.Context, c ExpiryCandidate, days int) (bool, error) {
	var tag pgconn.CommandTag
	var err error
	if c.Source == domain.TLSSourceUploaded {
		tag, err = r.pool.Exec(ctx, `UPDATE app_certificates SET expiry_notified_days = $4
			WHERE id = $3 AND app_id = $2 AND project_id = $1 AND replaced_at IS NULL`, c.ProjectID, c.AppID, c.CertificateID, days)
	} else {
		tag, err = r.pool.Exec(ctx, `UPDATE app_tls_status SET expiry_notified_days = $4
			WHERE app_id = $2 AND project_id = $1 AND leaf_sha256 = $3`, c.ProjectID, c.AppID, c.LeafSHA256, days)
	}
	if err != nil {
		return false, err
	}
	return tag.RowsAffected() == 1, nil
}
