package repository

import (
	"context"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

type Repository struct {
	DB               *pgxpool.Pool
	User             *UserRepo
	Project          *ProjectRepo
	EBPF             *EBPFRepo
	App              *AppRepo
	WAF              *WAFRepo
	WAFRollup        *WAFRollupRepo
	Host             *HostRepo
	Audit            *AuditRepo
	AgentGRPC        *AgentGRPCRepo
	SystemSettings   *SystemSettingsRepo
	ProjectMember    *ProjectMemberRepo
	InviteToken      *InviteTokenRepo
	DetectionRules   *DetectionRulesRepo
	CorrelationRules *CorrelationRulesRepo
	Incident         *IncidentRepo
	BackupCodes      *BackupCodeRepo
	WafCustomRules   *WafCustomRulesRepo
	HostFleet        *HostFleetRepo
	PasswordReset    *PasswordResetRepo
	HostEnroll       *HostEnrollRepo
	Storage          *StorageRepo
	TLS              *TLSRepo

	// keyTuning is the lock key and the waits of the encryption key lock; the zero value is the
	// production setting, and a test sets its own.
	keyTuning keyTuning
}

// PoolOptions sizes the shared connection pool. A zero value keeps pgx's own
// defaults, which is right for short-lived CLI commands and wrong for the
// server: pgx defaults to max(4, NumCPU), and that pool is shared by decision
// ingest, dashboard queries, auth, and the eBPF and host event paths at once.
type PoolOptions struct {
	MaxConns int
	MinConns int
	// StatementTimeout is set as the session statement_timeout on every
	// pooled connection: the database cancels a statement that runs
	// longer, so a runaway query cannot pin a connection. 0 leaves the
	// server's own setting in place.
	StatementTimeout time.Duration
}

// New opens the pool with pgx's defaults. Use NewWithPool for the server.
func New(ctx context.Context, dsn string) (*Repository, error) {
	return NewWithPool(ctx, dsn, PoolOptions{})
}

func NewWithPool(ctx context.Context, dsn string, opts PoolOptions) (*Repository, error) {
	poolCfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	if opts.MaxConns > 0 {
		poolCfg.MaxConns = clampInt32(opts.MaxConns)
	}
	if opts.MinConns > 0 {
		poolCfg.MinConns = clampInt32(opts.MinConns)
	}
	// A connection that lives forever also holds a server-side backend forever,
	// and keeps talking to a database that may have been failed over underneath
	// it. Recycling bounds both.
	if poolCfg.MaxConnLifetime == 0 {
		poolCfg.MaxConnLifetime = time.Hour
	}
	if poolCfg.MaxConnIdleTime == 0 {
		poolCfg.MaxConnIdleTime = 30 * time.Minute
	}
	applyStatementTimeout(poolCfg, opts.StatementTimeout)
	pool, err := pgxpool.NewWithConfig(ctx, poolCfg)
	if err != nil {
		return nil, err
	}
	if err := pool.Ping(ctx); err != nil {
		return nil, err
	}
	return FromPool(pool), nil
}

// applyStatementTimeout puts statement_timeout into the startup runtime
// params, so it holds for every connection the pool opens, including ones
// opened after a failover. A DSN that already sets it wins.
func applyStatementTimeout(poolCfg *pgxpool.Config, d time.Duration) {
	if d <= 0 {
		return
	}
	if poolCfg.ConnConfig.RuntimeParams == nil {
		poolCfg.ConnConfig.RuntimeParams = map[string]string{}
	}
	if _, set := poolCfg.ConnConfig.RuntimeParams["statement_timeout"]; set {
		return
	}
	poolCfg.ConnConfig.RuntimeParams["statement_timeout"] = strconv.FormatInt(d.Milliseconds(), 10)
}

// FromPool wires every sub-repository to an existing pool. The pool is not
// pinged; NewWithPool is the constructor that verifies the database.
func FromPool(pool *pgxpool.Pool) *Repository {
	projects := &ProjectRepo{pool: pool}
	host := &HostRepo{pool: pool}
	agentGRPC := NewAgentGRPCRepo(pool)
	return &Repository{
		DB:               pool,
		User:             &UserRepo{pool: pool},
		Project:          projects,
		EBPF:             &EBPFRepo{pool: pool, eventCache: newTraceEventCache(), projects: projects},
		App:              &AppRepo{pool: pool},
		WAF:              &WAFRepo{pool: pool},
		WAFRollup:        &WAFRollupRepo{pool: pool},
		Host:             host,
		Audit:            &AuditRepo{pool: pool},
		AgentGRPC:        agentGRPC,
		SystemSettings:   NewSystemSettingsRepo(pool),
		ProjectMember:    &ProjectMemberRepo{pool: pool},
		InviteToken:      &InviteTokenRepo{pool: pool},
		DetectionRules:   NewDetectionRulesRepo(pool),
		CorrelationRules: NewCorrelationRulesRepo(pool),
		Incident:         &IncidentRepo{pool: pool},
		BackupCodes:      &BackupCodeRepo{pool: pool},
		WafCustomRules:   &WafCustomRulesRepo{pool: pool},
		HostFleet:        &HostFleetRepo{pool: pool},
		PasswordReset:    &PasswordResetRepo{pool: pool},
		HostEnroll:       &HostEnrollRepo{pool: pool, host: host, grpc: agentGRPC},
		Storage:          NewStorageRepo(pool),
		TLS:              &TLSRepo{pool: pool},
	}
}

func (r *Repository) Close() {
	r.DB.Close()
}

// sweeperDeps satisfies KeySweeperDeps by fanning the three maintenance
// calls out to the individual sub-repos. Declared as an unexported struct so
// callers only see the interface.
type sweeperDeps struct{ r *Repository }

func (s sweeperDeps) PurgeExpiredPrevKeys(ctx context.Context) (int64, error) {
	return s.r.Host.PurgeExpiredPrevKeys(ctx)
}
func (s sweeperDeps) MarkOfflineStale(ctx context.Context) (int64, error) {
	return s.r.Host.MarkOfflineStale(ctx)
}

// KeySweeperDeps returns the repo-backed adapter used by RunKeySweeper.
func (r *Repository) KeySweeperDeps() KeySweeperDeps { return sweeperDeps{r: r} }
