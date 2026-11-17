package repository

import (
	"context"
	"encoding/json"
	"strconv"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/wafio/wafio-cp-backend/internal/domain"
)

// ── App models ────────────────────────────────────────────────────────────

type App struct {
	ID        string `json:"id"`
	ProjectID string `json:"project_id"`
	Name      string `json:"name"`

	// WAF inline-proxy routing
	ListenHost  *string `json:"listen_host"`
	ListenPort  *int    `json:"listen_port"`
	UpstreamURL *string `json:"upstream_url"`

	// Per-app reverse-proxy config (migration 000061).
	ProxyConfig json.RawMessage `json:"proxy_config,omitempty"`
	// ProxyWarnings is derived from ProxyConfig on read, e.g.
	// TRUSTED_PROXIES_UNSET; absent when there is nothing to flag.
	ProxyWarnings []domain.ProxyWarning `json:"proxy_warnings,omitempty"`
	// Set only on reads by callers below member: header values in
	// proxy_config and userinfo in upstream_url were blanked;
	// ProxyHeaderValuesSet tells whether any header value was configured.
	SecretsRedacted      bool `json:"secrets_redacted,omitempty"`
	ProxyHeaderValuesSet bool `json:"proxy_header_values_set,omitempty"`

	// FastCGI upstream settings (migration 000044). Read-only here: they are
	// written by the route/app update paths (app_atomic.go, app_wafkey.go).
	FCGIDocRoot string `json:"fcgi_doc_root"`
	FCGIIndex   string `json:"fcgi_index"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

type Deployment struct {
	ID         string     `json:"id"`
	AppID      string     `json:"app_id"`
	GitCommit  string     `json:"git_commit,omitempty"`
	GitMessage string     `json:"git_message,omitempty"`
	Status     string     `json:"status"`
	BuildLog   string     `json:"build_log,omitempty"`
	StartedAt  time.Time  `json:"started_at"`
	FinishedAt *time.Time `json:"finished_at,omitempty"`
}

// ── Repository ────────────────────────────────────────────────────────────

type AppRepo struct {
	pool *pgxpool.Pool
}

// ── App CRUD ──────────────────────────────────────────────────────────────

func (r *AppRepo) Create(ctx context.Context, a *App) (*App, error) {
	err := r.pool.QueryRow(ctx, `
		INSERT INTO apps (project_id, name)
		VALUES ($1, $2)
		RETURNING id, created_at, updated_at`,
		a.ProjectID, a.Name,
	).Scan(&a.ID, &a.CreatedAt, &a.UpdatedAt)
	return a, err
}

func (r *AppRepo) GetByID(ctx context.Context, id string) (*App, error) {
	a := &App{}
	err := r.pool.QueryRow(ctx, `
		SELECT id, project_id, name,
		       listen_host, listen_port, upstream_url,
		       COALESCE(proxy_config, '{}'::jsonb),
		       COALESCE(fcgi_doc_root, ''), COALESCE(fcgi_index, ''),
		       created_at, updated_at
		FROM apps WHERE id = $1`, id,
	).Scan(
		&a.ID, &a.ProjectID, &a.Name,
		&a.ListenHost, &a.ListenPort, &a.UpstreamURL,
		&a.ProxyConfig,
		&a.FCGIDocRoot, &a.FCGIIndex,
		&a.CreatedAt, &a.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	a.ProxyWarnings = domain.ProxyConfigWarnings(a.ProxyConfig)
	return a, nil
}

func (r *AppRepo) ListByProject(ctx context.Context, projectID string) ([]App, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, project_id, name,
		       listen_host, listen_port, upstream_url,
		       COALESCE(proxy_config, '{}'::jsonb),
		       COALESCE(fcgi_doc_root, ''), COALESCE(fcgi_index, ''),
		       created_at, updated_at
		FROM apps WHERE project_id = $1 ORDER BY created_at`, projectID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	apps := []App{}
	for rows.Next() {
		var a App
		if err := rows.Scan(
			&a.ID, &a.ProjectID, &a.Name,
			&a.ListenHost, &a.ListenPort, &a.UpstreamURL,
			&a.ProxyConfig,
			&a.FCGIDocRoot, &a.FCGIIndex,
			&a.CreatedAt, &a.UpdatedAt,
		); err != nil {
			return nil, err
		}
		a.ProxyWarnings = domain.ProxyConfigWarnings(a.ProxyConfig)
		apps = append(apps, a)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return apps, nil
}

func (r *AppRepo) Update(ctx context.Context, a *App) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE apps SET name = $2, updated_at = NOW()
		WHERE id = $1`,
		a.ID, a.Name,
	)
	return err
}

func (r *AppRepo) Delete(ctx context.Context, id string) error {
	_, err := r.pool.Exec(ctx, `DELETE FROM apps WHERE id = $1`, id)
	return err
}

func (r *AppRepo) CountByProject(ctx context.Context, projectID string) (int, error) {
	var n int
	err := r.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM apps WHERE project_id = $1`, projectID).Scan(&n)
	return n, err
}

func (r *AppRepo) CountByUser(ctx context.Context, userID string) (int, error) {
	var n int
	err := r.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM apps a
		JOIN projects p ON a.project_id = p.id
		WHERE p.user_id = $1`, userID).Scan(&n)
	return n, err
}

// ── Deployment CRUD ───────────────────────────────────────────────────────

func (r *AppRepo) CreateDeployment(ctx context.Context, appID string) (*Deployment, error) {
	d := &Deployment{}
	err := r.pool.QueryRow(ctx, `
		INSERT INTO deployments (app_id) VALUES ($1)
		RETURNING id, app_id, status, started_at`, appID,
	).Scan(&d.ID, &d.AppID, &d.Status, &d.StartedAt)
	return d, err
}

func (r *AppRepo) UpdateDeployment(ctx context.Context, id, status, buildLog, gitCommit, gitMessage string) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE deployments SET status = $2, build_log = $3, git_commit = $4, git_message = $5,
		       finished_at = CASE WHEN $2::varchar IN ('live','failed') THEN NOW() ELSE finished_at END
		WHERE id = $1`, id, status, buildLog, gitCommit, gitMessage)
	return err
}

func (r *AppRepo) ListDeployments(ctx context.Context, appID string, limit int) ([]Deployment, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, app_id, COALESCE(git_commit,''), COALESCE(git_message,''), status, COALESCE(build_log,''), started_at, finished_at
		FROM deployments WHERE app_id = $1
		ORDER BY started_at DESC LIMIT $2`, appID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	deps := []Deployment{}
	for rows.Next() {
		var d Deployment
		if err := rows.Scan(&d.ID, &d.AppID, &d.GitCommit, &d.GitMessage,
			&d.Status, &d.BuildLog, &d.StartedAt, &d.FinishedAt); err != nil {
			return nil, err
		}
		deps = append(deps, d)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return deps, nil
}

func (r *AppRepo) GetDeployment(ctx context.Context, id string) (*Deployment, error) {
	d := &Deployment{}
	err := r.pool.QueryRow(ctx, `
		SELECT id, app_id, COALESCE(git_commit,''), COALESCE(git_message,''), status, COALESCE(build_log,''), started_at, finished_at
		FROM deployments WHERE id = $1`, id,
	).Scan(&d.ID, &d.AppID, &d.GitCommit, &d.GitMessage,
		&d.Status, &d.BuildLog, &d.StartedAt, &d.FinishedAt)
	return d, err
}

// ListenLookup is a minimal projection of (project_id → (host:port → app_id))
// used by the gRPC stream to enrich live WAF decisions whose AppID is empty
// or "static" (agents in --static-upstream mode). Returns rows for all apps
// in the project that have a listen_host + listen_port configured.
func (r *AppRepo) ListListenTargets(ctx context.Context, projectID string) (map[string]string, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, listen_host, listen_port
		FROM apps
		WHERE project_id = $1 AND listen_host IS NOT NULL AND listen_port IS NOT NULL`,
		projectID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := make(map[string]string)
	for rows.Next() {
		var id, host string
		var port int
		if err := rows.Scan(&id, &host, &port); err != nil {
			return nil, err
		}
		// Index by both "host:port" and "host" so we tolerate clients that
		// send the Host header without an explicit port.
		out[host+":"+strconv.Itoa(port)] = id
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// BundleAppRow is a row returned by ListBundleApps. Used by the gRPC bundle
// loader to build the JSON the agent applies to its inline proxy router.
type BundleAppRow struct {
	AppID      string
	ListenHost string
	ListenPort int
	Upstream   string
	Mode       string
}

// ListBundleApps returns every app in the project that has a complete
// (listen_host, listen_port, upstream_url) tuple — i.e. is ready to serve
// traffic through a WAF agent. The second return value is the bundle
// generation (max updated_at as unix seconds) so the agent can short-circuit
// when nothing has changed since the last sync.
func (r *AppRepo) ListBundleApps(ctx context.Context, projectID string) ([]BundleAppRow, int64, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT id, listen_host, listen_port, upstream_url,
		       EXTRACT(EPOCH FROM updated_at)::bigint AS gen
		FROM apps
		WHERE project_id = $1
		  AND listen_host  IS NOT NULL
		  AND listen_port  IS NOT NULL
		  AND upstream_url IS NOT NULL
		ORDER BY listen_port`, projectID)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	out := []BundleAppRow{}
	var maxGen int64
	for rows.Next() {
		var row BundleAppRow
		var gen int64
		if err := rows.Scan(&row.AppID, &row.ListenHost, &row.ListenPort, &row.Upstream, &gen); err != nil {
			return nil, 0, err
		}
		row.Mode = "block"
		if gen > maxGen {
			maxGen = gen
		}
		out = append(out, row)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return out, maxGen, nil
}
