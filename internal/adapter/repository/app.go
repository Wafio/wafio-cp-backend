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

	// MaintenanceEnabled is the switch of apps.maintenance (migration 000119); the rest of that
	// object is read with GetMaintenance.
	MaintenanceEnabled bool `json:"maintenance_enabled"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
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
		       COALESCE((maintenance->>'enabled')::boolean, false),
		       created_at, updated_at
		FROM apps WHERE id = $1`, id,
	).Scan(
		&a.ID, &a.ProjectID, &a.Name,
		&a.ListenHost, &a.ListenPort, &a.UpstreamURL,
		&a.ProxyConfig,
		&a.FCGIDocRoot, &a.FCGIIndex,
		&a.MaintenanceEnabled,
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
		       COALESCE((maintenance->>'enabled')::boolean, false),
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
			&a.MaintenanceEnabled,
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
