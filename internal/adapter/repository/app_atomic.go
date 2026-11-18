package repository

import (
	"context"
	"encoding/json"

	"github.com/jackc/pgx/v5"

	"github.com/wafio/wafio-cp-backend/internal/domain"
)

// AppPatch changes routing and its bundle revision in one transaction. Nil
// fields preserve stored values; validation happens before opening the transaction.
type AppPatch struct {
	Name, ListenHost, Upstream, FCGIDocRoot, FCGIIndex *string
	ListenPort                                         *int
	ProxyConfig                                        json.RawMessage
	AgentID, Mode                                      string
}

// ApplyTo changes a bundle row of the application the way the patch changes the application.
func (p AppPatch) ApplyTo(row *WAFBundleAppRow) {
	if p.ListenHost != nil {
		row.ListenHost = *p.ListenHost
	}
	if p.Upstream != nil {
		row.Upstream = *p.Upstream
	}
	if p.FCGIDocRoot != nil {
		row.FCGIDocRoot = *p.FCGIDocRoot
	}
	if p.FCGIIndex != nil {
		row.FCGIIndex = *p.FCGIIndex
	}
	if p.ListenPort != nil {
		row.ListenPort = *p.ListenPort
	}
	if len(p.ProxyConfig) > 0 {
		row.ProxyConfig = p.ProxyConfig
	}
	if p.Mode != "" {
		row.Mode = p.Mode
	}
}

// UpdateAtomic applies the patch. With admit, the application row is locked first and admit is
// called with its stored maintenance object and the agent that serves it (empty when none) and its
// mode, with the bundle of that agent locked (lockAgentBundle), before anything is written; an
// error from it is returned as it is and nothing changes. A nil admit checks nothing.
func (r *AppRepo) UpdateAtomic(ctx context.Context, projectID, appID string, patch AppPatch,
	admit func(stored domain.Maintenance, agentID, mode string) error) error {
	if admit != nil {
		leave, err := enterNestedTx(ctx)
		if err != nil {
			return err
		}
		defer leave()
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	if admit != nil {
		var raw []byte
		var agentID, mode string
		if err := tx.QueryRow(ctx, `SELECT a.maintenance, COALESCE(waa.agent_id::text, ''), COALESCE(waa.mode, '')
			FROM apps a LEFT JOIN waf_agent_apps waa ON waa.app_id = a.id AND waa.enabled = TRUE
			WHERE a.id = $1 AND a.project_id = $2 FOR UPDATE OF a`, appID, projectID).Scan(&raw, &agentID, &mode); err != nil {
			return err
		}
		stored, err := decodeMaintenance(raw)
		if err != nil {
			return err
		}
		if agentID != "" {
			if err := lockAgentBundle(ctx, tx, agentID); err != nil {
				return err
			}
		}
		if err := admit(stored, agentID, mode); err != nil {
			return err
		}
	}
	var proxy *string
	if len(patch.ProxyConfig) > 0 {
		value := string(patch.ProxyConfig)
		proxy = &value
	}
	result, err := tx.Exec(ctx, `UPDATE apps SET name=COALESCE($3,name), listen_host=COALESCE($4,listen_host),
 listen_port=COALESCE($5,listen_port), upstream_url=COALESCE($6,upstream_url),
 fcgi_doc_root=COALESCE($7,fcgi_doc_root), fcgi_index=COALESCE($8,fcgi_index),
 proxy_config=COALESCE($9::jsonb,proxy_config), updated_at=NOW() WHERE id=$1 AND project_id=$2`,
		appID, projectID, patch.Name, patch.ListenHost, patch.ListenPort, patch.Upstream, patch.FCGIDocRoot, patch.FCGIIndex, proxy)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return pgx.ErrNoRows
	}
	if patch.Mode != "" {
		result, err = tx.Exec(ctx, `UPDATE waf_agent_apps SET mode=$3, updated_at=NOW() WHERE app_id=$1 AND agent_id=$2 AND enabled=TRUE`, appID, patch.AgentID, patch.Mode)
		if err != nil {
			return err
		}
		if result.RowsAffected() != 1 {
			return pgx.ErrNoRows
		}
	}
	_, err = tx.Exec(ctx, `INSERT INTO waf_agent_bundles (agent_id,generation,updated_at)
 SELECT agent_id,1,NOW() FROM waf_agent_apps WHERE app_id=$1 AND enabled=TRUE
 ON CONFLICT(agent_id) DO UPDATE SET generation=waf_agent_bundles.generation+1,updated_at=NOW()`, appID)
	if err != nil {
		return err
	}
	return tx.Commit(ctx)
}
