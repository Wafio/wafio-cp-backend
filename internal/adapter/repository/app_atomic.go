package repository

import (
	"context"
	"encoding/json"
	"github.com/jackc/pgx/v5"
)

// AppPatch changes routing and its bundle revision in one transaction. Nil
// fields preserve stored values; validation happens before opening the transaction.
type AppPatch struct {
	Name, ListenHost, Upstream, FCGIDocRoot, FCGIIndex *string
	ListenPort                                         *int
	ProxyConfig                                        json.RawMessage
	AgentID, Mode                                      string
}

func (r *AppRepo) UpdateAtomic(ctx context.Context, projectID, appID string, patch AppPatch) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
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
