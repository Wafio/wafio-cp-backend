package repository

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/jackc/pgx/v5"

	"github.com/wafio/wafio-cp-backend/internal/domain"
)

// AppPatch changes routing and its bundle revision in one transaction. Nil
// fields preserve stored values; validation happens before opening the transaction.
type AppPatch struct {
	Name, ListenHost, Upstream, FCGIDocRoot, FCGIIndex *string
	ListenPort                                         *int
	FCGIKeepConn                                       *bool
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
	if p.FCGIKeepConn != nil {
		row.FCGIKeepConn = *p.FCGIKeepConn
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

// touchesListener says whether the patch names a listen host or port. Whether that moves the plain
// listener is decided against the stored one, under the lock (UpdateAtomic).
func (p AppPatch) touchesListener() bool {
	return p.ListenHost != nil || p.ListenPort != nil
}

// samePlainListener compares the plain listeners of an application before and after a change; nil is
// none.
func samePlainListener(a, b *domain.PlainListener) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Addr == b.Addr
}

// asPlainListenerConflict names the listen port as the setting to change in a listener conflict. The
// forms that move a plain listener have no HTTPS listener field, and it is their listen port that
// caused the conflict.
func asPlainListenerConflict(err error) error {
	var c *domain.TLSConflictError
	if errors.As(err, &c) && c.Code == domain.TLSConflictListen {
		named := *c
		named.Field = "listen_port"
		return &named
	}
	return err
}

// UpdateAtomic applies the patch. With admit, the application row is locked first and admit is
// called with its stored maintenance object and the agent that serves it (empty when none) and its
// mode, with the bundle of that agent locked (lockAgentBundle), before anything is written; an
// error from it is returned as it is and nothing changes. A nil admit checks no maintenance rule.
//
// A patch that moves the plain listener (a new listen host or port that differs from the stored
// one) is also checked, with or without admit, against the TLS listeners of the other applications of
// the agent that serves the application (checkTLSFit): the bundle the agent gets afterwards must not
// name an address twice, because the agent refuses such a bundle as a whole. The row and the bundle
// are locked for that, and the error is a *domain.TLSConflictError naming listen_port; nothing
// changes. A save that sends the listen fields it already has is not checked again.
//
// A save that waits for those locks holds a pool connection, so it takes a place among the open
// transactions of its kind (enterNestedTx) whenever it takes them.
func (r *AppRepo) UpdateAtomic(ctx context.Context, projectID, appID string, patch AppPatch,
	admit func(stored domain.Maintenance, agentID, mode string) error) error {
	listener := patch.touchesListener()
	locked := admit != nil || listener
	if locked {
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
	servedBy := ""
	var before *domain.PlainListener
	if locked {
		var raw []byte
		if err := tx.QueryRow(ctx, `SELECT maintenance FROM apps WHERE id = $1 AND project_id = $2 FOR UPDATE`, appID, projectID).Scan(&raw); err != nil {
			return err
		}
		agentID, mode, err := enabledAssignment(ctx, tx, appID)
		if err != nil {
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
		if admit != nil {
			if err := admit(stored, agentID, mode); err != nil {
				return err
			}
		}
		if listener && agentID != "" {
			app, err := readTLSApp(ctx, tx, projectID, appID, false)
			if err != nil {
				return err
			}
			servedBy, before = agentID, app.plain
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
 proxy_config=COALESCE($9::jsonb,proxy_config), fcgi_keep_conn=COALESCE($10,fcgi_keep_conn),
 updated_at=NOW() WHERE id=$1 AND project_id=$2`,
		appID, projectID, patch.Name, patch.ListenHost, patch.ListenPort, patch.Upstream, patch.FCGIDocRoot, patch.FCGIIndex, proxy,
		patch.FCGIKeepConn)
	if err != nil {
		return err
	}
	if result.RowsAffected() != 1 {
		return pgx.ErrNoRows
	}
	if servedBy != "" {
		app, err := readTLSApp(ctx, tx, projectID, appID, false)
		if err != nil {
			return err
		}
		if !samePlainListener(before, app.plain) {
			if err := checkTLSFit(ctx, tx, app, servedBy); err != nil {
				return asPlainListenerConflict(err)
			}
		}
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
