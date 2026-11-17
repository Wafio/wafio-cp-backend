package repository

import "context"

// SetRouting stores the listen_host and upstream_url used by WAF agents when
// forwarding traffic for this application.
func (r *AppRepo) SetRouting(ctx context.Context, appID, listenHost, upstreamURL string) error {
	_, err := r.pool.Exec(ctx, `
		UPDATE apps
		   SET listen_host  = NULLIF($2,''),
		       upstream_url = NULLIF($3,''),
		       updated_at   = NOW()
		 WHERE id = $1`, appID, listenHost, upstreamURL)
	return err
}

// SetInlineProxy stores the listen_host, listen_port, and upstream_url for a
// WAF inline proxy route. The agent binds listen_host:listen_port and forwards
// traffic to upstream_url.
func (r *AppRepo) SetInlineProxy(ctx context.Context, appID, listenHost string, listenPort int, upstreamURL string) error {
	var portVal interface{}
	if listenPort > 0 {
		portVal = listenPort
	}
	_, err := r.pool.Exec(ctx, `
		UPDATE apps
		   SET listen_host  = NULLIF($2,''),
		       listen_port  = $3,
		       upstream_url = NULLIF($4,''),
		       updated_at   = NOW()
		 WHERE id = $1`, appID, listenHost, portVal, upstreamURL)
	return err
}

// SetFCGIConfig persists the FastCGI document root and index file for an app
// (migration 000044). Empty strings are stored as empty (not NULL) to allow
// clearing previously set values.
func (r *AppRepo) SetFCGIConfig(ctx context.Context, appID, docRoot, index string) error {
	if index == "" {
		index = "index.php"
	}
	_, err := r.pool.Exec(ctx, `
		UPDATE apps
		   SET fcgi_doc_root = $2,
		       fcgi_index    = $3,
		       updated_at    = NOW()
		 WHERE id = $1`, appID, docRoot, index)
	return err
}

// SetProxyConfig persists the per-app reverse-proxy config (migration 000061).
// raw must be valid JSON already validated by the caller; empty → "{}".
func (r *AppRepo) SetProxyConfig(ctx context.Context, appID string, raw []byte) error {
	if len(raw) == 0 {
		raw = []byte("{}")
	}
	_, err := r.pool.Exec(ctx, `
		UPDATE apps
		   SET proxy_config = $2::jsonb,
		       updated_at   = NOW()
		 WHERE id = $1`, appID, string(raw))
	return err
}
