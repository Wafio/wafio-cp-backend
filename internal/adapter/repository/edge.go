package repository

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/wafio/wafio-cp-backend/internal/domain"
)

// EdgeRepo stores the delivery settings of an application (compression, files from a folder and
// the response cache), what its WAF agent reported about them, and the requests to remove stored
// copies (migration 000127). Every query matches the project.
type EdgeRepo struct {
	pool *pgxpool.Pool
}

// The parts of the edge settings, as the agent names them in EdgeStatus. "redirects" is the main host
// name and the path prefix, which are stored with the TLS settings and the route.
const (
	EdgeRedirects   = "redirects"
	EdgeCompression = "compression"
	EdgeStaticFiles = "static_files"
	EdgeCache       = "cache"
)

var edgeParts = []string{EdgeRedirects, EdgeCompression, EdgeStaticFiles, EdgeCache}

// AgentTooOldError says that the agent that serves the application reported that it lacks Feature,
// so the change that needs it is refused.
type AgentTooOldError struct{ Feature, Agent string }

func (e *AgentTooOldError) Error() string {
	return fmt.Sprintf("the agent does not apply %s", e.Feature)
}

// FeatureUnsupportedError says that the agent an application moves to lacks parts the application
// uses.
type FeatureUnsupportedError struct {
	Agent    string
	Features []string
}

func (e *FeatureUnsupportedError) Error() string {
	return fmt.Sprintf("the agent does not apply %v", e.Features)
}

// EdgeAgent is the WAF agent that serves an application as the edge settings need it.
type EdgeAgent struct {
	ID, Name string
	LastSeen *time.Time
	// The four flags are what the agent said in Hello: nil when it never did.
	Redirects, Compression, StaticFiles, Cache *bool
}

// Flag returns what the agent reported for one part, nil when unknown.
func (a EdgeAgent) Flag(part string) *bool {
	switch part {
	case EdgeRedirects:
		return a.Redirects
	case EdgeCompression:
		return a.Compression
	case EdgeStaticFiles:
		return a.StaticFiles
	case EdgeCache:
		return a.Cache
	}
	return nil
}

// Lacks says that the agent reported that it cannot apply the part. An agent that never said passes.
func (a EdgeAgent) Lacks(part string) bool {
	f := a.Flag(part)
	return f != nil && !*f
}

func readEdgeAgent(ctx context.Context, q queryer, projectID, agentID string) (EdgeAgent, error) {
	a := EdgeAgent{ID: agentID}
	err := q.QueryRow(ctx, `SELECT name, last_seen, edge_redirects, edge_compression, edge_static_files, edge_cache
		FROM agents WHERE id = $1 AND project_id = $2 AND kind = 'waf' AND deleted_at IS NULL`, agentID, projectID).
		Scan(&a.Name, &a.LastSeen, &a.Redirects, &a.Compression, &a.StaticFiles, &a.Cache)
	if errors.Is(err, pgx.ErrNoRows) {
		return EdgeAgent{ID: agentID}, nil
	}
	return a, err
}

// requireEdgeFeature returns *AgentTooOldError when the agent reported that it lacks the part. An
// agent that never said, or that is gone, passes.
func requireEdgeFeature(ctx context.Context, q queryer, projectID, agentID, part string) error {
	a, err := readEdgeAgent(ctx, q, projectID, agentID)
	if err != nil {
		return err
	}
	if a.Lacks(part) {
		return &AgentTooOldError{Feature: part, Agent: a.Name}
	}
	return nil
}

// AppEdgeAgent returns the agent that serves the application, nil when none does. It returns
// pgx.ErrNoRows when the application is not in the project.
func (r *EdgeRepo) AppEdgeAgent(ctx context.Context, projectID, appID string) (*EdgeAgent, error) {
	if !canonicalIDs(&projectID, &appID) {
		return nil, pgx.ErrNoRows
	}
	var agentID string
	err := r.pool.QueryRow(ctx, `SELECT COALESCE((SELECT waa.agent_id::text FROM waf_agent_apps waa WHERE waa.app_id = a.id AND waa.enabled = TRUE LIMIT 1), '')
		FROM apps a WHERE a.id = $1 AND a.project_id = $2`, appID, projectID).Scan(&agentID)
	if err != nil || agentID == "" {
		return nil, err
	}
	a, err := readEdgeAgent(ctx, r.pool, projectID, agentID)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// admitEdgeMove checks that the agent an application moves to applies every part the application
// uses: a part that is switched on, a main host name, a path prefix. An agent that never said passes.
// It returns *FeatureUnsupportedError. The caller holds the row of the application.
func admitEdgeMove(ctx context.Context, q queryer, projectID, appID, agentID string) error {
	var comp, static, cache, canonical, prefix bool
	err := q.QueryRow(ctx, `SELECT COALESCE((compression->>'enabled')::boolean, FALSE),
		COALESCE((static_files->>'enabled')::boolean, FALSE), COALESCE((cache->>'enabled')::boolean, FALSE),
		tls_canonical_host <> '', COALESCE(proxy_config->>'strip_path_prefix', '') <> ''
		FROM apps WHERE id = $1 AND project_id = $2`, appID, projectID).Scan(&comp, &static, &cache, &canonical, &prefix)
	if err != nil {
		return err
	}
	if !comp && !static && !cache && !canonical && !prefix {
		return nil
	}
	agent, err := readEdgeAgent(ctx, q, projectID, agentID)
	if err != nil {
		return err
	}
	used := map[string]bool{EdgeRedirects: canonical || prefix, EdgeCompression: comp, EdgeStaticFiles: static, EdgeCache: cache}
	var lacking []string
	for _, part := range edgeParts {
		if used[part] && agent.Lacks(part) {
			lacking = append(lacking, part)
		}
	}
	if len(lacking) > 0 {
		return &FeatureUnsupportedError{Agent: agent.Name, Features: lacking}
	}
	return nil
}

// UpdateEdgeFeatures stores what the WAF agent reported in Hello: whether it applies each part of the
// edge settings. Written on every connect, so an agent replaced by an older build goes back to false.
func (r *EdgeRepo) UpdateEdgeFeatures(ctx context.Context, projectID, agentID string, redirects, compression, staticFiles, cache bool) error {
	if r == nil || r.pool == nil {
		return nil
	}
	_, err := r.pool.Exec(ctx, `UPDATE agents SET edge_redirects = $3, edge_compression = $4, edge_static_files = $5, edge_cache = $6
		WHERE deleted_at IS NULL AND id = $1 AND project_id = $2`, agentID, projectID, redirects, compression, staticFiles, cache)
	return err
}

// ── Delivery objects ──────────────────────────────────────────────────────

// DeliveryPart names one of the three objects stored on an application.
type DeliveryPart string

const (
	DeliveryCompression DeliveryPart = "compression"
	DeliveryStaticFiles DeliveryPart = "static_files"
	DeliveryCache       DeliveryPart = "cache"
)

// column is the apps column of the part. It is the only text of a part that reaches SQL.
func (p DeliveryPart) column() (string, bool) {
	switch p {
	case DeliveryCompression, DeliveryStaticFiles, DeliveryCache:
		return string(p), true
	}
	return "", false
}

// AppDelivery is the three stored delivery objects of an application, with the defaults filled in.
type AppDelivery struct {
	Compression domain.Compression
	StaticFiles domain.StaticFiles
	Cache       domain.Cache
}

// Part returns the object of one part.
func (d AppDelivery) Part(p DeliveryPart) any {
	switch p {
	case DeliveryCompression:
		return d.Compression
	case DeliveryStaticFiles:
		return d.StaticFiles
	}
	return d.Cache
}

// partOn says whether the object holds a switch that is on. It reads the raw column.
func partOn(raw []byte) bool {
	var o struct {
		Enabled bool `json:"enabled"`
	}
	return json.Unmarshal(raw, &o) == nil && o.Enabled
}

// DeliveryEnabled says whether the stored object of a bundle row has its switch on.
func DeliveryEnabled(raw []byte) bool { return partOn(raw) }

func decodeDelivery(comp, static, cache []byte) (AppDelivery, error) {
	var d AppDelivery
	for _, f := range []struct {
		raw []byte
		to  any
	}{{comp, &d.Compression}, {static, &d.StaticFiles}, {cache, &d.Cache}} {
		if err := json.Unmarshal(f.raw, f.to); err != nil {
			return AppDelivery{}, err
		}
	}
	d.Compression.FillDefaults()
	d.Cache.FillDefaults()
	if d.StaticFiles.Missing == "" {
		d.StaticFiles.Missing = domain.StaticMissingApp
	}
	return d, nil
}

// GetDelivery returns the delivery objects of an application of the project. An application that
// never saved one reads as the defaults with every switch off. It returns pgx.ErrNoRows when the
// application is not in the project.
func (r *EdgeRepo) GetDelivery(ctx context.Context, projectID, appID string) (AppDelivery, error) {
	if !canonicalIDs(&projectID, &appID) {
		return AppDelivery{}, pgx.ErrNoRows
	}
	var comp, static, cache []byte
	if err := r.pool.QueryRow(ctx, `SELECT compression, static_files, cache FROM apps WHERE id = $1 AND project_id = $2`,
		appID, projectID).Scan(&comp, &static, &cache); err != nil {
		return AppDelivery{}, err
	}
	return decodeDelivery(comp, static, cache)
}

// DeliveryAdmit judges a delivery object that is about to be saved, after the application row and the
// bundle of its agent are held and before the write. stored is what is replaced; agent is the agent
// that serves the application, agentID "" when none does. It may query the pool (the change holds a
// place among the transactions of its kind for that). An error from it stops the change as it is.
type DeliveryAdmit func(stored AppDelivery, agent EdgeAgent, agentID string) error

// DeliveryUpdate is what a save of a delivery object did.
type DeliveryUpdate struct {
	Previous AppDelivery
	// AgentID is the agent that serves the application, "" when none does.
	AgentID string
	// Generation is the bundle generation the agent has after the save, 0 without an agent.
	Generation int64
	// BundleBumped says that the bundle changed, so the caller pushes it. A part that is off before
	// and after is not in the bundle, and neither is a save of the value that is stored.
	BundleBumped bool
}

// UpdateDelivery stores one delivery object, which must have passed through its Normalize. In one
// transaction that holds the application row and the bundle of its agent, so that two saves for one
// agent are measured one after the other, it reads the stored objects, asks admit, writes the object
// and raises the bundle generation when the bundle changes. It returns pgx.ErrNoRows when the
// application is not in the project, and what admit returned.
func (r *EdgeRepo) UpdateDelivery(ctx context.Context, projectID, appID string, part DeliveryPart, value any, admit DeliveryAdmit) (DeliveryUpdate, error) {
	col, ok := part.column()
	if !ok || !canonicalIDs(&projectID, &appID) {
		return DeliveryUpdate{}, pgx.ErrNoRows
	}
	leave, err := enterNestedTx(ctx)
	if err != nil {
		return DeliveryUpdate{}, err
	}
	defer leave()
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return DeliveryUpdate{}, err
	}
	defer tx.Rollback(ctx) //nolint:errcheck
	var comp, static, cache []byte
	if err := tx.QueryRow(ctx, `SELECT compression, static_files, cache FROM apps WHERE id = $1 AND project_id = $2 FOR UPDATE`,
		appID, projectID).Scan(&comp, &static, &cache); err != nil {
		return DeliveryUpdate{}, err
	}
	var out DeliveryUpdate
	if out.AgentID, _, err = enabledAssignment(ctx, tx, appID); err != nil {
		return DeliveryUpdate{}, err
	}
	var agent EdgeAgent
	if out.AgentID != "" {
		if err := lockAgentBundle(ctx, tx, out.AgentID); err != nil {
			return DeliveryUpdate{}, err
		}
		if agent, err = readEdgeAgent(ctx, tx, projectID, out.AgentID); err != nil {
			return DeliveryUpdate{}, err
		}
	}
	if out.Previous, err = decodeDelivery(comp, static, cache); err != nil {
		return DeliveryUpdate{}, err
	}
	if admit != nil {
		if err := admit(out.Previous, agent, out.AgentID); err != nil {
			return DeliveryUpdate{}, err
		}
	}
	raw, err := json.Marshal(value)
	if err != nil {
		return DeliveryUpdate{}, err
	}
	before, err := json.Marshal(out.Previous.Part(part))
	if err != nil {
		return DeliveryUpdate{}, err
	}
	// The column name comes from the fixed set of DeliveryPart.column.
	if _, err := tx.Exec(ctx, `UPDATE apps SET `+col+` = $3::jsonb, updated_at = NOW() WHERE id = $1 AND project_id = $2`,
		appID, projectID, string(raw)); err != nil {
		return DeliveryUpdate{}, err
	}
	if out.AgentID != "" {
		changed := string(before) != string(raw) && (partOn(before) || partOn(raw))
		if changed {
			if out.Generation, err = bumpBundleGen(ctx, tx, appID); err != nil {
				return DeliveryUpdate{}, err
			}
			out.BundleBumped = true
		} else if err := tx.QueryRow(ctx, `SELECT generation FROM waf_agent_bundles WHERE agent_id = $1`, out.AgentID).Scan(&out.Generation); err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return DeliveryUpdate{}, err
		}
	}
	return out, tx.Commit(ctx)
}
